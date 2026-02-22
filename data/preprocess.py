"""
TransWAF - Dataset Preprocessor
Converts raw HTTP logs into labelled train/val/test CSV splits.

Supported sources:
  csic      -- CSIC 2010 HTTP dataset (download manually)
  synthetic -- Generated synthetic data (python data/download_csic.py --synthetic)
  captured  -- mitmproxy-captured traffic from DVWA / Juice Shop / WebGoat

Usage:
  python data/preprocess.py --source synthetic
  python data/preprocess.py --source captured --input data/raw/captured_traffic.csv
  python data/preprocess.py --source captured --merge   # merge with existing splits
"""

import re
import sys
import argparse
import pandas as pd
import numpy as np
from pathlib import Path
from sklearn.model_selection import train_test_split
from urllib.parse import unquote_plus, unquote
from html import unescape
from loguru import logger

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

RAW_DIR = ROOT / "data" / "raw"
PROCESSED_DIR = ROOT / "data" / "processed"
PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

# ─────────────────────────────────────────────────────────────
# Attack type detection regexes (for CSIC 2010 which has no labels)
# ─────────────────────────────────────────────────────────────
SQLI_PATTERNS = re.compile(
    r"(\bunion\b.*\bselect\b|\bselect\b.*\bfrom\b|\bdrop\b.*\btable\b|"
    r"\binsert\b.*\binto\b|\bupdate\b.*\bset\b|\bdelete\b.*\bfrom\b|"
    r"or\s+[\'\"]?1[\'\"]?\s*=\s*[\'\"]?1|--\s*$|#\s*$|\/\*.*\*\/|"
    r"\bsleep\s*\(|\bwaitfor\s+delay\b|\bbenchmark\s*\(|"
    r"\binformation_schema\b|\bxp_cmdshell\b)",
    re.IGNORECASE,
)

XSS_PATTERNS = re.compile(
    r"(<script[\s\S]*?>|<\/script>|javascript\s*:|on\w+\s*=|"
    r"<\s*img[^>]*onerror|<\s*svg[^>]*onload|<\s*iframe|"
    r"document\.cookie|document\.write|eval\s*\(|alert\s*\(|"
    r"String\.fromCharCode|&#x|&#\d+;)",
    re.IGNORECASE,
)

CMDI_PATTERNS = re.compile(
    r"(;\s*(ls|cat|id|whoami|wget|curl|nc|bash|sh|python|perl|ruby)\b|"
    r"\|\s*(ls|cat|id|whoami|wget|curl|nc|bash|sh)\b|"
    r"&&\s*(cat|ls|id)|`[^`]+`|\$\([^)]+\)|"
    r"/etc/passwd|/etc/shadow|/bin/bash|/bin/sh|"
    r"cmd\.exe|powershell|net\s+user|systeminfo|ipconfig)",
    re.IGNORECASE,
)

PATH_TRAVERSAL_PATTERNS = re.compile(
    r"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e\/|%252e%252e|"
    r"\.\.%2f|\.\.%5c|%c0%ae|%c1%9c|"
    r"\/etc\/passwd|\/etc\/shadow|\/proc\/self|"
    r"boot\.ini|win\.ini|system32)",
    re.IGNORECASE,
)

RCE_PATTERNS = re.compile(
    r"(\$\{[^}]+\}|\{\{[^}]+\}\}|<%.*%>|"
    r"Runtime\.getRuntime\(\)|exec\s*\(|system\s*\(|"
    r"passthru\s*\(|shell_exec\s*\(|popen\s*\(|"
    r"__import__.*os|subprocess|base64_decode|"
    r"getClass\(\)\.getClassLoader\(\)|"
    r"\[\[.*\]\]|#\{.*\}|\*\{.*\})",
    re.IGNORECASE,
)


def detect_attack_type(text: str) -> str:
    """Auto-label an HTTP request string with attack type."""
    t = text.lower()
    # Order matters — check more specific patterns first
    if CMDI_PATTERNS.search(t):
        return "cmdi"
    if RCE_PATTERNS.search(t):
        return "rce"
    if PATH_TRAVERSAL_PATTERNS.search(t):
        return "path_traversal"
    if SQLI_PATTERNS.search(t):
        return "sqli"
    if XSS_PATTERNS.search(t):
        return "xss"
    return "benign"


# ─────────────────────────────────────────────────────────────
# CSIC 2010 Parser
# ─────────────────────────────────────────────────────────────
def parse_csic_file(filepath: Path) -> list[dict]:
    """Parse CSIC 2010 HTTP format (requests separated by blank lines)."""
    records = []
    with open(filepath, "r", encoding="latin-1") as f:
        content = f.read()

    # Split on double newlines (HTTP request boundaries)
    raw_requests = re.split(r"\n\s*\n", content.strip())

    for raw in raw_requests:
        raw = raw.strip()
        if not raw or not re.match(r"(GET|POST|PUT|DELETE|HEAD|OPTIONS)", raw):
            continue
        records.append({"request": raw, "label": None})

    return records

def load_captured_traffic(filepath: Path) -> pd.DataFrame:
    """
    Load captured traffic from mitmproxy capture_traffic.py output CSV.
    Expects columns: timestamp, method, url, label, request_raw, source_app
    """
    if not filepath.exists():
        logger.error(f"Captured traffic file not found: {filepath}")
        logger.error("Run: mitmdump -s data/capture_traffic.py --listen-port 8080")
        sys.exit(1)

    df = pd.read_csv(filepath)
    logger.info(f"Loaded {len(df)} captured requests from {filepath.name}")

    # Rename columns to match expected schema
    if "request_raw" in df.columns:
        df = df.rename(columns={"request_raw": "request"})
    elif "request" not in df.columns:
        logger.error("Captured CSV must have a 'request_raw' or 'request' column")
        sys.exit(1)

    # Re-run auto-labeling on top of captured labels (for any missed patterns)
    if "label" not in df.columns:
        df["label"] = df["request"].apply(detect_attack_type)
    else:
        # Fix benign items that may actually contain attacks
        mask = df["label"] == "benign"
        df.loc[mask, "label"] = df.loc[mask, "request"].apply(detect_attack_type)

    dist = df["label"].value_counts()
    logger.info(f"Captured traffic class distribution:\n{dist.to_string()}")
    logger.info(f"Source apps: {df.get('source_app', pd.Series()).value_counts().to_dict()}")

    return df[["request", "label"]]


def load_csic_2010() -> pd.DataFrame:
    """Load and label CSIC 2010 dataset."""
    normal_train = RAW_DIR / "normalTrafficTraining.txt"
    normal_test = RAW_DIR / "normalTrafficTest.txt"
    anomalous = RAW_DIR / "anomalousTrafficTest.txt"

    records = []

    for f in [normal_train, normal_test]:
        if f.exists():
            parsed = parse_csic_file(f)
            for r in parsed:
                r["label"] = "benign"
            records.extend(parsed)
            logger.info(f"Loaded {len(parsed)} benign records from {f.name}")

    if anomalous.exists():
        parsed = parse_csic_file(anomalous)
        for r in parsed:
            r["label"] = detect_attack_type(r["request"])
        records.extend(parsed)
        logger.info(f"Loaded {len(parsed)} anomalous records from {anomalous.name}")

    df = pd.DataFrame(records)
    return df


# ─────────────────────────────────────────────────────────────
# Text Normalization (mirrors the pipeline normalizer)
# ─────────────────────────────────────────────────────────────
def normalize_request(text: str) -> str:
    """Apply the same normalization as the inference pipeline."""
    # Multi-pass URL decode (handles double-encoded payloads)
    for _ in range(3):
        decoded = unquote_plus(text)
        if decoded == text:
            break
        text = decoded

    # HTML entity decode
    text = unescape(text)

    # Remove null bytes
    text = text.replace("\x00", "")

    # Normalize whitespace
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\r\n|\r", "\n", text)

    # Truncate to 2000 chars max (tokenizer will further truncate)
    return text[:2000].strip()


# ─────────────────────────────────────────────────────────────
# Main Preprocessing Pipeline
# ─────────────────────────────────────────────────────────────
def preprocess(source: str = "csic", input_file: Path = None,
               merge: bool = False, seed: int = 42):
    logger.info(f"[TransWAF Preprocessor] Source: {source}")

    if source == "captured":
        if input_file is None:
            input_file = RAW_DIR / "captured_traffic.csv"
        df = load_captured_traffic(input_file)
    elif source == "synthetic":
        syn_parquet = RAW_DIR / "synthetic_dataset.parquet"
        logger.info(f"Looking for dataset in: {RAW_DIR}")

        if syn_parquet.exists():
            logger.info(f"Reading Parquet: {syn_parquet}")
            df = pd.read_parquet(syn_parquet, engine="pyarrow")
            logger.info(f"Loaded {len(df)} synthetic samples from Parquet")
        else:
            logger.error(f"Synthetic dataset not found at: {syn_parquet}")
            logger.error("Run: python data/download_csic.py --synthetic")
            sys.exit(1)


    else:
        df = load_csic_2010()

    if df.empty:
        logger.error("No data loaded. Check your dataset files.")
        sys.exit(1)

    # Drop rows with missing labels or requests
    df = df.dropna(subset=["request", "label"])
    df["request"] = df["request"].astype(str)
    df["label"] = df["label"].astype(str)

    # Normalize requests
    logger.info("Applying normalization...")
    df["request_normalized"] = df["request"].apply(normalize_request)

    # Remove empty requests
    df = df[df["request_normalized"].str.len() > 10].reset_index(drop=True)

    # Log class distribution
    dist = df["label"].value_counts()
    logger.info(f"Class distribution:\n{dist.to_string()}")

    # ── Optional merge with existing synthetic splits ────────
    if merge:
        existing_splits = []
        for split_name in ["train.parquet", "val.parquet", "test.parquet"]:
            p = PROCESSED_DIR / split_name
            if p.exists():
                existing_splits.append(pd.read_parquet(p, engine="pyarrow"))
        if existing_splits:
            existing_df = pd.concat(existing_splits, ignore_index=True)
            logger.info(f"Merging {len(df)} captured samples with {len(existing_df)} existing samples")
            df = pd.concat([existing_df, df], ignore_index=True).drop_duplicates()
            # Re-normalize label column after concat
            df["label"] = df["label"].astype(str)
            dist = df["label"].value_counts()
            logger.info(f"Merged class distribution:\n{dist.to_string()}")
        else:
            logger.warning("--merge specified but no existing splits found. Proceeding without merge.")

    # ── Stratified train/val/test split ──────────────────────
    logger.info("Splitting into train/val/test sets...")
    X = df[["request_normalized", "label"]]

    # Check if any class has fewer than 2 samples (stratify would crash)
    min_class_count = df["label"].value_counts().min()
    use_stratify = min_class_count >= 2
    if not use_stratify:
        logger.warning(
            f"Some classes have <2 samples (min={min_class_count}). "
            "Falling back to non-stratified split. Use --merge to combine with synthetic data."
        )

    train_df, temp_df = train_test_split(
        X, test_size=0.30, stratify=X["label"] if use_stratify else None, random_state=seed
    )
    # Re-check stratify for the second split
    min_temp_count = temp_df["label"].value_counts().min()
    use_stratify2 = min_temp_count >= 2
    val_df, test_df = train_test_split(
        temp_df, test_size=0.50, stratify=temp_df["label"] if use_stratify2 else None, random_state=seed
    )

    logger.info(f"Train: {len(train_df)}, Val: {len(val_df)}, Test: {len(test_df)}")

    # Save splits as Parquet (binary format, immune to Windows newline/encoding bugs)
    train_df.to_parquet(PROCESSED_DIR / "train.parquet", engine="pyarrow", index=False)
    val_df.to_parquet(PROCESSED_DIR / "val.parquet", engine="pyarrow", index=False)
    test_df.to_parquet(PROCESSED_DIR / "test.parquet", engine="pyarrow", index=False)
    logger.info(f"Saved splits to {PROCESSED_DIR}/")

    # Summary stats
    summary = {
        "total_samples": len(df),
        "train_size": len(train_df),
        "val_size": len(val_df),
        "test_size": len(test_df),
        "class_distribution": dist.to_dict(),
        "source": source,
    }
    import json
    with open(PROCESSED_DIR / "summary.json", "w") as f:
        json.dump(summary, f, indent=2)

    logger.info("[✓] Preprocessing complete!")
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="TransWAF Dataset Preprocessor")
    parser.add_argument(
        "--source", choices=["csic", "synthetic", "captured"], default="csic",
        help="Dataset source (default: csic)"
    )
    parser.add_argument(
        "--input", type=str, default=None,
        help="Path to input file (required for --source captured)"
    )
    parser.add_argument(
        "--merge", action="store_true",
        help="Merge captured data with existing train/val/test splits"
    )
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    args = parser.parse_args()

    preprocess(
        source=args.source,
        input_file=Path(args.input) if args.input else None,
        merge=args.merge,
        seed=args.seed,
    )
