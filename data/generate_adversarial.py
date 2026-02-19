"""
TransWAF - Adversarial Payload Augmentation Generator
Implements WAF-A-MoLE style mutation operators for SQLi payloads
and encoding-based evasion for other attack types.
Generates adversarial_test.csv for robustness evaluation.

Usage:
  python data/generate_adversarial.py
"""

import re
import sys
import random
import pandas as pd
from pathlib import Path
from urllib.parse import quote
from loguru import logger

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

PROCESSED_DIR = ROOT / "data" / "processed"
PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

random.seed(42)


# ─────────────────────────────────────────────────────────────
# SQLi Mutation Operators (WAF-A-MoLE style)
# ─────────────────────────────────────────────────────────────

def sqli_case_variation(payload: str) -> str:
    """Randomly vary case of SQL keywords."""
    keywords = ["SELECT", "UNION", "FROM", "WHERE", "INSERT", "DROP",
                "UPDATE", "DELETE", "AND", "OR", "NULL", "TABLE"]
    result = payload
    for kw in keywords:
        pattern = re.compile(re.escape(kw), re.IGNORECASE)
        def vary_case(m):
            return "".join(
                c.upper() if random.random() > 0.5 else c.lower()
                for c in m.group()
            )
        result = pattern.sub(vary_case, result)
    return result


def sqli_comment_insertion(payload: str) -> str:
    """Insert SQL comments between keywords."""
    keywords = ["SELECT", "UNION", "FROM", "WHERE", "AND", "OR"]
    result = payload
    for kw in keywords:
        pattern = re.compile(rf"\b{kw}\b", re.IGNORECASE)
        comments = ["/**/", "/*!*/", "/*comment*/", "/*a*/"]
        result = pattern.sub(
            lambda m: m.group() + random.choice(comments),
            result
        )
    return result


def sqli_whitespace_variation(payload: str) -> str:
    """Replace spaces with alternative whitespace characters."""
    alternatives = ["+", "%20", "%09", "/**/", "\t", "\n"]
    return payload.replace(" ", random.choice(alternatives))


def sqli_url_encode(payload: str) -> str:
    """URL-encode random characters in the payload."""
    result = []
    for char in payload:
        if char in "'\"=<>()":
            result.append(quote(char))
        elif char.isalpha() and random.random() < 0.3:
            result.append(f"%{ord(char):02X}")
        else:
            result.append(char)
    return "".join(result)


def sqli_double_encode(payload: str) -> str:
    """Double-encode specific characters."""
    return payload.replace("%", "%25").replace("'", "%2527")


def sqli_hex_encode(payload: str) -> str:
    """Hex-encode string literals in SQL."""
    def encode_string(m):
        s = m.group(1)
        hex_encoded = "".join(f"{ord(c):02x}" for c in s)
        return f"0x{hex_encoded}"
    return re.sub(r"'([^']+)'", encode_string, payload)


def sqli_logical_equivalent(payload: str) -> str:
    """Replace logical expressions with equivalents."""
    replacements = [
        (r"\bOR\s+1=1\b", "OR 2=2"),
        (r"\bOR\s+'1'='1'\b", "OR 'a'='a'"),
        (r"\bAND\s+1=1\b", "AND 2=2"),
        (r"--\s*$", "#"),
        (r"#\s*$", "--"),
    ]
    result = payload
    for pattern, replacement in replacements:
        result = re.sub(pattern, replacement, result, flags=re.IGNORECASE)
    return result


SQLI_MUTATIONS = [
    sqli_case_variation,
    sqli_comment_insertion,
    sqli_whitespace_variation,
    sqli_url_encode,
    sqli_double_encode,
    sqli_hex_encode,
    sqli_logical_equivalent,
]


# ─────────────────────────────────────────────────────────────
# XSS Mutation Operators
# ─────────────────────────────────────────────────────────────

def xss_tag_mutation(payload: str) -> str:
    """Vary HTML tag casing."""
    return re.sub(
        r"<(\/?)(script|img|svg|iframe|body|input|details)",
        lambda m: f"<{m.group(1)}{m.group(2).upper() if random.random()>0.5 else m.group(2).lower()}",
        payload, flags=re.IGNORECASE
    )


def xss_encoding(payload: str) -> str:
    """HTML entity or URL encode parts of the payload."""
    result = payload
    for char, encoded in [("<", "&lt;"), (">", "&gt;"), ("'", "&#39;"), ('"', "&quot;")]:
        if random.random() > 0.6:
            result = result.replace(char, encoded, 1)
    return result


def xss_null_byte(payload: str) -> str:
    """Insert null bytes within script tags."""
    return payload.replace("<script>", "<scr\x00ipt>")


def xss_javascript_variation(payload: str) -> str:
    """Vary javascript: URI encoding."""
    variations = [
        "javascript:", "JAVASCRIPT:", "Javascript:",
        "java\tscript:", "java\nscript:", "java script:",
        "&#106;avascript:", "\x6aavascript:",
    ]
    return re.sub(r"javascript:", random.choice(variations), payload, flags=re.IGNORECASE)


XSS_MUTATIONS = [xss_tag_mutation, xss_encoding, xss_null_byte, xss_javascript_variation]


# ─────────────────────────────────────────────────────────────
# Generic Mutations (all attack types)
# ─────────────────────────────────────────────────────────────

def double_url_encode(payload: str) -> str:
    return payload.replace("%", "%25")


def unicode_variation(payload: str) -> str:
    """Replace some ASCII chars with Unicode equivalents."""
    mapping = {"/": "%c0%af", ".": "%c0%ae", "#": "%23"}
    result = payload
    for k, v in mapping.items():
        if k in result and random.random() > 0.5:
            result = result.replace(k, v, 1)
    return result


def apply_mutations(request: str, label: str, n_mutations: int = 3) -> str:
    """Apply n_mutations random mutations to a request."""
    # Extract payload portion (after ? or in body)
    if label == "sqli":
        mutators = SQLI_MUTATIONS
    elif label == "xss":
        mutators = XSS_MUTATIONS
    else:
        mutators = [double_url_encode, unicode_variation, sqli_whitespace_variation]

    selected = random.choices(mutators, k=n_mutations)
    result = request
    for mutator in selected:
        try:
            result = mutator(result)
        except Exception:
            pass
    return result


# ─────────────────────────────────────────────────────────────
# Main Generation
# ─────────────────────────────────────────────────────────────

def generate_adversarial_set(n_per_class: int = 1000):
    """Generate adversarial test set from existing test split."""
    test_file = PROCESSED_DIR / "test.csv"
    if not test_file.exists():
        logger.error("test.csv not found. Run preprocess.py first.")
        sys.exit(1)

    test_df = pd.read_csv(test_file)
    adversarial_records = []

    attack_labels = [l for l in test_df["label"].unique() if l != "benign"]

    for label in attack_labels:
        subset = test_df[test_df["label"] == label]
        logger.info(f"Generating {n_per_class} adversarial {label} samples...")

        for _ in range(n_per_class):
            row = subset.sample(1).iloc[0]
            original = row["request_normalized"]
            mutated = apply_mutations(original, label, n_mutations=random.randint(2, 5))
            adversarial_records.append({
                "request_normalized": mutated,
                "label": label,
                "original": original,
                "is_adversarial": True,
            })

    adv_df = pd.DataFrame(adversarial_records)
    out_path = PROCESSED_DIR / "adversarial_test.csv"
    adv_df.to_csv(out_path, index=False)
    logger.info(f"[✓] Saved {len(adv_df)} adversarial samples to {out_path}")
    return adv_df


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Generate adversarial test dataset")
    parser.add_argument("--n", type=int, default=1000,
                        help="Adversarial samples per attack class (default: 1000)")
    args = parser.parse_args()
    generate_adversarial_set(n_per_class=args.n)
