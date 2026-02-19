"""
TransWAF - Main Inference Pipeline
The single entry point for real-time HTTP request classification.

Usage:
    waf = TransWAF(model_path="models/transwaf_best")
    result = waf.classify(raw_http_request)
    # result: {"label": "sqli", "confidence": 0.98, "action": "BLOCK", ...}

    # Demo mode (no trained model needed):
    waf = TransWAF(demo_mode=True)
"""

import json
import time
import os
from pathlib import Path
from typing import Optional

import torch
import numpy as np
from transformers import AutoTokenizer

from src.pipeline.http_parser import HTTPParser
from src.pipeline.normalizer import RequestNormalizer
from src.explainability.attention_viz import AttentionRollout

ROOT = Path(__file__).parent.parent.parent

# Default thresholds (can be overridden via .env)
BLOCK_THRESHOLD = float(os.getenv("BLOCK_THRESHOLD", 0.80))
FLAG_THRESHOLD = float(os.getenv("FLAG_THRESHOLD", 0.50))

LABEL_DISPLAY = {
    "benign": "Benign",
    "sqli": "SQL Injection",
    "xss": "Cross-Site Scripting",
    "cmdi": "Command Injection",
    "path_traversal": "Path Traversal",
    "rce": "Remote Code Execution",
}

THREAT_LEVEL = {
    "benign": "NONE",
    "sqli": "HIGH",
    "xss": "HIGH",
    "cmdi": "CRITICAL",
    "path_traversal": "MEDIUM",
    "rce": "CRITICAL",
}

LABEL2ID = {"benign": 0, "sqli": 1, "xss": 2, "cmdi": 3, "path_traversal": 4, "rce": 5}
ID2LABEL = {v: k for k, v in LABEL2ID.items()}


class TransWAF:
    """
    End-to-end TransWAF inference pipeline.

    Stages:
        1. HTTP Parser    — extract method, path, headers, body
        2. Normalizer     — multi-pass decode, unicode folding
        3. Tokenizer      — DistilBERT WordPiece tokenization
        4. Encoder        — DistilBERT transformer encoding
        5. Classifier     — 6-class softmax head
        6. Explainability — Attention rollout saliency
        7. Decision       — BLOCK / FLAG / ALLOW

    Args:
        model_path: Path to fine-tuned checkpoint directory (from train.py).
                    If None and demo_mode=False, raises FileNotFoundError.
        demo_mode:  If True, loads base DistilBERT weights without a
                    trained classifier head — useful for pipeline testing
                    before training is complete.
        block_threshold: Confidence above which requests are blocked (0.8)
        flag_threshold:  Confidence above which requests are flagged (0.5)
    """

    def __init__(
        self,
        model_path: Optional[str] = None,
        demo_mode: bool = False,
        block_threshold: float = BLOCK_THRESHOLD,
        flag_threshold: float = FLAG_THRESHOLD,
    ):
        self.block_threshold = block_threshold
        self.flag_threshold = flag_threshold
        self.demo_mode = demo_mode

        self.parser = HTTPParser()
        self.normalizer = RequestNormalizer()
        self.rollout = AttentionRollout(discard_ratio=0.9)

        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.model = None
        self.tokenizer = None
        self.model_cfg = {}

        if demo_mode:
            self._load_demo_mode()
        else:
            if model_path is None:
                default = ROOT / "models" / "transwaf_best"
                if default.exists():
                    model_path = str(default)
                else:
                    raise FileNotFoundError(
                        "No trained model found. Either:\n"
                        "  1. Run: python src/training/train.py\n"
                        "  2. Use: TransWAF(demo_mode=True)"
                    )
            self._load_model(Path(model_path))

    def _load_demo_mode(self):
        """Load base DistilBERT without a trained classification head."""
        from transformers import AutoModel

        base_name = "distilbert-base-uncased"
        print(f"[TransWAF] Demo mode — loading {base_name} (no trained classifier)")
        self.tokenizer = AutoTokenizer.from_pretrained(base_name)
        self._base_encoder = AutoModel.from_pretrained(base_name).to(self.device)
        self._base_encoder.eval()
        self.model_cfg = {
            "num_labels": 6,
            "hidden_dim": 256,
            "dropout_prob": 0.3,
            "label2id": LABEL2ID,
        }
        print("[TransWAF] Demo mode active — classification uses heuristic fallback")

    def _load_model(self, checkpoint_dir: Path):
        """Load fine-tuned TransWAFModel from checkpoint."""
        import sys
        sys.path.insert(0, str(ROOT))
        from src.training.train import TransWAFModel

        cfg_path = checkpoint_dir / "transwaf_config.json"
        if not cfg_path.exists():
            raise FileNotFoundError(
                f"transwaf_config.json not found in {checkpoint_dir}. "
                "Run train.py first or use demo_mode=True."
            )

        with open(cfg_path) as f:
            self.model_cfg = json.load(f)

        print(f"[TransWAF] Loading model from {checkpoint_dir}")
        self.tokenizer = AutoTokenizer.from_pretrained(str(checkpoint_dir))

        self.model = TransWAFModel(
            model_name=str(checkpoint_dir),
            num_labels=self.model_cfg["num_labels"],
            dropout_prob=self.model_cfg["dropout_prob"],
            hidden_dim=self.model_cfg["hidden_dim"],
        ).to(self.device)

        classifier_path = checkpoint_dir / "classifier_head.pt"
        if classifier_path.exists():
            self.model.classifier.load_state_dict(
                torch.load(classifier_path, map_location=self.device)
            )

        self.model.eval()
        print(f"[TransWAF] Model loaded | Device: {self.device}")

    def _heuristic_classify(self, text: str) -> dict:
        """
        Fallback heuristic classification for demo mode.
        Uses the same regex patterns as preprocess.py.
        """
        import re
        text_lower = text.lower()

        checks = [
            ("cmdi", r";\s*(ls|cat|id|whoami|bash)|&&\s*cat|`id`|\$\(id\)|/etc/passwd"),
            ("rce", r"\$\{[^}]+\}|\{\{[^}]+\}\}|__import__|system\s*\(|passthru"),
            ("path_traversal", r"\.\./|\.\.\\|%2e%2e|/etc/passwd|boot\.ini"),
            ("sqli", r"\bunion\b.*\bselect\b|\bor\b.*=.*|--|#\s*$|\bsleep\s*\("),
            ("xss", r"<script|onerror=|javascript:|alert\s*\(|document\.cookie"),
        ]

        for label, pattern in checks:
            if re.search(pattern, text_lower, re.IGNORECASE):
                conf = 0.85 + np.random.uniform(-0.05, 0.10)
                return {
                    "label": label,
                    "confidence": round(float(min(conf, 0.99)), 4),
                    "all_scores": {l: 0.01 for l in LABEL2ID},
                }

        return {
            "label": "benign",
            "confidence": round(float(np.random.uniform(0.82, 0.97)), 4),
            "all_scores": {"benign": 0.92},
        }

    @torch.no_grad()
    def _run_model(self, text: str) -> dict:
        """Run the transformer model and return logits + attentions."""
        inputs = self.tokenizer(
            text,
            max_length=512,
            truncation=True,
            padding="max_length",
            return_tensors="pt",
        )
        input_ids = inputs["input_ids"].to(self.device)
        attention_mask = inputs["attention_mask"].to(self.device)

        outputs = self.model(
            input_ids=input_ids,
            attention_mask=attention_mask,
            output_attentions=True,
        )

        logits = outputs["logits"][0]  # (num_labels,)
        probs = torch.softmax(logits, dim=-1).cpu().numpy()
        pred_id = int(np.argmax(probs))
        pred_label = ID2LABEL[pred_id]
        confidence = float(probs[pred_id])

        all_scores = {ID2LABEL[i]: round(float(p), 4) for i, p in enumerate(probs)}

        return {
            "label": pred_label,
            "confidence": round(confidence, 4),
            "all_scores": all_scores,
            "attentions": outputs["attentions"],
            "input_ids": input_ids,
        }

    def _get_saliency(self, model_output: dict, text: str) -> dict:
        """Extract attention saliency map for the classification."""
        try:
            attentions = model_output.get("attentions")
            input_ids = model_output.get("input_ids")

            if attentions is None or input_ids is None:
                return {}

            rollout_scores = self.rollout.rollout(attentions, input_ids)
            tokens = self.tokenizer.convert_ids_to_tokens(input_ids[0].cpu().tolist())

            return self.rollout.get_token_saliency(tokens, rollout_scores, top_k=15)
        except Exception:
            return {}

    def _make_decision(self, confidence: float, label: str) -> tuple[str, str]:
        """
        Convert confidence to a WAF action.

        Returns:
            (action, confidence_level) where action ∈ {BLOCK, FLAG, ALLOW}
        """
        if label == "benign":
            if confidence >= self.block_threshold:
                return "ALLOW", "HIGH"
            elif confidence >= self.flag_threshold:
                return "ALLOW", "MEDIUM"
            else:
                return "FLAG", "LOW"
        else:
            if confidence >= self.block_threshold:
                return "BLOCK", "HIGH"
            elif confidence >= self.flag_threshold:
                return "FLAG", "MEDIUM"
            else:
                return "ALLOW", "LOW"

    def classify(self, raw_request: str) -> dict:
        """
        Classify a raw HTTP request string.

        Args:
            raw_request: Full HTTP/1.1 request as a string

        Returns:
            {
                "label": str,             # Attack class label
                "label_display": str,     # Human-readable label
                "confidence": float,      # Softmax probability [0, 1]
                "action": str,            # BLOCK | FLAG | ALLOW
                "threat_level": str,      # CRITICAL | HIGH | MEDIUM | NONE
                "confidence_level": str,  # HIGH | MEDIUM | LOW
                "all_scores": dict,       # Probabilities for all classes
                "saliency": dict,         # Token → importance scores
                "latency_ms": float,      # Inference time
                "normalized_text": str,   # What the model actually saw
            }
        """
        start = time.perf_counter()

        # Stage 1: Parse
        parsed = self.parser.parse(raw_request)

        # Stage 2: Normalize
        normalized_text = self.normalizer.normalize_request_object(parsed)
        if not normalized_text.strip():
            normalized_text = self.normalizer.normalize(raw_request)

        # Stage 3-5: Inference
        if self.demo_mode or self.model is None:
            model_output = self._heuristic_classify(normalized_text)
            saliency = {}
        else:
            model_output = self._run_model(normalized_text)
            # Stage 6: Explainability
            saliency = self._get_saliency(model_output, normalized_text)

        label = model_output["label"]
        confidence = model_output["confidence"]
        all_scores = model_output.get("all_scores", {})

        # Stage 7: Decision
        action, confidence_level = self._make_decision(confidence, label)

        latency_ms = round((time.perf_counter() - start) * 1000, 2)

        return {
            "label": label,
            "label_display": LABEL_DISPLAY.get(label, label),
            "confidence": confidence,
            "action": action,
            "threat_level": THREAT_LEVEL.get(label, "UNKNOWN"),
            "confidence_level": confidence_level,
            "all_scores": all_scores,
            "saliency": saliency,
            "latency_ms": latency_ms,
            "normalized_text": normalized_text[:500],  # truncate for API response
        }

    def classify_batch(self, raw_requests: list[str]) -> list[dict]:
        """Classify multiple requests. Returns list of result dicts."""
        return [self.classify(r) for r in raw_requests]
