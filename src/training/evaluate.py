"""
TransWAF - Evaluation Script
Loads trained model and evaluates on clean and adversarial test sets.
Generates full per-class classification report and saves to JSON.

Usage:
  python src/training/evaluate.py
  python src/training/evaluate.py --checkpoint models/transwaf_best
"""

import sys
import json
import argparse
from pathlib import Path

import torch
from transformers import AutoTokenizer
from sklearn.metrics import classification_report, confusion_matrix
import numpy as np
from loguru import logger

ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(ROOT))

from src.training.config import CONFIG
from src.training.dataset import WAFDataset, LABEL2ID, ID2LABEL
from src.training.train import TransWAFModel, evaluate
from torch.utils.data import DataLoader


def load_model(checkpoint_dir: Path, device: torch.device) -> tuple:
    """Load TransWAFModel and tokenizer from checkpoint."""
    config_path = checkpoint_dir / "transwaf_config.json"
    if not config_path.exists():
        raise FileNotFoundError(
            f"No transwaf_config.json found in {checkpoint_dir}. Did you run train.py?"
        )

    with open(config_path) as f:
        model_cfg = json.load(f)

    tokenizer = AutoTokenizer.from_pretrained(checkpoint_dir)
    model = TransWAFModel(
        model_name=str(checkpoint_dir),
        num_labels=model_cfg["num_labels"],
        dropout_prob=model_cfg["dropout_prob"],
        hidden_dim=model_cfg["hidden_dim"],
    )

    classifier_path = checkpoint_dir / "classifier_head.pt"
    if classifier_path.exists():
        model.classifier.load_state_dict(
            torch.load(classifier_path, map_location=device)
        )

    model = model.to(device)
    model.eval()
    return model, tokenizer, model_cfg


def run_evaluation(checkpoint_dir: Path = None):
    cfg = CONFIG
    checkpoint_dir = checkpoint_dir or cfg.training.output_dir
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    logger.info(f"Loading model from: {checkpoint_dir}")
    model, tokenizer, model_cfg = load_model(checkpoint_dir, device)

    results = {}

    # ── Clean Test Set ────────────────────────────────────────
    test_file = cfg.data.processed_dir / "test.csv"
    if test_file.exists():
        test_ds = WAFDataset(test_file, tokenizer, cfg.data.max_seq_length)
        test_loader = DataLoader(test_ds, batch_size=cfg.training.eval_batch_size, shuffle=False)
        logger.info("Evaluating on clean test set...")
        test_metrics = evaluate(model, test_loader, device, desc="Clean Test")

        report = classification_report(
            test_metrics["labels"],
            test_metrics["predictions"],
            target_names=[ID2LABEL[i] for i in sorted(ID2LABEL.keys())],
            output_dict=True,
        )

        cm = confusion_matrix(test_metrics["labels"], test_metrics["predictions"])

        logger.info(f"\n{'='*60}")
        logger.info("CLEAN TEST SET RESULTS")
        logger.info(f"{'='*60}")
        logger.info(f"Accuracy:  {test_metrics['accuracy']:.4f}")
        logger.info(f"Macro F1:  {test_metrics['f1']:.4f}")
        logger.info(f"\n{classification_report(test_metrics['labels'], test_metrics['predictions'], target_names=[ID2LABEL[i] for i in sorted(ID2LABEL.keys())])}")

        results["clean_test"] = {
            "accuracy": test_metrics["accuracy"],
            "macro_f1": test_metrics["f1"],
            "per_class": report,
            "confusion_matrix": cm.tolist(),
        }

    # ── Adversarial Test Set ──────────────────────────────────
    adv_file = cfg.data.processed_dir / "adversarial_test.csv"
    if adv_file.exists():
        adv_ds = WAFDataset(adv_file, tokenizer, cfg.data.max_seq_length)
        adv_loader = DataLoader(adv_ds, batch_size=cfg.training.eval_batch_size, shuffle=False)
        logger.info("Evaluating on adversarial test set...")
        adv_metrics = evaluate(model, adv_loader, device, desc="Adversarial Test")

        adv_report = classification_report(
            adv_metrics["labels"],
            adv_metrics["predictions"],
            target_names=[ID2LABEL[i] for i in sorted(ID2LABEL.keys()) if ID2LABEL[i] != "benign"],
            output_dict=True,
            zero_division=0,
        )

        logger.info(f"\n{'='*60}")
        logger.info("ADVERSARIAL TEST SET RESULTS")
        logger.info(f"{'='*60}")
        logger.info(f"Accuracy:  {adv_metrics['accuracy']:.4f}")
        logger.info(f"Macro F1:  {adv_metrics['f1']:.4f}")

        results["adversarial_test"] = {
            "accuracy": adv_metrics["accuracy"],
            "macro_f1": adv_metrics["f1"],
            "per_class": adv_report,
        }

        if "clean_test" in results:
            drop = results["clean_test"]["accuracy"] - adv_metrics["accuracy"]
            logger.info(f"\nEvasion Accuracy Drop: {drop:.4f} ({drop*100:.1f}%)")
            results["evasion_robustness"] = {
                "accuracy_drop": round(drop, 4),
                "robustness_score": round(adv_metrics["accuracy"], 4),
            }

    # ── Save Report ───────────────────────────────────────────
    report_path = checkpoint_dir / "evaluation_report.json"
    with open(report_path, "w") as f:
        json.dump(results, f, indent=2)
    logger.info(f"\n[✓] Evaluation report saved to: {report_path}")

    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Evaluate TransWAF model")
    parser.add_argument("--checkpoint", type=str, default=None,
                        help="Path to model checkpoint directory")
    args = parser.parse_args()

    checkpoint = Path(args.checkpoint) if args.checkpoint else None
    run_evaluation(checkpoint)
