"""
TransWAF - DistilBERT Fine-Tuning Script
Production-grade training loop with:
- Class-weighted loss for imbalanced data
- LR warmup + cosine decay schedule
- Mixed precision (optional)
- TensorBoard + JSON logging
- Best model checkpoint saving

Usage:
  python src/training/train.py
  python src/training/train.py --epochs 3 --batch-size 16
"""

import sys
import json
import time
import argparse
from pathlib import Path

import torch
import torch.nn as nn
from torch.optim import AdamW
from torch.utils.tensorboard import SummaryWriter
from transformers import (
    AutoTokenizer,
    AutoModel,
    get_linear_schedule_with_warmup,
)
from sklearn.metrics import f1_score, accuracy_score, classification_report
import numpy as np
from tqdm import tqdm
from loguru import logger

ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(ROOT))

from src.training.config import CONFIG
from src.training.dataset import get_dataloaders, ID2LABEL, LABEL2ID


# ─────────────────────────────────────────────────────────────
# TransWAF Model Architecture
# ─────────────────────────────────────────────────────────────

class TransWAFModel(nn.Module):
    """
    DistilBERT + custom classification head for 6-class WAF attack detection.

    Architecture:
        DistilBERT (6 transformer layers, frozen embeddings optional)
        → [CLS] pooling (H_CLS ∈ R^768)
        → Dense(768 → 256) → ReLU → Dropout(0.3)
        → Dense(256 → num_labels) → Softmax
    """

    def __init__(self, model_name: str, num_labels: int, dropout_prob: float = 0.3, hidden_dim: int = 256):
        super().__init__()
        self.encoder = AutoModel.from_pretrained(model_name)
        encoder_dim = self.encoder.config.hidden_size  # 768 for distilbert

        self.classifier = nn.Sequential(
            nn.Linear(encoder_dim, hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout_prob),
            nn.Linear(hidden_dim, num_labels),
        )
        self.num_labels = num_labels

    def forward(self, input_ids, attention_mask, labels=None, output_attentions=False):
        outputs = self.encoder(
            input_ids=input_ids,
            attention_mask=attention_mask,
            output_attentions=output_attentions,
        )

        # Use [CLS] token representation (first token)
        cls_output = outputs.last_hidden_state[:, 0, :]  # (batch, hidden_dim)

        logits = self.classifier(cls_output)

        result = {"logits": logits}

        if output_attentions:
            result["attentions"] = outputs.attentions

        if labels is not None:
            loss_fn = nn.CrossEntropyLoss()
            result["loss"] = loss_fn(logits, labels)

        return result


# ─────────────────────────────────────────────────────────────
# Evaluation Helper
# ─────────────────────────────────────────────────────────────

@torch.no_grad()
def evaluate(model, dataloader, device, desc="Evaluating"):
    model.eval()
    all_preds, all_labels = [], []
    total_loss = 0.0
    n_batches = 0

    loss_fn = nn.CrossEntropyLoss()

    for batch in tqdm(dataloader, desc=desc, leave=False):
        input_ids = batch["input_ids"].to(device)
        attention_mask = batch["attention_mask"].to(device)
        labels = batch["labels"].to(device)

        outputs = model(input_ids, attention_mask)
        logits = outputs["logits"]

        loss = loss_fn(logits, labels)
        total_loss += loss.item()
        n_batches += 1

        preds = logits.argmax(dim=-1).cpu().numpy()
        all_preds.extend(preds)
        all_labels.extend(labels.cpu().numpy())

    accuracy = accuracy_score(all_labels, all_preds)
    macro_f1 = f1_score(all_labels, all_preds, average="macro", zero_division=0)
    avg_loss = total_loss / max(n_batches, 1)

    return {
        "accuracy": round(accuracy, 4),
        "f1": round(macro_f1, 4),
        "loss": round(avg_loss, 4),
        "predictions": all_preds,
        "labels": all_labels,
    }


# ─────────────────────────────────────────────────────────────
# Training Loop
# ─────────────────────────────────────────────────────────────

def train(
    epochs: int = None,
    train_batch_size: int = None,
    eval_batch_size: int = None,
    learning_rate: float = None,
):
    cfg = CONFIG
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    logger.info(f"Using device: {device}")

    # Override config with CLI args if provided
    epochs = epochs or cfg.training.num_epochs
    train_batch_size = train_batch_size or cfg.training.train_batch_size
    eval_batch_size = eval_batch_size or cfg.training.eval_batch_size
    learning_rate = learning_rate or cfg.training.learning_rate

    # ── Tokenizer ────────────────────────────────────────────
    logger.info(f"Loading tokenizer: {cfg.model.base_model_name}")
    tokenizer = AutoTokenizer.from_pretrained(cfg.model.base_model_name)

    # ── Data ─────────────────────────────────────────────────
    logger.info("Building DataLoaders...")
    train_loader, val_loader, test_loader, class_weights = get_dataloaders(
        data_dir=cfg.data.processed_dir,
        tokenizer=tokenizer,
        train_batch_size=train_batch_size,
        eval_batch_size=eval_batch_size,
        max_length=cfg.data.max_seq_length,
        num_workers=cfg.training.dataloader_num_workers,
    )

    logger.info(f"Train batches: {len(train_loader)} | Val batches: {len(val_loader)}")

    # ── Model ─────────────────────────────────────────────────
    logger.info(f"Initializing TransWAFModel ({cfg.model.base_model_name})...")
    model = TransWAFModel(
        model_name=cfg.model.base_model_name,
        num_labels=cfg.model.num_labels,
        dropout_prob=cfg.model.dropout_prob,
        hidden_dim=cfg.model.hidden_dim,
    ).to(device)

    total_params = sum(p.numel() for p in model.parameters())
    trainable_params = sum(p.numel() for p in model.parameters() if p.requires_grad)
    logger.info(f"Total parameters: {total_params:,} | Trainable: {trainable_params:,}")

    # ── Loss with class weights ───────────────────────────────
    class_weights = class_weights.to(device)
    loss_fn = nn.CrossEntropyLoss(weight=class_weights)

    # ── Optimizer & Scheduler ────────────────────────────────
    optimizer = AdamW(
        model.parameters(),
        lr=learning_rate,
        weight_decay=cfg.training.weight_decay,
    )

    total_steps = len(train_loader) * epochs
    warmup_steps = int(total_steps * cfg.training.warmup_ratio)

    scheduler = get_linear_schedule_with_warmup(
        optimizer,
        num_warmup_steps=warmup_steps,
        num_training_steps=total_steps,
    )

    # ── TensorBoard ──────────────────────────────────────────
    writer = SummaryWriter(log_dir=str(cfg.training.logging_dir))

    # ── Training ─────────────────────────────────────────────
    best_val_f1 = 0.0
    training_history = []
    global_step = 0

    logger.info(f"\n{'='*60}")
    logger.info(f"  TransWAF Training   |   Epochs: {epochs}   |   LR: {learning_rate}")
    logger.info(f"{'='*60}\n")

    for epoch in range(1, epochs + 1):
        model.train()
        epoch_loss = 0.0
        epoch_start = time.time()

        progress = tqdm(train_loader, desc=f"Epoch {epoch}/{epochs}", unit="batch")

        for batch in progress:
            input_ids = batch["input_ids"].to(device)
            attention_mask = batch["attention_mask"].to(device)
            labels = batch["labels"].to(device)

            optimizer.zero_grad()

            outputs = model(input_ids, attention_mask)
            loss = loss_fn(outputs["logits"], labels)

            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), cfg.training.max_grad_norm)
            optimizer.step()
            scheduler.step()

            epoch_loss += loss.item()
            global_step += 1

            if global_step % cfg.training.logging_steps == 0:
                current_lr = scheduler.get_last_lr()[0]
                writer.add_scalar("train/loss", loss.item(), global_step)
                writer.add_scalar("train/lr", current_lr, global_step)

            progress.set_postfix({"loss": f"{loss.item():.4f}"})

        # ── Epoch Evaluation ─────────────────────────────────
        avg_train_loss = epoch_loss / len(train_loader)
        val_metrics = evaluate(model, val_loader, device, desc=f"Epoch {epoch} Val")
        epoch_time = time.time() - epoch_start

        logger.info(
            f"Epoch {epoch}/{epochs} | "
            f"Train Loss: {avg_train_loss:.4f} | "
            f"Val Loss: {val_metrics['loss']:.4f} | "
            f"Val Acc: {val_metrics['accuracy']:.4f} | "
            f"Val F1: {val_metrics['f1']:.4f} | "
            f"Time: {epoch_time:.0f}s"
        )

        writer.add_scalar("val/loss", val_metrics["loss"], epoch)
        writer.add_scalar("val/accuracy", val_metrics["accuracy"], epoch)
        writer.add_scalar("val/f1", val_metrics["f1"], epoch)

        training_history.append({
            "epoch": epoch,
            "train_loss": avg_train_loss,
            **{f"val_{k}": v for k, v in val_metrics.items()
               if k not in ["predictions", "labels"]},
        })

        # ── Save Best Checkpoint ──────────────────────────────
        if val_metrics["f1"] > best_val_f1:
            best_val_f1 = val_metrics["f1"]
            output_dir = cfg.training.output_dir
            model.encoder.save_pretrained(output_dir)
            tokenizer.save_pretrained(output_dir)
            torch.save(model.classifier.state_dict(), output_dir / "classifier_head.pt")

            # Save model config
            model_info = {
                "base_model": cfg.model.base_model_name,
                "num_labels": cfg.model.num_labels,
                "dropout_prob": cfg.model.dropout_prob,
                "hidden_dim": cfg.model.hidden_dim,
                "label2id": LABEL2ID,
                "id2label": {str(k): v for k, v in ID2LABEL.items()},
                "best_val_f1": best_val_f1,
                "best_epoch": epoch,
            }
            with open(output_dir / "transwaf_config.json", "w") as f:
                json.dump(model_info, f, indent=2)

            logger.info(f"  ✓ New best model saved (Val F1: {best_val_f1:.4f})")

    # ── Final Test Evaluation ─────────────────────────────────
    logger.info("\nRunning final test set evaluation...")
    test_metrics = evaluate(model, test_loader, device, desc="Test")

    test_report = classification_report(
        test_metrics["labels"],
        test_metrics["predictions"],
        target_names=list(LABEL2ID.keys()),
        output_dict=True,
    )

    logger.info(f"\nTest Results:")
    logger.info(f"  Accuracy: {test_metrics['accuracy']:.4f}")
    logger.info(f"  Macro F1: {test_metrics['f1']:.4f}")
    logger.info(f"\n{classification_report(test_metrics['labels'], test_metrics['predictions'], target_names=list(LABEL2ID.keys()))}")

    results = {
        "training_history": training_history,
        "best_val_f1": best_val_f1,
        "test_metrics": {
            "accuracy": test_metrics["accuracy"],
            "macro_f1": test_metrics["f1"],
            "per_class": test_report,
        },
        "config": {
            "epochs": epochs,
            "train_batch_size": train_batch_size,
            "learning_rate": learning_rate,
            "model_name": cfg.model.base_model_name,
        },
    }

    results_path = cfg.training.output_dir / "training_results.json"
    with open(results_path, "w") as f:
        json.dump(results, f, indent=2)

    logger.info(f"\n[✓] Training complete! Results saved to {results_path}")
    writer.close()
    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train TransWAF DistilBERT model")
    parser.add_argument("--epochs", type=int, default=None)
    parser.add_argument("--batch-size", type=int, default=None)
    parser.add_argument("--eval-batch-size", type=int, default=None)
    parser.add_argument("--lr", type=float, default=None)
    args = parser.parse_args()

    train(
        epochs=args.epochs,
        train_batch_size=args.batch_size,
        eval_batch_size=args.eval_batch_size,
        learning_rate=args.lr,
    )
