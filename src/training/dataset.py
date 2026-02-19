"""
TransWAF - PyTorch Dataset Class
Loads the processed CSV splits and produces tokenized inputs
for DistilBERT fine-tuning.
"""

import pandas as pd
import torch
from torch.utils.data import Dataset, DataLoader
from transformers import AutoTokenizer
from pathlib import Path
from loguru import logger
from typing import Optional


LABEL2ID = {
    "benign": 0,
    "sqli": 1,
    "xss": 2,
    "cmdi": 3,
    "path_traversal": 4,
    "rce": 5,
}

ID2LABEL = {v: k for k, v in LABEL2ID.items()}


class WAFDataset(Dataset):
    """
    PyTorch Dataset for TransWAF HTTP request classification.

    Args:
        filepath: Path to CSV file with 'request_normalized' and 'label' columns
        tokenizer: HuggingFace tokenizer instance
        max_length: Maximum token sequence length
        label2id: Mapping from label string to integer ID
    """

    def __init__(
        self,
        filepath: Path,
        tokenizer,
        max_length: int = 512,
        label2id: dict = LABEL2ID,
    ):
        self.df = pd.read_csv(filepath)
        self.df = self.df.dropna(subset=["request_normalized", "label"]).reset_index(drop=True)
        self.tokenizer = tokenizer
        self.max_length = max_length
        self.label2id = label2id

        # Validate labels
        unknown = set(self.df["label"].unique()) - set(label2id.keys())
        if unknown:
            logger.warning(f"Unknown labels will be dropped: {unknown}")
            self.df = self.df[self.df["label"].isin(label2id.keys())].reset_index(drop=True)

        logger.info(f"Loaded {len(self.df)} samples from {filepath.name}")
        logger.info(f"Class distribution:\n{self.df['label'].value_counts().to_string()}")

    def __len__(self):
        return len(self.df)

    def __getitem__(self, idx):
        row = self.df.iloc[idx]
        text = str(row["request_normalized"])
        label_id = self.label2id[str(row["label"])]

        encoding = self.tokenizer(
            text,
            max_length=self.max_length,
            padding="max_length",
            truncation=True,
            return_tensors="pt",
        )

        return {
            "input_ids": encoding["input_ids"].squeeze(0),
            "attention_mask": encoding["attention_mask"].squeeze(0),
            "labels": torch.tensor(label_id, dtype=torch.long),
        }

    def get_class_weights(self) -> torch.Tensor:
        """Compute inverse-frequency class weights for imbalanced datasets."""
        counts = self.df["label"].value_counts()
        total = len(self.df)
        weights = []
        for label in sorted(self.label2id, key=self.label2id.get):
            count = counts.get(label, 1)
            weights.append(total / (len(self.label2id) * count))
        return torch.tensor(weights, dtype=torch.float)


def get_dataloaders(
    data_dir: Path,
    tokenizer,
    train_batch_size: int = 32,
    eval_batch_size: int = 64,
    max_length: int = 512,
    num_workers: int = 0,
) -> tuple[DataLoader, DataLoader, DataLoader]:
    """
    Build train, val, and test DataLoaders.

    Returns:
        (train_loader, val_loader, test_loader)
    """
    train_ds = WAFDataset(data_dir / "train.csv", tokenizer, max_length)
    val_ds = WAFDataset(data_dir / "val.csv", tokenizer, max_length)
    test_ds = WAFDataset(data_dir / "test.csv", tokenizer, max_length)

    train_loader = DataLoader(
        train_ds, batch_size=train_batch_size, shuffle=True,
        num_workers=num_workers, pin_memory=True
    )
    val_loader = DataLoader(
        val_ds, batch_size=eval_batch_size, shuffle=False,
        num_workers=num_workers, pin_memory=True
    )
    test_loader = DataLoader(
        test_ds, batch_size=eval_batch_size, shuffle=False,
        num_workers=num_workers, pin_memory=True
    )

    return train_loader, val_loader, test_loader, train_ds.get_class_weights()
