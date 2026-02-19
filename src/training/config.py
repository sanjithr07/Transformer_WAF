"""
TransWAF - Training Configuration
All hyperparameters and paths in one place.
"""
from dataclasses import dataclass, field
from pathlib import Path
import os
from dotenv import load_dotenv

load_dotenv()

ROOT_DIR = Path(__file__).parent.parent.parent


@dataclass
class DataConfig:
    raw_dir: Path = ROOT_DIR / "data" / "raw"
    processed_dir: Path = ROOT_DIR / "data" / "processed"
    train_file: str = "train.csv"
    val_file: str = "val.csv"
    test_file: str = "test.csv"
    adversarial_file: str = "adversarial_test.csv"
    train_split: float = 0.70
    val_split: float = 0.15
    test_split: float = 0.15
    max_seq_length: int = int(os.getenv("MAX_SEQ_LENGTH", 512))
    random_seed: int = int(os.getenv("SEED", 42))


@dataclass
class ModelConfig:
    base_model_name: str = os.getenv("MODEL_NAME", "distilbert-base-uncased")
    num_labels: int = 6
    dropout_prob: float = 0.3
    hidden_dim: int = 256
    label2id: dict = field(default_factory=lambda: {
        "benign": 0,
        "sqli": 1,
        "xss": 2,
        "cmdi": 3,
        "path_traversal": 4,
        "rce": 5,
    })
    id2label: dict = field(default_factory=lambda: {
        0: "benign",
        1: "sqli",
        2: "xss",
        3: "cmdi",
        4: "path_traversal",
        5: "rce",
    })
    label_display: dict = field(default_factory=lambda: {
        "benign": "Benign",
        "sqli": "SQL Injection",
        "xss": "Cross-Site Scripting",
        "cmdi": "Command Injection",
        "path_traversal": "Path Traversal",
        "rce": "Remote Code Execution",
    })
    threat_level: dict = field(default_factory=lambda: {
        "benign": "NONE",
        "sqli": "HIGH",
        "xss": "HIGH",
        "cmdi": "CRITICAL",
        "path_traversal": "MEDIUM",
        "rce": "CRITICAL",
    })


@dataclass
class TrainingConfig:
    output_dir: Path = ROOT_DIR / "models" / "transwaf_best"
    logging_dir: Path = ROOT_DIR / "logs" / "tensorboard"
    num_epochs: int = int(os.getenv("NUM_EPOCHS", 5))
    train_batch_size: int = int(os.getenv("TRAIN_BATCH_SIZE", 32))
    eval_batch_size: int = int(os.getenv("EVAL_BATCH_SIZE", 64))
    learning_rate: float = float(os.getenv("LEARNING_RATE", 2e-5))
    weight_decay: float = float(os.getenv("WEIGHT_DECAY", 0.01))
    warmup_ratio: float = float(os.getenv("WARMUP_RATIO", 0.1))
    max_grad_norm: float = float(os.getenv("MAX_GRAD_NORM", 1.0))
    save_steps: int = 500
    eval_steps: int = 500
    logging_steps: int = 50
    load_best_model_at_end: bool = True
    metric_for_best_model: str = "eval_f1"
    fp16: bool = False  # Set to True if CUDA GPU available
    dataloader_num_workers: int = 0  # Set > 0 on Linux/Mac


@dataclass
class TransWAFConfig:
    data: DataConfig = field(default_factory=DataConfig)
    model: ModelConfig = field(default_factory=ModelConfig)
    training: TrainingConfig = field(default_factory=TrainingConfig)

    def __post_init__(self):
        # Create necessary directories
        self.data.raw_dir.mkdir(parents=True, exist_ok=True)
        self.data.processed_dir.mkdir(parents=True, exist_ok=True)
        self.training.output_dir.mkdir(parents=True, exist_ok=True)
        self.training.logging_dir.mkdir(parents=True, exist_ok=True)
        (ROOT_DIR / "logs").mkdir(parents=True, exist_ok=True)


# Singleton config
CONFIG = TransWAFConfig()
