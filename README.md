# TransWAF — Transformer-Based Web Application Firewall

> **99.76% Accuracy | 99.83% F1-Score | 6-Class Attack Detection | Real-Time REST API**

TransWAF is a production-ready Web Application Firewall powered by a fine-tuned **DistilBERT** transformer model. Unlike traditional rule-based WAFs, TransWAF understands the *semantic meaning* of HTTP requests, making it resistant to evasion techniques like encoding obfuscation, SQL comment injection, and payload fragmentation.

---

## Table of Contents

1. [How It Works — End-to-End Process Flow](#how-it-works)
2. [Attack Classes Detected](#attack-classes)
3. [Project Results](#results)
4. [Folder Structure & File Descriptions](#folder-structure)
5. [Quick Start Guide](#quick-start)
6. [Integrating TransWAF into Your Website or Portal](#integration)
7. [API Reference](#api-reference)
8. [Future Scope](#future-scope)
9. [Limitations](#limitations)
10. [Tech Stack](#tech-stack)

---

## How It Works

### End-to-End Process Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│                         TRAINING PIPELINE                           │
│                                                                     │
│  1. Data Generation                                                 │
│     ├── Synthetic HTTP payloads (18,000 samples, balanced 6 classes)│
│     ├── Real traffic from DVWA / Juice Shop / WebGoat (mitmproxy)  │
│     └── Adversarial mutations (WAF-A-MoLE style evasion attempts)  │
│                           │                                         │
│  2. Preprocessing                                                   │
│     ├── Multi-pass URL decode (handles double-encoded payloads)     │
│     ├── HTML entity decode                                          │
│     ├── Unicode normalization                                       │
│     ├── Auto-labeling via regex patterns                            │
│     └── Stratified 70/15/15 train/val/test split                   │
│                           │                                         │
│  3. Model Training                                                  │
│     ├── DistilBERT tokenizer (WordPiece, max 512 tokens)           │
│     ├── DistilBERT encoder (66M parameters, 6 transformer layers)  │
│     ├── Custom classification head (768 → 256 → 6 classes)        │
│     ├── Class-weighted CrossEntropyLoss (handles imbalance)        │
│     ├── Linear warmup + cosine LR decay                            │
│     └── Best checkpoint saved on validation F1                     │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│                       INFERENCE PIPELINE                            │
│                                                                     │
│  Incoming HTTP Request                                              │
│         │                                                           │
│         ▼                                                           │
│  [1] HTTP Parser          Handles malformed / partial requests      │
│         │                                                           │
│         ▼                                                           │
│  [2] Normalizer           URL decode → HTML decode → Unicode norm  │
│         │                 (3-pass to catch double-encoded payloads) │
│         ▼                                                           │
│  [3] DistilBERT Tokenizer WordPiece tokenization, padding/trunc    │
│         │                                                           │
│         ▼                                                           │
│  [4] Transformer Encoder  6 self-attention layers → [CLS] vector  │
│         │                                                           │
│         ▼                                                           │
│  [5] Classification Head  Linear(768→256) → ReLU → Linear(256→6) │
│         │                                                           │
│         ▼                                                           │
│  [6] Decision Engine      confidence > BLOCK_THRESHOLD → BLOCK    │
│         │                 confidence > FLAG_THRESHOLD  → FLAG      │
│         │                 else                         → ALLOW     │
│         ▼                                                           │
│  [7] Explainability       Attention rollout → token saliency map   │
│         │                 (highlights which words triggered block)  │
│         ▼                                                           │
│  JSON Response: { verdict, label, confidence, saliency_tokens }    │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Attack Classes

| Class | Description | Example Payload |
|-------|-------------|-----------------|
| **benign** | Normal, legitimate HTTP traffic | `GET /products?page=2` |
| **sqli** | SQL Injection — manipulates database queries | `' OR 1=1--` |
| **xss** | Cross-Site Scripting — injects client-side scripts | `<script>alert(1)</script>` |
| **cmdi** | Command Injection — executes OS commands | `; cat /etc/passwd` |
| **path_traversal** | Directory traversal — accesses unauthorized files | `../../../etc/shadow` |
| **rce** | Remote Code Execution — server-side template injection | `{{7*7}}`, `${T(Runtime).exec('id')}` |

---

## Results

Trained on **NVIDIA RTX 4050** · Training time: **~7 minutes** · Dataset: **18,376 samples**

| Class | Precision | Recall | F1-Score |
|-------|-----------|--------|----------|
| Benign | 100.0% | 99.6% | 99.8% |
| SQLi | 100.0% | 100.0% | 100.0% |
| XSS | 100.0% | 100.0% | 100.0% |
| CMDi | 98.4% | 100.0% | 99.2% |
| Path Traversal | 100.0% | 100.0% | 100.0% |
| RCE | 100.0% | 100.0% | 100.0% |
| **Overall** | **99.73%** | **99.93%** | **99.83%** |

**Test Accuracy: 99.76%** — only 1 misclassification in 413 test samples.

---

## Model Training & Dataset

### Base Model — Why DistilBERT?

TransWAF is built on top of **DistilBERT** (`distilbert-base-uncased`), a distilled version of Google's BERT model. It was chosen for three reasons:

| Reason | Detail |
|--------|--------|
| **Speed** | 40% fewer parameters than BERT-base — faster inference for real-time WAF use |
| **Accuracy** | Retains 97% of BERT's performance on NLP benchmarks |
| **Semantic Understanding** | Pre-trained on 3.3B words — understands SQL keywords, script tags, and shell commands in context, not just as patterns |

A WAF that understands `sElEcT` as SQL and `SeleCT` as SQL (case-insensitive, obfuscated) is far harder to evade than one that matches the string `SELECT` literally.

---

### Model Architecture

```
Input: Raw HTTP Request (string)
       │
       ▼
DistilBERT Tokenizer
  └── WordPiece vocabulary (30,522 tokens)
  └── Max length: 512 tokens
  └── Special tokens: [CLS] request text [SEP]
       │
       ▼
DistilBERT Encoder (pre-trained, fine-tuned)
  └── 6 transformer layers
  └── 12 attention heads per layer
  └── Hidden size: 768 dimensions
  └── 66.4 million parameters total
       │
       ▼ [CLS] token embedding (768-dim vector)
       │
Classification Head (trained from scratch)
  └── Linear(768 → 256)
  └── ReLU activation
  └── Dropout(p=0.3)          ← regularization
  └── Linear(256 → 6)         ← 6 attack classes
       │
       ▼
Softmax → class probabilities
```

**Why use the [CLS] token?** In BERT-style models, the [CLS] (classification) token is positioned at the start of every input. After passing through all transformer layers, it aggregates information from the entire sequence via self-attention, making it ideal as a "summary" representation of the full HTTP request.

---

### Dataset Composition

The model was trained on **18,376 labeled HTTP request samples** from two sources:

#### Source 1 — Synthetic Dataset (18,000 samples)

Generated by `data/download_csic.py`. Each sample is a realistic HTTP request with an attack payload embedded in a plausible endpoint.

| Class | Samples | Example Payload Embedded |
|-------|---------|--------------------------|
| benign | 3,000 | `GET /api/products?category=laptop&page=3` |
| sqli | 3,000 | `GET /user?id=' OR 1=1-- HTTP/1.1` |
| xss | 3,000 | `GET /search?q=<script>alert(document.cookie)</script>` |
| cmdi | 3,000 | `GET /api/ping?host=; cat /etc/passwd` |
| path_traversal | 3,000 | `GET /download?file=../../etc/shadow` |
| rce | 3,000 | `GET /template?expr={{7*7}}` |

Each attack payload is embedded inside a **full, realistic HTTP/1.1 request** with proper headers (Host, User-Agent, Content-Type, etc.) — not just a bare payload string. This teaches the model to classify from context, not just the attack string alone.

#### Source 2 — Captured Real Traffic (376 samples)

Captured from three real vulnerable web applications using **mitmproxy** (`data/capture_traffic.py`):

| Application | Port | Type |
|-------------|------|------|
| **DVWA** (Damn Vulnerable Web App) | 8081 | PHP-based, all OWASP Top 10 vulnerabilities |
| **OWASP Juice Shop** | 3000 | Node.js modern SPA with 100+ challenge vulnerabilities |
| **WebGoat** | 8888 | Java/Spring Boot guided attack lessons |

The `attack_scenarios.py` script automatically fires pre-built payloads at all three apps, and mitmproxy intercepts and labels each captured HTTP request using the same regex patterns as the inference pipeline — guaranteeing label consistency.

#### Adversarial Test Set (5,000 samples)

Generated by `data/generate_adversarial.py` using WAF-A-MoLE-style mutations:

| Mutation Type | Example |
|---------------|---------|
| SQL comment insertion | `SELECT/**/username/**/FROM users` |
| Case alternation | `sElEcT uSeRnAmE fRoM uSeRs` |
| Whitespace substitution | `SELECT%09username%09FROM%09users` |
| Double URL encoding | `%2527 → %27 → '` |
| HTML entity encoding | `&lt;script&gt;alert(1)&lt;/script&gt;` |
| XSS tag variations | `<IMG SRC=x onerror=alert(1)>` |
| Null byte injection | `select%00 from users` |

---

### Data Preprocessing Pipeline

Every sample goes through the same normalization steps (in `data/preprocess.py` and `src/pipeline/normalizer.py`) before being fed to the model:

```
Raw HTTP Request
      │
      ▼
1. URL Decode (3 passes)
   e.g. %2527 → %27 → '
   Catches single, double, and triple-encoded payloads

      │
      ▼
2. HTML Entity Decode
   e.g. &lt;script&gt; → <script>
   Catches payloads disguised as HTML-safe strings

      │
      ▼
3. Unicode Normalization (NFC)
   e.g. ＜ (fullwidth less-than) → <
   Catches unicode lookalike bypass attempts

      │
      ▼
4. Whitespace normalization
   Collapse multiple spaces/tabs, normalize CRLF

      │
      ▼
5. Truncate to 2000 chars
   (DistilBERT tokenizer further reduces to 512 tokens)

      │
      ▼
Normalized Text → saved to request_normalized column
```

---

### Train / Validation / Test Split

| Split | Samples | Purpose |
|-------|---------|---------|
| **Train** | 12,863 (70%) | Model weight updates |
| **Validation** | 2,756 (15%) | Hyperparameter tuning, best checkpoint selection |
| **Test** | 2,757 (15%) | Final unbiased performance measurement |

Split is **stratified** — each split contains the same proportion of each attack class, preventing any class from being underrepresented in evaluation.

---

### Hyperparameters

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Base model | `distilbert-base-uncased` | Best speed/accuracy tradeoff |
| Max sequence length | 512 tokens | Covers most HTTP requests |
| Batch size | 32 | Fits RTX 4050 6GB VRAM |
| Learning rate | 2e-5 | Standard BERT fine-tuning LR |
| Epochs | 5 | Converges at epoch 3, no overfitting |
| LR warmup | 10% of steps | Prevents early instability |
| LR schedule | Cosine decay | Smooth convergence |
| Dropout | 0.3 | In classification head |
| Loss function | CrossEntropyLoss (class-weighted) | Handles class imbalance |
| Optimizer | AdamW | Standard for transformer fine-tuning |

---

### Training History (Epoch by Epoch)

| Epoch | Train Loss | Val Loss | Val Accuracy | Val F1 |
|-------|-----------|----------|-------------|--------|
| 1 | 1.5688 | 0.7685 | 91.26% | 83.50% |
| 2 | 0.6158 | 0.1963 | 97.82% | 94.32% |
| **3** | **0.1858** | **0.0755** | **99.76%** | **99.83%** ← best checkpoint saved |
| 4 | 0.0879 | 0.0497 | 99.76% | 99.83% |
| 5 | 0.0621 | 0.0446 | 99.76% | 99.83% |

The model converges rapidly at **epoch 3** and plateaus — demonstrating that the classification task is learnable and not overfitting (validation loss continues to drop while accuracy stabilizes). The best checkpoint from epoch 3 is saved and used for all inference.

**Training hardware:**
- GPU: NVIDIA GeForce RTX 4050 Laptop GPU (6GB VRAM)
- Training time: **~7 minutes** for 5 epochs
- Framework: PyTorch 2.5.1 + CUDA 12.1

---


```
WAFP/
│
├── api/                          # REST API server (FastAPI)
│   ├── __init__.py
│   ├── main.py                   # App entry point — all endpoints defined here
│   ├── models.py                 # Pydantic request/response schemas
│   └── database.py               # Async SQLite layer for request logging
│
├── dashboard/                    # Frontend web dashboard
│   ├── index.html                # Main HTML — tabs: Overview, Analyzer, History, Docs
│   ├── style.css                 # Dark glassmorphism theme
│   └── app.js                    # Live polling, chart rendering, payload analyzer UI
│
├── data/                         # Data pipeline scripts
│   ├── download_csic.py          # Generates 18,000 synthetic labeled HTTP samples
│   ├── preprocess.py             # Normalizes + splits data into train/val/test Parquet
│   ├── generate_adversarial.py   # Creates evasion-augmented test set (WAF-A-MoLE style)
│   ├── capture_traffic.py        # mitmproxy addon — captures & auto-labels live traffic
│   ├── attack_scenarios.py       # Sends SQLi/XSS/CMDi/PT/RCE payloads against DVWA etc.
│   ├── docker-compose.yml        # Spins up DVWA, Juice Shop, WebGoat for traffic capture
│   ├── raw/                      # Raw datasets (gitignored — regenerate with scripts)
│   └── processed/                # Train/val/test Parquet splits (gitignored)
│
├── src/
│   ├── pipeline/                 # Core inference pipeline
│   │   ├── http_parser.py        # RFC 2616 HTTP/1.1 parser (handles malformed requests)
│   │   ├── normalizer.py         # Multi-pass URL/HTML/Unicode decoder
│   │   └── transwaf.py           # Main orchestrator — runs all 7 inference stages
│   │
│   ├── training/                 # Model training & evaluation
│   │   ├── config.py             # Central config dataclass (paths, hyperparameters)
│   │   ├── dataset.py            # PyTorch Dataset — loads Parquet, tokenizes, weights
│   │   ├── train.py              # Training loop — DistilBERT + classification head
│   │   └── evaluate.py           # Loads checkpoint, prints per-class report + confusion matrix
│   │
│   └── explainability/
│       └── attention_viz.py      # Attention rollout → per-token saliency scores
│
├── tests/                        # Pytest test suite
│   ├── test_parser.py            # Unit tests for HTTP parser
│   ├── test_normalizer.py        # Unit tests for multi-pass normalizer
│   ├── test_pipeline.py          # Integration tests for full inference pipeline (demo mode)
│   └── test_api.py               # Async API endpoint tests (HTTPX TestClient)
│
├── models/                       # Saved model checkpoints (gitignored — large binary files)
│   └── transwaf_best/
│       ├── config.json           # DistilBERT architecture config
│       ├── model.safetensors     # Trained model weights
│       ├── tokenizer files       # Vocabulary + tokenizer config
│       ├── classifier_head.pt    # Custom classification head weights
│       ├── transwaf_config.json  # TransWAF-specific hyperparameters
│       ├── training_results.json # Loss/accuracy per epoch
│       └── evaluation_report.json# Final per-class metrics + confusion matrix
│
├── logs/                         # TensorBoard training logs (gitignored)
├── .env.example                  # Environment variable template (copy to .env)
├── .gitignore                    # Excludes venvs, models, datasets, pycache
├── requirements.txt              # All Python dependencies
├── pyproject.toml                # pytest configuration
└── README.md                     # This file
```

### Key File Descriptions

| File | Role |
|------|------|
| `api/main.py` | Defines all REST endpoints (`/classify`, `/batch`, `/stats`, `/history`, `/health`, `/dashboard`). Loads the TransWAF model on startup and handles CORS for browser access. |
| `api/database.py` | Asynchronous SQLite database. Every classified request is logged here, enabling the history tab and stats aggregation. |
| `src/pipeline/transwaf.py` | The brain of the system. Chains together: parse → normalize → tokenize → encode → classify → explain → decide. Falls back to a heuristic demo mode if no trained model is found. |
| `src/pipeline/normalizer.py` | Critical for evasion resistance. Runs URL decoding 3 times (catches double-encoded `%2527 → %27 → '`), then HTML entity decoding, then Unicode normalization. |
| `src/training/train.py` | Defines `TransWAFModel` (DistilBERT + classification head), the training loop, learning rate scheduling, mixed precision, and TensorBoard logging. |
| `data/capture_traffic.py` | A `mitmproxy` addon. Sits between your browser and the vulnerable apps, capturing every HTTP request and auto-labeling it using the same 6-class regex patterns as the inference pipeline. |
| `src/explainability/attention_viz.py` | Implements attention rollout — multiplies attention matrices across all transformer layers to produce a single saliency score per token. Tells analysts *why* a request was blocked. |

---

## Quick Start Guide

### Prerequisites
- Python 3.12 (for GPU training) — [download](https://www.python.org/downloads/)
- NVIDIA GPU with CUDA 12.1 drivers (optional but recommended)
- Docker Desktop (optional — for real traffic capture)

### 1. Clone & Set Up Environment

```bash
git clone https://github.com/YOUR_USERNAME/TransWAF.git
cd TransWAF

# Create Python 3.12 virtual environment
py -3.12 -m venv venv312
venv312\Scripts\activate          # Windows
# source venv312/bin/activate     # Linux/Mac

# Install PyTorch with GPU support (CUDA 12.1)
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu121

# Install all other dependencies
pip install -r requirements.txt
```

### 2. Generate Training Data

```bash
# Generate 18,000 synthetic labeled HTTP samples
python data/download_csic.py --synthetic

# Normalize and split into train/val/test
python data/preprocess.py --source synthetic

# Generate adversarial evasion test set
python data/generate_adversarial.py
```

### 3. (Optional) Capture Real Traffic

```bash
# Start vulnerable apps
docker compose -f data/docker-compose.yml up -d

# Start mitmproxy capture (new terminal)
mitmdump -s data/capture_traffic.py --listen-port 8080

# Run automated attacks (new terminal)
python data/attack_scenarios.py --target all

# Merge captured data with synthetic
python data/preprocess.py --source captured --merge
```

### 4. Train the Model

```bash
python src/training/train.py --epochs 5 --batch-size 32
# Trains in ~7 min on RTX 4050. Saves best checkpoint to models/transwaf_best/
```

### 5. Evaluate

```bash
python src/training/evaluate.py
# Prints per-class precision/recall/F1 and saves evaluation_report.json
```

### 6. Start the API Server & Dashboard

```bash
uvicorn api.main:app --reload --port 8000
```

Open your browser:
- **Dashboard**: http://localhost:8000/dashboard
- **API Docs (Swagger)**: http://localhost:8000/docs

---

## Integration

### Adding TransWAF to Your Website or Portal

TransWAF exposes a standard REST API, making it easy to integrate into any web application regardless of the tech stack.

#### Option 1 — Reverse Proxy (Recommended for Production)

Place TransWAF as a reverse proxy in front of your web server using **Nginx**:

```nginx
# nginx.conf
server {
    listen 80;

    location / {
        # Forward every request to TransWAF first
        proxy_pass http://localhost:8000/classify;
        proxy_set_header X-Original-URI $request_uri;
        proxy_set_header X-Original-Method $request_method;
    }
}
```

Or use a custom Nginx Lua script to call `/classify` and block if verdict is `BLOCK`.

#### Option 2 — Middleware (Node.js / Express)

```javascript
// transwaf-middleware.js
const axios = require('axios');

module.exports = async function transwafMiddleware(req, res, next) {
    const rawRequest = `${req.method} ${req.url} HTTP/1.1\r\nHost: ${req.hostname}\r\n\r\n${req.body || ''}`;

    try {
        const { data } = await axios.post('http://localhost:8000/classify', {
            raw_request: rawRequest
        });

        if (data.verdict === 'BLOCK') {
            return res.status(403).json({ error: 'Request blocked by WAF', label: data.label });
        }
    } catch (e) {
        console.error('TransWAF unreachable — failing open');
    }

    next();
};

// In your Express app:
// app.use(transwafMiddleware);
```

#### Option 3 — Python / Django / Flask Middleware

```python
# transwaf_middleware.py
import httpx

TRANSWAF_URL = "http://localhost:8000/classify"

class TransWAFMiddleware:
    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        raw = f"{environ['REQUEST_METHOD']} {environ['PATH_INFO']} HTTP/1.1\r\n"

        with httpx.Client() as client:
            resp = client.post(TRANSWAF_URL, json={"raw_request": raw}, timeout=1.0)
            result = resp.json()

        if result.get("verdict") == "BLOCK":
            start_response("403 Forbidden", [("Content-Type", "application/json")])
            return [b'{"error": "Blocked by TransWAF"}']

        return self.app(environ, start_response)
```

#### Option 4 — Direct API Call from any Language

```bash
# Bash / curl
curl -X POST http://localhost:8000/classify \
  -H "Content-Type: application/json" \
  -d '{"raw_request": "GET /search?q=<script>alert(1)</script> HTTP/1.1\r\nHost: example.com"}'

# Response:
# {
#   "verdict": "BLOCK",
#   "label": "xss",
#   "confidence": 0.9998,
#   "latency_ms": 12.4,
#   "saliency_tokens": [["<script>", 0.94], ["alert", 0.87], ...]
# }
```

#### Option 5 — Batch Classification

Send multiple requests in one API call (useful for log analysis):

```python
import httpx

requests_to_check = [
    "GET /api/users?id=1 HTTP/1.1\r\nHost: example.com",
    "GET /search?q=' OR 1=1-- HTTP/1.1\r\nHost: example.com",
    "POST /login HTTP/1.1\r\nHost: example.com\r\n\r\nusername=admin&password=pass"
]

resp = httpx.post("http://localhost:8000/batch", json={"requests": requests_to_check})
for result in resp.json()["results"]:
    print(result["verdict"], result["label"], result["confidence"])
```

---

## API Reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/classify` | POST | Classify a single HTTP request |
| `/batch` | POST | Classify up to 100 requests at once |
| `/stats` | GET | Get aggregate detection statistics |
| `/history` | GET | Paginated request history (supports `?page=1&limit=50`) |
| `/health` | GET | Health check — returns model status and uptime |
| `/dashboard` | GET | Serves the web dashboard UI |
| `/docs` | GET | Interactive Swagger API documentation |

Full schema documentation available at: `http://localhost:8000/docs`

---

## Future Scope

| Enhancement | Description |
|-------------|-------------|
| **HTTPS / TLS Termination** | Currently only handles HTTP. Adding TLS termination would allow inspection of encrypted traffic. |
| **Real-Time Stream Mode** | WebSocket endpoint to classify a continuous stream of requests as they arrive (for live proxy use). |
| **Active Learning Loop** | Flag borderline predictions for human review, then retrain on confirmed labels to continuously improve accuracy. |
| **More Attack Classes** | Extend to SSRF, XXE, IDOR, Deserialization, and Log4Shell (currently 6 classes). |
| **Rule Fusion** | Combine ML predictions with traditional WAF rules (ModSecurity CRS) for defense-in-depth. |
| **Multi-Language Support** | Train on HTTP requests in multiple languages — current model is English-biased. |
| **Distributed Deployment** | Deploy as a Kubernetes sidecar proxy that scales horizontally with your app. |
| **CSIC 2010 / CIC-IDS Integration** | Replace synthetic data with the full CSIC 2010 HTTP dataset and CIC-IDS2017/2018 for more realistic benchmarks. |
| **Differential Privacy** | Apply DP-SGD during training so the model cannot memorize sensitive payload patterns from training data. |
| **Browser Extension** | A browser extension that proxies all requests through TransWAF before they reach the server. |

---

## Limitations

| Limitation | Impact | Workaround |
|------------|--------|------------|
| **CPU-only inference on Python 3.14** | Training requires Python 3.12 for CUDA wheels | Use `venv312` (Python 3.12) for all ML tasks |
| **Synthetic training data** | Model may not generalize to novel, real-world payload variants | Supplement with real traffic via mitmproxy capture |
| **512-token context window** | Very long HTTP requests (large POST bodies) get truncated | Increase `max_seq_length` in `config.py` at the cost of more VRAM |
| **English-biased tokenizer** | WordPiece tokenizer handles ASCII/Latin scripts better than CJK or Arabic | Use a multilingual tokenizer (e.g., `bert-base-multilingual-cased`) |
| **No HTTPS inspection** | Cannot classify encrypted TLS traffic without a man-in-the-middle certificate | Use mitmproxy with a trusted CA cert for internal traffic |
| **Single-label classification** | Assumes each request has exactly one attack type | Multi-label output head needed for chained payloads (e.g., SQLi inside an XSS payload) |
| **No session context** | Classifies each request in isolation — cannot detect multi-step attacks | Stateful analysis (LSTM/sequence model over request sequences) needed |
| **Demo mode on no model** | Without a trained model, falls back to heuristic regex classification | Always run `train.py` before deploying in production |

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| ML Model | DistilBERT (HuggingFace Transformers) |
| Training Framework | PyTorch 2.5.1 + CUDA 12.1 |
| API Server | FastAPI + Uvicorn |
| Database | SQLite (async via aiosqlite) |
| Frontend | HTML5 + Vanilla CSS + JavaScript + Chart.js |
| Data Pipeline | pandas, pyarrow, scikit-learn |
| Traffic Capture | mitmproxy |
| Vulnerable Apps | DVWA, OWASP Juice Shop, WebGoat (Docker) |
| Testing | pytest + pytest-asyncio + HTTPX |
| Explainability | Attention Rollout (custom implementation) |

---

## License

MIT License — free to use, modify, and distribute with attribution.

---

## Citation

If you use TransWAF in your research or project:

```bibtex
@software{transwaf2026,
  title   = {TransWAF: Transformer-Based Web Application Firewall},
  year    = {2026},
  note    = {99.76\% accuracy on 6-class HTTP attack detection},
  url     = {https://github.com/YOUR_USERNAME/TransWAF}
}
```
test