# 🛡️ TransWAF — Transformer-Based End-to-End Web Application Firewall

**TransWAF** is a production-ready, intent-aware Web Application Firewall that uses a fine-tuned DistilBERT transformer to classify HTTP requests into 6 attack categories in real time. It provides full explainability via attention heatmaps, making it the first open-source neural WAF with a complete deployment pipeline.

## 🔥 Features

- **6-Class Multi-Attack Detection**: SQL Injection, XSS, Command Injection, Path Traversal, Remote Code Execution, Benign
- **Intent-Based (Semantic) Analysis**: Understands *meaning* of payloads, not just pattern matching — resistant to obfuscation
- **Evasion-Aware**: Trained on adversarially mutated payloads (WAF-A-MoLE style)
- **Attention Explainability**: Visual token-level heatmaps show exactly *why* a request was blocked
- **REST API**: Drop-in FastAPI server with `/classify`, `/batch`, `/stats`, `/history` endpoints
- **Live Dashboard**: Real-time monitoring UI with attack feed, charts, and interactive payload analyzer
- **Production Pipeline**: HTTP parser → normalizer → tokenizer → transformer → decision engine

---

## 📁 Project Structure

```
WAFP/
├── data/                       # Dataset tools
│   ├── download_csic.py        # CSIC 2010 dataset instructions + download
│   ├── preprocess.py           # Parse, label, normalize, split datasets
│   └── generate_adversarial.py # Adversarial payload augmentation
│
├── src/
│   ├── pipeline/               # Core inference pipeline
│   │   ├── http_parser.py      # HTTP/1.1 request parser
│   │   ├── normalizer.py       # Multi-pass request normalization
│   │   └── transwaf.py         # Main TransWAF inference class
│   │
│   ├── training/               # Model training
│   │   ├── config.py           # Hyperparameter configuration
│   │   ├── dataset.py          # PyTorch dataset class
│   │   ├── train.py            # DistilBERT fine-tuning script
│   │   └── evaluate.py         # Evaluation and report generation
│   │
│   └── explainability/         # Interpretability
│       └── attention_viz.py    # Attention rollout saliency maps
│
├── api/                        # FastAPI REST server
│   ├── main.py                 # Application entry point
│   ├── models.py               # Pydantic request/response schemas
│   ├── database.py             # SQLite async database
│   └── middleware.py           # Logging middleware
│
├── dashboard/                  # Web UI
│   ├── index.html              # Main dashboard page
│   ├── style.css               # Dark glassmorphism theme
│   └── app.js                  # Live stats + payload analyzer
│
├── tests/                      # Test suite
│   ├── test_parser.py
│   ├── test_normalizer.py
│   ├── test_pipeline.py
│   └── test_api.py
│
├── models/                     # Saved model checkpoints (created during training)
├── logs/                       # Runtime logs
├── .env.example                # Environment variables template
├── requirements.txt
└── README.md
```

---

## 🚀 Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Configure Environment

```bash
cp .env.example .env
# Edit .env as needed
```

### 3. Prepare Dataset

```bash
# Follow instructions to download CSIC 2010:
python data/download_csic.py

# Then preprocess and generate splits:
python data/preprocess.py

# Generate adversarial augmentation:
python data/generate_adversarial.py
```

### 4. Train the Model

```bash
python src/training/train.py
# Training takes ~3 hours on CPU, ~8 minutes on GPU
# Checkpoint saved to: models/transwaf_best/
```

### 5. Evaluate

```bash
python src/training/evaluate.py
# Outputs: models/evaluation_report.json
```

### 6. Start the API Server

```bash
uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload
```

### 7. Open the Dashboard

Navigate to [http://localhost:8000/dashboard](http://localhost:8000/dashboard)

---

## 📡 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/classify` | Classify a single HTTP request |
| `POST` | `/batch` | Classify multiple HTTP requests |
| `GET` | `/stats` | Live statistics (totals, attack breakdown) |
| `GET` | `/history` | Paginated request history |
| `GET` | `/health` | Health check |
| `GET` | `/docs` | OpenAPI interactive documentation |

### Example: Classify a Request

```bash
curl -X POST http://localhost:8000/classify \
  -H "Content-Type: application/json" \
  -d '{
    "raw_request": "GET /search?q=1+UNION+SELECT+null,password+FROM+users-- HTTP/1.1\r\nHost: example.com\r\n\r\n"
  }'
```

**Response:**
```json
{
  "label": "sqli",
  "label_display": "SQL Injection",
  "confidence": 0.9823,
  "action": "BLOCK",
  "threat_level": "HIGH",
  "saliency": {
    "UNION": 0.94,
    "SELECT": 0.91,
    "password": 0.87,
    "FROM": 0.78,
    "users": 0.83,
    "--": 0.89
  },
  "latency_ms": 12.4
}
```

---

## 🔌 Integration into Your System

### As a Reverse Proxy Filter (NGINX + Lua)

```nginx
# In nginx.conf — send each request to TransWAF before routing to backend
location / {
    access_by_lua_block {
        local http = require "resty.http"
        local httpc = http.new()
        local res, err = httpc:request_uri("http://localhost:8000/classify", {
            method = "POST",
            body = '{"raw_request": "' .. ngx.var.request .. '"}',
            headers = { ["Content-Type"] = "application/json" }
        })
        local result = require("cjson").decode(res.body)
        if result.action == "BLOCK" then
            ngx.status = 403
            ngx.say('{"error":"Blocked by TransWAF","reason":"' .. result.label_display .. '"}')
            return ngx.exit(403)
        end
    }
    proxy_pass http://backend;
}
```

### As Python Middleware

```python
from src.pipeline.transwaf import TransWAF

waf = TransWAF(model_path="models/transwaf_best")

def protect(raw_http_request: str) -> bool:
    result = waf.classify(raw_http_request)
    if result["action"] == "BLOCK":
        raise SecurityException(f"Blocked: {result['label_display']}")
    return True
```

### As a Django Middleware

```python
# myapp/middleware/waf.py
from src.pipeline.transwaf import TransWAF

class TransWAFMiddleware:
    waf = TransWAF(model_path="models/transwaf_best")

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        raw = self._reconstruct_request(request)
        result = self.waf.classify(raw)
        if result["action"] == "BLOCK":
            from django.http import HttpResponseForbidden
            return HttpResponseForbidden(f"Blocked by TransWAF: {result['label_display']}")
        return self.get_response(request)

    def _reconstruct_request(self, request):
        return f"{request.method} {request.get_full_path()} HTTP/1.1\r\nHost: {request.get_host()}\r\n\r\n{request.body.decode('utf-8', errors='ignore')}"
```

---

## 🏷️ Attack Classes

| ID | Label | Description |
|----|-------|-------------|
| 0 | `benign` | Normal HTTP traffic |
| 1 | `sqli` | SQL Injection — database manipulation |
| 2 | `xss` | Cross-Site Scripting — script injection |
| 3 | `cmdi` | Command Injection — OS command execution |
| 4 | `path_traversal` | Directory traversal attacks |
| 5 | `rce` | Remote Code Execution |

---

## 🔬 Model Architecture

- **Base Model**: `distilbert-base-uncased` (66M params, 6 transformer layers)
- **Custom Pre-Training**: Additional MLM on HTTP corpus
- **Classification Head**: Dense(768→256) → ReLU → Dropout(0.3) → Dense(256→6) → Softmax
- **Normalization**: Multi-pass URL decode, HTML entity decode, case normalization
- **Chunking**: Overlapping window strategy for requests > 512 tokens

---

## 📜 License

MIT — Free for academic and commercial use.

## 📄 Citation

If you use TransWAF in your research, please cite:
```
@inproceedings{transwaf2025,
  title={TransWAF: A Transformer-Based End-to-End Web Application Firewall Pipeline for Multi-Class Attack Detection},
  author={[Your Name]},
  booktitle={[Conference Name]},
  year={2025}
}
```
