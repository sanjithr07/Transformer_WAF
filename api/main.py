"""
TransWAF - FastAPI Application
Production REST API server with:
  - POST /classify         : Single HTTP request classification
  - POST /batch            : Batch classification (up to 100 requests)
  - GET  /stats            : Live aggregated statistics
  - GET  /history          : Paginated request history
  - GET  /health           : Health check
  - GET  /dashboard        : Serve monitoring dashboard
  - GET  /docs             : OpenAPI documentation (auto-generated)

Start with:
  uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload
"""

import sys
import uuid
import time
import torch
from pathlib import Path
from datetime import datetime
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from loguru import logger

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from api.models import (
    ClassifyRequest, ClassifyResponse,
    BatchClassifyRequest, BatchClassifyResponse,
    StatsResponse, HealthResponse,
    HistoryResponse, RequestHistoryItem,
)
from api import database

# Global WAF instance
_waf = None


def get_waf():
    """Get the global TransWAF instance, raising if not initialized."""
    if _waf is None:
        raise HTTPException(status_code=503, detail="TransWAF model not loaded")
    return _waf


# ─────────────────────────────────────────────────────────────
# App Lifecycle
# ─────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize model and database on startup."""
    global _waf

    # Initialize database
    await database.init_db()
    logger.info("Database initialized")

    # Load TransWAF model
    model_path = ROOT / "models" / "transwaf_best"
    try:
        from src.pipeline.transwaf import TransWAF
        if model_path.exists() and (model_path / "transwaf_config.json").exists():
            logger.info(f"Loading trained model from {model_path}")
            _waf = TransWAF(model_path=str(model_path))
        else:
            logger.warning("No trained model found — starting in demo mode")
            logger.warning("Run 'python src/training/train.py' to train the model")
            _waf = TransWAF(demo_mode=True)
        logger.info("TransWAF ready ✓")
    except Exception as e:
        logger.error(f"Failed to load TransWAF: {e}")
        logger.warning("Starting in demo mode as fallback")
        from src.pipeline.transwaf import TransWAF
        _waf = TransWAF(demo_mode=True)

    yield

    # Cleanup
    logger.info("Shutting down TransWAF API")


# ─────────────────────────────────────────────────────────────
# FastAPI Application
# ─────────────────────────────────────────────────────────────

app = FastAPI(
    title="TransWAF API",
    description=(
        "Transformer-Based Intent-Aware Web Application Firewall.\n\n"
        "Classifies HTTP requests into 6 attack categories using a fine-tuned "
        "DistilBERT model with attention-based explainability.\n\n"
        "**Attack Classes:** Benign | SQL Injection | XSS | "
        "Command Injection | Path Traversal | Remote Code Execution"
    ),
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS — allow dashboard and external integrations
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve dashboard static files
dashboard_dir = ROOT / "dashboard"
if dashboard_dir.exists():
    app.mount("/static", StaticFiles(directory=str(dashboard_dir)), name="static")


# ─────────────────────────────────────────────────────────────
# Endpoints
# ─────────────────────────────────────────────────────────────

@app.get("/", include_in_schema=False)
async def root():
    return {"name": "TransWAF API", "version": "1.0.0", "docs": "/docs", "dashboard": "/dashboard"}


@app.get("/dashboard", response_class=HTMLResponse, include_in_schema=False)
async def dashboard():
    """Serve the monitoring dashboard."""
    html_path = ROOT / "dashboard" / "index.html"
    if html_path.exists():
        return FileResponse(str(html_path))
    return HTMLResponse("<h1>Dashboard not found</h1><p>Check dashboard/ directory.</p>")


@app.get("/health", response_model=HealthResponse, tags=["System"])
async def health():
    """Health check endpoint."""
    waf = get_waf()
    return HealthResponse(
        status="ok",
        model_loaded=waf.model is not None or waf.demo_mode,
        demo_mode=waf.demo_mode,
        device=str(waf.device),
    )


@app.post("/classify", response_model=ClassifyResponse, tags=["Classification"])
async def classify(req: ClassifyRequest):
    """
    Classify a single HTTP request.

    Returns the predicted attack class, confidence score, WAF action (BLOCK/FLAG/ALLOW),
    and an attention saliency map showing which tokens influenced the decision.
    """
    waf = get_waf()

    if not req.raw_request.strip():
        raise HTTPException(status_code=400, detail="raw_request cannot be empty")

    result = waf.classify(req.raw_request)

    if not req.explain:
        result["saliency"] = {}

    # Log to database
    request_id = str(uuid.uuid4())[:8]
    result["request_id"] = request_id
    result["timestamp"] = datetime.utcnow()

    await database.insert_request(result)

    return ClassifyResponse(**result)


@app.post("/batch", response_model=BatchClassifyResponse, tags=["Classification"])
async def batch_classify(req: BatchClassifyRequest):
    """
    Classify a batch of HTTP requests (up to 100).

    More efficient than calling /classify repeatedly for multiple requests.
    """
    waf = get_waf()

    if not req.requests:
        raise HTTPException(status_code=400, detail="requests list cannot be empty")

    start = time.perf_counter()
    results = []
    blocked = flagged = allowed = 0

    for raw in req.requests:
        result = waf.classify(raw)
        if not req.explain:
            result["saliency"] = {}
        result["request_id"] = str(uuid.uuid4())[:8]
        result["timestamp"] = datetime.utcnow()
        await database.insert_request(result)

        action = result.get("action", "ALLOW")
        if action == "BLOCK":
            blocked += 1
        elif action == "FLAG":
            flagged += 1
        else:
            allowed += 1

        results.append(ClassifyResponse(**result))

    total_latency = round((time.perf_counter() - start) * 1000, 2)

    return BatchClassifyResponse(
        results=results,
        total=len(results),
        blocked=blocked,
        flagged=flagged,
        allowed=allowed,
        total_latency_ms=total_latency,
    )


@app.get("/stats", response_model=StatsResponse, tags=["Analytics"])
async def stats():
    """
    Get aggregated statistics for all classified requests.
    Useful for the dashboard and external monitoring integrations.
    """
    waf = get_waf()
    db_stats = await database.get_stats()

    model_info = {
        "demo_mode": waf.demo_mode,
        "device": str(waf.device),
        "model_config": waf.model_cfg,
    }

    return StatsResponse(
        **db_stats,
        model_info=model_info,
    )


@app.get("/history", response_model=HistoryResponse, tags=["Analytics"])
async def history(
    page: int = Query(default=1, ge=1, description="Page number"),
    page_size: int = Query(default=50, ge=1, le=200, description="Items per page"),
    action: Optional[str] = Query(default=None, description="Filter by action: BLOCK, FLAG, ALLOW"),
):
    """
    Get paginated history of all classified requests.
    Supports filtering by action (BLOCK/FLAG/ALLOW).
    """
    result = await database.get_history(
        page=page, page_size=page_size, action_filter=action
    )

    items = []
    for row in result["items"]:
        items.append(RequestHistoryItem(
            id=row["id"],
            timestamp=datetime.fromisoformat(row["timestamp"]),
            label=row["label"],
            label_display=row["label_display"],
            confidence=row["confidence"],
            action=row["action"],
            threat_level=row["threat_level"],
            latency_ms=row["latency_ms"],
            normalized_text=row.get("normalized_text", ""),
        ))

    return HistoryResponse(
        items=items,
        total=result["total"],
        page=result["page"],
        page_size=result["page_size"],
    )


# ─────────────────────────────────────────────────────────────
# Request Logging Middleware
# ─────────────────────────────────────────────────────────────

@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log all API requests with timing."""
    start = time.perf_counter()
    response = await call_next(request)
    duration = round((time.perf_counter() - start) * 1000, 2)
    logger.info(f"{request.method} {request.url.path} → {response.status_code} ({duration}ms)")
    return response


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api.main:app", host="0.0.0.0", port=8000, reload=True)
