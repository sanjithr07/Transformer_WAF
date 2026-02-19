"""
TransWAF - Pydantic Request/Response Models
"""

from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime


class ClassifyRequest(BaseModel):
    raw_request: str = Field(
        ...,
        description="Full raw HTTP/1.1 request string",
        example=(
            "GET /search?q=1+UNION+SELECT+null,password+FROM+users-- HTTP/1.1\r\n"
            "Host: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
        ),
    )
    explain: bool = Field(
        default=True,
        description="Whether to include attention saliency map in response",
    )


class BatchClassifyRequest(BaseModel):
    requests: list[str] = Field(
        ...,
        description="List of raw HTTP request strings",
        max_length=100,
    )
    explain: bool = Field(default=False)


class ClassifyResponse(BaseModel):
    label: str
    label_display: str
    confidence: float
    action: str  # BLOCK | FLAG | ALLOW
    threat_level: str  # CRITICAL | HIGH | MEDIUM | NONE
    confidence_level: str  # HIGH | MEDIUM | LOW
    all_scores: dict[str, float]
    saliency: dict[str, float]
    latency_ms: float
    normalized_text: str
    request_id: Optional[str] = None
    timestamp: Optional[datetime] = None


class BatchClassifyResponse(BaseModel):
    results: list[ClassifyResponse]
    total: int
    blocked: int
    flagged: int
    allowed: int
    total_latency_ms: float


class StatsResponse(BaseModel):
    total_requests: int
    blocked: int
    flagged: int
    allowed: int
    attack_breakdown: dict[str, int]
    avg_latency_ms: float
    model_info: dict


class HealthResponse(BaseModel):
    status: str
    model_loaded: bool
    demo_mode: bool
    device: str
    version: str = "1.0.0"


class RequestHistoryItem(BaseModel):
    id: int
    timestamp: datetime
    label: str
    label_display: str
    confidence: float
    action: str
    threat_level: str
    latency_ms: float
    normalized_text: str


class HistoryResponse(BaseModel):
    items: list[RequestHistoryItem]
    total: int
    page: int
    page_size: int
