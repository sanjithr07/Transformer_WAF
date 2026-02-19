"""TransWAF - FastAPI Endpoint Tests"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
import asyncio
from httpx import AsyncClient, ASGITransport


@pytest.fixture(scope="module")
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="module")
async def client():
    """Async test client for the FastAPI app."""
    from api.main import app
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        yield ac


SQLI_REQUEST = (
    "GET /search?q=1'+UNION+SELECT+null,password+FROM+users-- HTTP/1.1\r\n"
    "Host: victim.example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
)

BENIGN_REQUEST = (
    "GET /products?category=electronics&page=1 HTTP/1.1\r\n"
    "Host: shop.example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
)


@pytest.mark.asyncio
class TestAPIEndpoints:

    async def test_health_endpoint(self, client):
        res = await client.get("/health")
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "ok"
        assert "model_loaded" in data
        assert "demo_mode" in data

    async def test_classify_sqli(self, client):
        res = await client.post("/classify", json={
            "raw_request": SQLI_REQUEST,
            "explain": True,
        })
        assert res.status_code == 200
        data = res.json()
        assert data["label"] == "sqli"
        assert data["action"] == "BLOCK"
        assert 0 <= data["confidence"] <= 1
        assert "all_scores" in data

    async def test_classify_benign(self, client):
        res = await client.post("/classify", json={
            "raw_request": BENIGN_REQUEST,
            "explain": False,
        })
        assert res.status_code == 200
        data = res.json()
        assert data["label"] == "benign"
        assert data["action"] == "ALLOW"

    async def test_classify_empty_request(self, client):
        res = await client.post("/classify", json={"raw_request": ""})
        assert res.status_code == 400

    async def test_batch_classify(self, client):
        res = await client.post("/batch", json={
            "requests": [SQLI_REQUEST, BENIGN_REQUEST],
            "explain": False,
        })
        assert res.status_code == 200
        data = res.json()
        assert data["total"] == 2
        assert len(data["results"]) == 2
        assert "blocked" in data
        assert "allowed" in data

    async def test_stats_endpoint(self, client):
        res = await client.get("/stats")
        assert res.status_code == 200
        data = res.json()
        assert "total_requests" in data
        assert "blocked" in data
        assert "allowed" in data
        assert "avg_latency_ms" in data

    async def test_history_endpoint(self, client):
        res = await client.get("/history?page=1&page_size=10")
        assert res.status_code == 200
        data = res.json()
        assert "items" in data
        assert "total" in data
        assert "page" in data

    async def test_history_filter_by_action(self, client):
        res = await client.get("/history?action=BLOCK")
        assert res.status_code == 200
        data = res.json()
        for item in data["items"]:
            assert item["action"] == "BLOCK"

    async def test_root_endpoint(self, client):
        res = await client.get("/")
        assert res.status_code == 200
        data = res.json()
        assert "name" in data
        assert "docs" in data

    async def test_classify_response_structure(self, client):
        res = await client.post("/classify", json={
            "raw_request": SQLI_REQUEST,
            "explain": True,
        })
        data = res.json()
        required_fields = [
            "label", "label_display", "confidence", "action",
            "threat_level", "confidence_level", "all_scores",
            "saliency", "latency_ms", "normalized_text",
        ]
        for field in required_fields:
            assert field in data, f"Missing field: {field}"
