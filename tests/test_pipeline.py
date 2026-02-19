"""TransWAF - Pipeline Integration Tests (demo mode, no trained model required)"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from src.pipeline.transwaf import TransWAF


@pytest.fixture(scope="module")
def waf():
    """Create TransWAF in demo mode (no trained model needed)."""
    return TransWAF(demo_mode=True)


SQLI_REQUEST = (
    "GET /search?q=1'+UNION+SELECT+null,password+FROM+users-- HTTP/1.1\r\n"
    "Host: victim.example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
)

XSS_REQUEST = (
    "POST /comment HTTP/1.1\r\nHost: example.com\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n\r\n"
    "body=<script>alert(document.cookie)</script>"
)

BENIGN_REQUEST = (
    "GET /products?category=electronics&page=1 HTTP/1.1\r\n"
    "Host: shop.example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
)

CMDI_REQUEST = (
    "GET /ping?host=127.0.0.1;cat+/etc/passwd HTTP/1.1\r\n"
    "Host: example.com\r\nUser-Agent: curl/7.68\r\n\r\n"
)


class TestTransWAFPipeline:
    def test_returns_result_dict(self, waf):
        result = waf.classify(BENIGN_REQUEST)
        assert isinstance(result, dict)

    def test_required_fields_present(self, waf):
        result = waf.classify(SQLI_REQUEST)
        required = ["label", "label_display", "confidence", "action", "threat_level",
                    "confidence_level", "all_scores", "saliency", "latency_ms", "normalized_text"]
        for field in required:
            assert field in result, f"Missing field: {field}"

    def test_confidence_in_range(self, waf):
        result = waf.classify(BENIGN_REQUEST)
        assert 0.0 <= result["confidence"] <= 1.0

    def test_action_values(self, waf):
        result = waf.classify(SQLI_REQUEST)
        assert result["action"] in {"BLOCK", "FLAG", "ALLOW"}

    def test_label_values(self, waf):
        result = waf.classify(SQLI_REQUEST)
        valid_labels = {"benign", "sqli", "xss", "cmdi", "path_traversal", "rce"}
        assert result["label"] in valid_labels

    def test_sqli_detected(self, waf):
        result = waf.classify(SQLI_REQUEST)
        # In demo mode, heuristic should catch UNION SELECT
        assert result["label"] == "sqli"

    def test_xss_detected(self, waf):
        result = waf.classify(XSS_REQUEST)
        assert result["label"] == "xss"

    def test_cmdi_detected(self, waf):
        result = waf.classify(CMDI_REQUEST)
        assert result["label"] == "cmdi"

    def test_benign_classified(self, waf):
        result = waf.classify(BENIGN_REQUEST)
        assert result["label"] == "benign"

    def test_latency_positive(self, waf):
        result = waf.classify(SQLI_REQUEST)
        assert result["latency_ms"] > 0

    def test_batch_classify(self, waf):
        requests = [SQLI_REQUEST, BENIGN_REQUEST, XSS_REQUEST]
        results = waf.classify_batch(requests)
        assert len(results) == 3
        assert all(isinstance(r, dict) for r in results)

    def test_empty_request_handled(self, waf):
        result = waf.classify("")
        # Should not raise
        assert "label" in result

    def test_malformed_request_handled(self, waf):
        result = waf.classify("this is not http at all")
        assert "label" in result

    def test_all_scores_sum_approx_one(self, waf):
        result = waf.classify(SQLI_REQUEST)
        if result["all_scores"]:
            total = sum(result["all_scores"].values())
            assert abs(total - 1.0) < 0.3  # Demo mode uses heuristics so not strict

    def test_sqli_is_blocked(self, waf):
        result = waf.classify(SQLI_REQUEST)
        # High confidence attack → BLOCK
        if result["confidence"] >= waf.block_threshold:
            assert result["action"] == "BLOCK"

    def test_normalized_text_in_result(self, waf):
        result = waf.classify(SQLI_REQUEST)
        assert isinstance(result["normalized_text"], str)
        assert len(result["normalized_text"]) > 0
