"""TransWAF - HTTP Parser Tests"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from src.pipeline.http_parser import HTTPParser, ParsedRequest


@pytest.fixture
def parser():
    return HTTPParser()


class TestHTTPParser:
    def test_basic_get(self, parser):
        raw = "GET /search?q=hello HTTP/1.1\r\nHost: example.com\r\n\r\n"
        req = parser.parse(raw)
        assert req.method == "GET"
        assert req.path == "/search"
        assert "q" in req.query_params
        assert req.query_string == "q=hello"

    def test_post_with_body(self, parser):
        raw = (
            "POST /login HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "\r\n"
            "username=admin&password=secret"
        )
        req = parser.parse(raw)
        assert req.method == "POST"
        assert req.path == "/login"
        assert "username=admin" in req.body

    def test_headers_parsing(self, parser):
        raw = (
            "GET / HTTP/1.1\r\n"
            "Host: example.com\r\n"
            "User-Agent: TestBot/1.0\r\n"
            "Cookie: session=abc; csrf=xyz\r\n"
            "\r\n"
        )
        req = parser.parse(raw)
        assert req.headers.get("user-agent") == "TestBot/1.0"
        assert "session=abc" in req.headers.get("cookie", "")

    def test_malformed_request(self, parser):
        raw = "NOT VALID HTTP"
        req = parser.parse(raw)
        # Should not raise; graceful fallback
        assert isinstance(req, ParsedRequest)

    def test_empty_request(self, parser):
        req = parser.parse("")
        assert req.method == "GET"

    def test_sqli_payload_preserved(self, parser):
        raw = "GET /search?q=1'+OR+'1'='1 HTTP/1.1\r\nHost: target.com\r\n\r\n"
        req = parser.parse(raw)
        assert req.query_string != ""
        assert req.path == "/search"

    def test_lf_line_endings(self, parser):
        raw = "GET /api/data HTTP/1.1\nHost: example.com\n\n"
        req = parser.parse(raw)
        assert req.method == "GET"

    def test_to_text(self, parser):
        raw = "GET /test?foo=bar HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Test\r\n\r\n"
        req = parser.parse(raw)
        text = req.to_text()
        assert "GET" in text
        assert "/test" in text

    def test_batch_parse(self, parser):
        requests = [
            "GET / HTTP/1.1\r\nHost: a.com\r\n\r\n",
            "POST /login HTTP/1.1\r\nHost: b.com\r\n\r\ndata=value",
        ]
        results = parser.parse_batch(requests)
        assert len(results) == 2
        assert results[0].method == "GET"
        assert results[1].method == "POST"
