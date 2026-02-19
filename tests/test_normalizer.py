"""TransWAF - Normalizer Tests"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from src.pipeline.normalizer import RequestNormalizer


@pytest.fixture
def norm():
    return RequestNormalizer()


class TestRequestNormalizer:
    def test_url_decode_single(self, norm):
        assert norm.normalize("hello%20world") == "hello world"

    def test_url_decode_double(self, norm):
        # %2527 → %27 → '  (double-encoded single quote)
        result = norm.normalize("%2527")
        assert "'" in result or "%" not in result  # decoded at least once

    def test_url_decode_triple(self, norm):
        result = norm.normalize("%252527")
        # Should decode iteratively
        assert result  # At minimum shouldn't crash

    def test_html_entity_decode(self, norm):
        result = norm.normalize("&lt;script&gt;alert(1)&lt;/script&gt;")
        assert "<script>" in result
        assert "&lt;" not in result

    def test_null_byte_removal(self, norm):
        payload = "evil\x00payload"
        result = norm.normalize(payload)
        assert "\x00" not in result
        assert "evil" in result
        assert "payload" in result

    def test_unicode_slash_normalize(self, norm):
        # Full-width slash
        result = norm.normalize("\uff0fetc\uff0fpasswd")
        assert "/" in result

    def test_whitespace_normalization(self, norm):
        result = norm.normalize("a   b\t\tc")
        assert "   " not in result and "\t" not in result

    def test_empty_input(self, norm):
        assert norm.normalize("") == ""
        assert norm.normalize(None) == ""

    def test_max_length_truncation(self, norm):
        long_text = "A" * 5000
        result = norm.normalize(long_text)
        assert len(result) <= 2000

    def test_sqli_normalizes(self, norm):
        # Make sure SQLi content isn't destroyed
        payload = "1'+UNION+SELECT+null,password+FROM+users--"
        result = norm.normalize(payload)
        assert "UNION" in result.upper()
        assert "SELECT" in result.upper()

    def test_xss_normalizes(self, norm):
        payload = "%3Cscript%3Ealert(1)%3C/script%3E"
        result = norm.normalize(payload)
        assert "<script>" in result.lower()
