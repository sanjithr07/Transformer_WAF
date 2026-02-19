"""
TransWAF - Request Normalizer
Multi-pass normalization pipeline that decodes and standardizes
HTTP request payloads before transformer inference.
This is critical for evasion resistance.
"""

import re
from html import unescape
from urllib.parse import unquote, unquote_plus


class RequestNormalizer:
    """
    Multi-pass request normalizer.

    Normalization order matters:
    1. Multi-pass URL decode (handles double/triple encoding)
    2. HTML entity decode
    3. Unicode normalization
    4. Null byte removal
    5. Whitespace normalization
    6. Length truncation
    """

    # Common Unicode evasion characters
    UNICODE_SLASH_MAP = {
        "\u2215": "/",   # DIVISION SLASH
        "\uff0f": "/",   # FULLWIDTH SOLIDUS
        "\u29f8": "/",   # BIG SOLIDUS
        "\u2044": "/",   # FRACTION SLASH
        "\uff3c": "\\",  # FULLWIDTH REVERSE SOLIDUS
    }

    UNICODE_DOT_MAP = {
        "\u2024": ".",   # ONE DOT LEADER
        "\uff0e": ".",   # FULLWIDTH FULL STOP
    }

    def __init__(self, max_length: int = 2000):
        self.max_length = max_length

    def normalize(self, text: str) -> str:
        """Apply full normalization pipeline."""
        if not text:
            return ""

        # 1. Multi-pass URL decode (up to 5 passes for deep encoding)
        text = self._multi_pass_url_decode(text)

        # 2. HTML entity decode
        text = unescape(text)

        # 3. Unicode normalization (slash/dot variants)
        text = self._unicode_normalize(text)

        # 4. Remove null bytes and control chars (except space/tab/newline)
        text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)

        # 5. Normalize whitespace
        text = re.sub(r"[ \t]+", " ", text)
        text = re.sub(r"\r\n|\r", "\n", text)
        text = text.strip()

        # 6. Truncate
        return text[: self.max_length]

    def _multi_pass_url_decode(self, text: str, max_passes: int = 5) -> str:
        """
        Decode URL encoding iteratively until no more changes.
        Handles %2527 → %27 → ' (double-encoded single quote).
        """
        for _ in range(max_passes):
            decoded = unquote(text)
            # Also handle + → space in query-style payloads
            if "+" in decoded:
                decoded_plus = unquote_plus(decoded)
                if decoded_plus != decoded and not any(
                    kw in decoded_plus.lower() for kw in ["http://", "https://"]
                ):
                    decoded = decoded_plus
            if decoded == text:
                break
            text = decoded
        return text

    def _unicode_normalize(self, text: str) -> str:
        """Replace Unicode lookalike characters with ASCII equivalents."""
        for char, replacement in {**self.UNICODE_SLASH_MAP, **self.UNICODE_DOT_MAP}.items():
            text = text.replace(char, replacement)
        return text

    def normalize_request_object(self, parsed_request) -> str:
        """
        Normalize a ParsedRequest object into a single clean text string.
        Applies normalization to each component individually, then combines.
        """
        parts = []

        # Method + path
        parts.append(f"{parsed_request.method} {self.normalize(parsed_request.path)}")

        # Query string
        if parsed_request.query_string:
            parts.append(f"QUERY {self.normalize(parsed_request.query_string)}")

        # Security-relevant headers
        relevant = [
            "user-agent", "cookie", "referer", "x-forwarded-for",
            "content-type", "authorization", "origin", "x-requested-with",
        ]
        for h in relevant:
            val = parsed_request.headers.get(h, "")
            if val:
                parts.append(f"{h.upper()} {self.normalize(val)}")

        # Body
        if parsed_request.body:
            parts.append(f"BODY {self.normalize(parsed_request.body)}")

        combined = " | ".join(parts)
        return combined[: self.max_length]
