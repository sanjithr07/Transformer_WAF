"""
TransWAF - HTTP/1.1 Request Parser
Parses raw HTTP request strings into structured components
ready for normalization and tokenization.
"""

import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse, parse_qs


@dataclass
class ParsedRequest:
    """Structured representation of an HTTP request."""
    method: str = "GET"
    path: str = "/"
    query_string: str = ""
    query_params: dict = field(default_factory=dict)
    http_version: str = "HTTP/1.1"
    headers: dict = field(default_factory=dict)
    body: str = ""
    raw: str = ""

    def to_text(self) -> str:
        """
        Serialize all components into a single text representation
        for transformer input. Includes all security-relevant fields.
        """
        parts = [f"{self.method} {self.path}"]

        if self.query_string:
            parts.append(f"QUERY {self.query_string}")

        # Include security-relevant headers only
        relevant_headers = [
            "user-agent", "cookie", "referer", "x-forwarded-for",
            "content-type", "authorization", "x-custom-header",
            "x-requested-with", "origin",
        ]
        for h in relevant_headers:
            val = self.headers.get(h, "")
            if val:
                parts.append(f"{h.upper()} {val}")

        if self.body:
            parts.append(f"BODY {self.body}")

        return " | ".join(parts)


class HTTPParser:
    """
    RFC 2616-compliant HTTP/1.1 request parser.
    Handles malformed, truncated, and injection-attempt requests gracefully.
    """

    # Matches the request line: METHOD /path?query HTTP/1.1
    REQUEST_LINE_RE = re.compile(
        r"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE|CONNECT)\s+"
        r"([^\s]+)\s+"
        r"(HTTP/[\d.]+)",
        re.IGNORECASE,
    )

    def parse(self, raw: str) -> ParsedRequest:
        """
        Parse a raw HTTP request string.

        Args:
            raw: Full HTTP request as a string (may include CRLF or LF)

        Returns:
            ParsedRequest with all extracted components
        """
        if not raw or not raw.strip():
            return ParsedRequest(raw=raw)

        # Normalize line endings
        raw = raw.replace("\r\n", "\n").replace("\r", "\n")

        # Split into header section and body
        if "\n\n" in raw:
            header_section, body = raw.split("\n\n", 1)
        else:
            header_section = raw
            body = ""

        lines = header_section.strip().split("\n")
        if not lines:
            return ParsedRequest(raw=raw, body=body)

        # Parse request line
        request_line = lines[0].strip()
        m = self.REQUEST_LINE_RE.match(request_line)
        if not m:
            # Malformed request — still attempt partial parse
            return ParsedRequest(raw=raw, body=body, path=request_line[:200])

        method = m.group(1).upper()
        full_path = m.group(2)
        http_version = m.group(3)

        # Parse URL
        try:
            parsed_url = urlparse(full_path)
            path = parsed_url.path or "/"
            query_string = parsed_url.query or ""
            query_params = parse_qs(query_string, keep_blank_values=True)
        except Exception:
            path = full_path[:500]
            query_string = ""
            query_params = {}

        # Parse headers
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                key, _, val = line.partition(":")
                headers[key.strip().lower()] = val.strip()

        return ParsedRequest(
            method=method,
            path=path,
            query_string=query_string,
            query_params=query_params,
            http_version=http_version,
            headers=headers,
            body=body.strip()[:2000],  # Limit body size
            raw=raw[:5000],
        )

    def parse_batch(self, raw_requests: list[str]) -> list[ParsedRequest]:
        """Parse multiple requests."""
        return [self.parse(r) for r in raw_requests]
