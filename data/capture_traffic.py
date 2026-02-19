"""
TransWAF - mitmproxy Traffic Capture Addon
Captures and auto-labels HTTP requests from vulnerable web apps:
  - DVWA (Damn Vulnerable Web Application)
  - OWASP Juice Shop
  - WebGoat

Usage:
  1. Start target app (see docker-compose.yml in data/)
  2. Run: mitmdump -s data/capture_traffic.py --listen-port 8080
  3. Configure browser/tool proxy to 127.0.0.1:8080
  4. Browse/attack the target app
  5. Labeled CSV is saved to data/raw/captured_traffic.csv

Requirements:
  pip install mitmproxy
"""

import csv
import re
import time
from pathlib import Path
from datetime import datetime
from mitmproxy import http, ctx

OUTPUT_FILE = Path(__file__).parent / "raw" / "captured_traffic.csv"
OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

# ── Attack Detection Patterns ─────────────────────────────────────────────────
# These map to the same 6 classes as the TransWAF model

PATTERNS = {
    "sqli": [
        r"\bUNION\b.{0,30}\bSELECT\b",
        r"\bOR\b\s+['\"0-9].{0,10}=.{0,10}['\"0-9]",
        r"(?:--|#|/\*)[\s\w]*$",
        r"\bSLEEP\s*\(\s*\d+\s*\)",
        r"\bWAITFOR\b.{0,20}\bDELAY\b",
        r"\bSELECT\b.{0,60}\bFROM\b",
        r"\bINSERT\b.{0,30}\bINTO\b",
        r"\bDROP\b.{0,20}\bTABLE\b",
        r"(?:'\s*;\s*|\"\s*;\s*)(?:DROP|INSERT|UPDATE|DELETE)",
        r"\bINFORMATION_SCHEMA\b",
        r"\bGROUP\s+BY\b.{0,30}\bHAVING\b",
        r"'\s+AND\s+(?:1\s*=\s*1|'1'\s*=\s*'1')",
    ],
    "xss": [
        r"<\s*script[\s>]",
        r"javascript\s*:",
        r"on(?:load|error|click|mouseover|focus|blur|change|submit|keyup|keydown)\s*=",
        r"<\s*img[^>]+src\s*=\s*['\"]?\s*(?:javascript|data):",
        r"<\s*(?:iframe|object|embed|applet|link|meta)[^>]*>",
        r"document\s*\.\s*(?:cookie|location|write|getElementById)",
        r"(?:alert|prompt|confirm)\s*\(",
        r"eval\s*\(",
        r"String\.fromCharCode\s*\(",
        r"\\x[0-9a-f]{2}",
    ],
    "cmdi": [
        r"[;&|`]\s*(?:ls|cat|id|whoami|pwd|uname|ps|netstat|ifconfig|ipconfig)",
        r"(?:&&|;|\|)\s*(?:bash|sh|cmd|python|perl|ruby|php|wget|curl)",
        r"`[^`]*(?:id|whoami|ls|cat)[^`]*`",
        r"\$\([^)]*(?:id|whoami|ls|cat)[^)]*\)",
        r"/etc/(?:passwd|shadow|hosts|crontab)",
        r"(?:nc|netcat)\s+-[a-z]*\s+\d+",
        r">\s*/(?:dev/null|tmp/)",
        r"(?:bash|sh)\s+-(?:c|i)\s+['\"]",
    ],
    "path_traversal": [
        r"(?:\.\./){2,}",
        r"(?:\.\.\\){2,}",
        r"%2e%2e[%/\\]",
        r"(?:\.\.%2f){2,}",
        r"(?:\.\.%5c){2,}",
        r"(?:boot\.ini|win\.ini|system\.ini)",
        r"/etc/(?:passwd|shadow|hosts)",
        r"(?:file|php|data)://",
        r"(?:proc/self|proc/\d+)/(?:environ|cmdline|mem)",
    ],
    "rce": [
        r"\$\{[^}]+\}",               # Template injection ${...}
        r"\{\{[^}]+\}\}",             # SSTI {{...}}
        r"__(?:import|class|subclasses|mro|globals|builtins)__",
        r"(?:system|exec|shell_exec|passthru|popen)\s*\(",
        r"(?:Runtime|ProcessBuilder)\.(?:exec|getRuntime)",
        r"deserializ",
        r"java\.lang\.Runtime",
        r"(?:cmd|command)\s*=.*(?:calc|powershell|bash|sh)",
        r"(?:ldap|rmi|dns|ftp)://",   # JNDI injection
        r"(?:ognl|mvel|groovy|beanshell)\s*:",
    ],
}

COMPILED = {
    label: [re.compile(p, re.IGNORECASE) for p in patterns]
    for label, patterns in PATTERNS.items()
}

# Priority order (higher priority = checked first)
LABEL_PRIORITY = ["cmdi", "rce", "path_traversal", "sqli", "xss"]


def auto_label(full_request_text: str) -> str:
    """Auto-label a request based on regex pattern matching."""
    text = full_request_text
    for label in LABEL_PRIORITY:
        for pattern in COMPILED[label]:
            if pattern.search(text):
                return label
    return "benign"


def request_to_text(flow: http.HTTPFlow) -> str:
    """Serialize mitmproxy flow to a raw HTTP request string."""
    req = flow.request
    lines = [f"{req.method} {req.pretty_url} HTTP/{req.http_version}"]
    for k, v in req.headers.items():
        lines.append(f"{k}: {v}")
    lines.append("")
    if req.content:
        try:
            lines.append(req.content.decode("utf-8", errors="replace"))
        except Exception:
            pass
    return "\n".join(lines)


# ── mitmproxy Addon Class ─────────────────────────────────────────────────────

class TrafficCapture:
    """
    mitmproxy addon that captures HTTP requests and saves them
    as labeled CSV rows for TransWAF training.
    """

    def __init__(self):
        self.count = 0
        self.label_counts = {l: 0 for l in list(PATTERNS.keys()) + ["benign"]}

        # Write CSV header if file doesn't exist
        if not OUTPUT_FILE.exists():
            with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=[
                    "timestamp", "method", "url", "label",
                    "request_raw", "source_app"
                ])
                writer.writeheader()
            ctx.log.info(f"[TransWAF Capture] Writing to {OUTPUT_FILE}")

        ctx.log.info("[TransWAF Capture] mitmproxy addon loaded. Proxy ready.")
        ctx.log.info("[TransWAF Capture] Configure browser proxy to 127.0.0.1:8080")

    def request(self, flow: http.HTTPFlow):
        """Called for each intercepted HTTP request."""

        # Skip non-HTTP/HTTPS
        if flow.request.scheme not in ("http", "https"):
            return

        # Skip static assets (won't contain attack payloads)
        url = flow.request.pretty_url
        skip_extensions = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
                           ".css", ".woff", ".woff2", ".ttf", ".eot", ".map")
        if any(url.lower().endswith(ext) for ext in skip_extensions):
            return

        raw_text = request_to_text(flow)
        label = auto_label(raw_text)

        # Detect source app from URL/host
        host = flow.request.host.lower()
        source_app = "unknown"
        if any(x in host for x in ["dvwa", "localhost:80", "127.0.0.1:80"]):
            source_app = "dvwa"
        elif any(x in host for x in ["juice", "localhost:3000", "127.0.0.1:3000"]):
            source_app = "juice_shop"
        elif any(x in host for x in ["webgoat", "localhost:8080", "127.0.0.1:8080"]):
            source_app = "webgoat"

        # Write row
        with open(OUTPUT_FILE, "a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=[
                "timestamp", "method", "url", "label",
                "request_raw", "source_app"
            ])
            writer.writerow({
                "timestamp": datetime.utcnow().isoformat(),
                "method": flow.request.method,
                "url": url[:500],
                "label": label,
                "request_raw": raw_text[:3000],
                "source_app": source_app,
            })

        self.count += 1
        self.label_counts[label] = self.label_counts.get(label, 0) + 1

        if self.count % 50 == 0:
            ctx.log.info(
                f"[TransWAF Capture] Captured {self.count} requests | "
                + " | ".join(f"{l}: {c}" for l, c in self.label_counts.items() if c > 0)
            )


addons = [TrafficCapture()]
