"""
TransWAF - Real-time Intercepting WAF Proxy
Connects external websites and analyzes all incoming and outgoing HTTPS requests.

Usage:
  mitmdump -s waf_proxy.py --listen-port 8081

  Configure your browser or app to use 127.0.0.1:8081 as the HTTP/HTTPS proxy.
  TransWAF API must be running on http://localhost:8000.
"""

import urllib.request
import json
from mitmproxy import http, ctx

TRANSWAF_URL = "http://localhost:8000/classify"

def request_to_text(flow: http.HTTPFlow) -> str:
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

class TransWAFProxy:
    def request(self, flow: http.HTTPFlow):
        # Skip static files to improve performance
        url = flow.request.pretty_url
        skip_extensions = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
                           ".css", ".woff", ".woff2", ".ttf", ".eot", ".map", ".js")
        if any(url.lower().split("?")[0].endswith(ext) for ext in skip_extensions):
            return

        raw_request = request_to_text(flow)
        
        try:
            # Send raw HTTP request string to the TransWAF classification API
            data = json.dumps({"raw_request": raw_request}).encode('utf-8')
            req = urllib.request.Request(
                TRANSWAF_URL, 
                data=data, 
                headers={'Content-Type': 'application/json'}
            )
            
            with urllib.request.urlopen(req, timeout=2.0) as response:
                result = json.loads(response.read().decode('utf-8'))
                
                action = result.get("action", "ALLOW")
                label = result.get("label_display", "Unknown")
                
                if action == "BLOCK":
                    ctx.log.warn(f"[TransWAF] BLOCKED request to {url} (Threat: {label})")
                    flow.response = http.Response.make(
                        403,  # Forbidden
                        bytes(f'{{"error": "Blocked by TransWAF Proxy", "reason": "{label}"}}', 'utf-8'),
                        {"Content-Type": "application/json"}
                    )
                elif action == "FLAG":
                    ctx.log.info(f"[TransWAF] FLAGGED request to {url} (Threat: {label})")
                    # Inject warning header to target backend
                    flow.request.headers["X-TransWAF-Threat"] = label
                    
        except Exception as e:
            ctx.log.error(f"[TransWAF] Failed to reach WAF API: {e}. Failsafe passing request.")

addons = [TransWAFProxy()]
