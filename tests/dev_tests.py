# tests/dev_tests.py

import requests
import ast

API_URL = "http://127.0.0.1:8000/api/scan_url"

# 👇 Test cases: (expression, expected comment)
TEST_CASES = [
    ("https://safe.com", "✅ Clean normal URL"),
    ("https://safe.com/" + "a"*101, "⚠️ Suspicious: Too long"),
    ("http://", "❌ Invalid: incomplete URL"),
    ("https://phishy.biz/login.php?user=admin", "⚠️ Suspicious login URL"),
    ("https://xn--e1afmkfd.xn--p1ai", "⚠️ Punycode domain (IDN)"),
    ("https://www.safe.com/home?session=123456", "✅ Safe with params"),
    ("ftp://files.safe.com", "❌ Non-HTTP protocol"),
    ("https://safe.com/<script>alert(1)</script>", "❌ XSS-looking URL"),
]

def test_url_scan(expr):
    try:
        url = ast.literal_eval(f'"{expr}"') if isinstance(expr, str) and ('"' not in expr and "'" not in expr) else str(ast.literal_eval(expr))
    except Exception as e:
        print(f"[!] Failed to evaluate: {expr} — {e}")
        return

    payload = {"url": url}
    try:
        response = requests.post(API_URL, json=payload)
        print(f"[→] {url}\n    ↪ {response.status_code}: {response.json()}")

    except Exception as e:
        print(f"[!] Request failed for {url}: {e}")


if __name__ == "__main__":
    print("=== ThreatPeek Dev Tester ===")
    for expr, comment in TEST_CASES:
        print(f"\n[*] Testing: {comment}")
        test_url_scan(expr)
