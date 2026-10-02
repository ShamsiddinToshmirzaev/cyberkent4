#!/usr/bin/env python3
"""
TOKEN GHOST — Local CTF Challenge Server
JWT Algorithm Confusion (RS256→HS256) + Jinja2 SSTI
"""

import base64
import hashlib
import hmac
import json
import os

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import Flask, jsonify, render_template_string, request

app = Flask(__name__)

# Generate RSA key pair on startup
PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
PUBLIC_KEY = PRIVATE_KEY.public_key()

PUBLIC_PEM = PUBLIC_KEY.public_bytes(
    serialization.Encoding.PEM,
    serialization.PublicFormat.SubjectPublicKeyInfo,
)

FLAG = os.environ.pop("FLAG", "ctf4{test_flag}")


def _b64url(n: int) -> str:
    length = (n.bit_length() + 7) // 8
    return base64.urlsafe_b64encode(n.to_bytes(length, "big")).rstrip(b"=").decode()


pub_numbers = PUBLIC_KEY.public_key().public_numbers() if hasattr(PUBLIC_KEY, "public_key") else PUBLIC_KEY.public_numbers()


@app.get("/robots.txt")
def robots():
    return (
        "User-agent: *\n"
        "Disallow: /api/admin/\n"
        "Disallow: /api/.well-known/\n"
        "Disallow: /api/internal/\n"
        "Disallow: /api/debug/\n"
    ), 200, {"Content-Type": "text/plain"}


@app.get("/api/.well-known/jwks.json")
def jwks():
    nums = PUBLIC_KEY.public_numbers()
    return jsonify({
        "keys": [{
            "kty": "RSA",
            "use": "sig",
            "kid": "key-001",
            "alg": "RS256",
            "n": _b64url(nums.n),
            "e": _b64url(nums.e),
        }]
    })


@app.post("/api/auth/login")
def login():
    data = request.get_json(silent=True) or {}
    if data.get("username") == "alice" and data.get("password") == "test1234":
        token = jwt.encode(
            {"sub": "42", "role": "user", "username": "alice", "exp": 9999999999},
            PRIVATE_KEY,
            algorithm="RS256",
            headers={"kid": "key-001"},
        )
        return jsonify({"token": token, "role": "user"})
    return jsonify({"error": "Invalid credentials"}), 401


def _b64url_decode(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def _verify_token():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None, (jsonify({"error": "Missing token"}), 401)
    token = auth[7:]
    parts = token.split(".")
    if len(parts) != 3:
        return None, (jsonify({"error": "Invalid token format"}), 401)
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
        alg = header.get("alg", "")

        if alg == "RS256":
            # Proper RS256 verification
            jwt.decode(token, PUBLIC_PEM, algorithms=["RS256"])
        elif alg == "HS256":
            # VULNERABILITY: accepts HS256 signed with RSA public key as secret
            msg = f"{parts[0]}.{parts[1]}".encode()
            expected_sig = hmac.new(PUBLIC_PEM, msg, hashlib.sha256).digest()
            provided_sig = _b64url_decode(parts[2])
            if not hmac.compare_digest(expected_sig, provided_sig):
                return None, (jsonify({"error": "Invalid signature"}), 401)
        else:
            return None, (jsonify({"error": "Unsupported algorithm"}), 401)

        return payload, None
    except Exception as e:
        return None, (jsonify({"error": "Invalid token", "detail": str(e)}), 401)


@app.get("/api/admin/dashboard")
def admin_dashboard():
    payload, err = _verify_token()
    if err:
        return err
    if payload.get("role") != "admin":
        return jsonify({
            "error": "Insufficient privileges",
            "required_role": "admin",
            "your_role": payload.get("role"),
        }), 403
    return jsonify({
        "welcome": payload.get("username"),
        "endpoints": [
            "/api/admin/users",
            "/api/admin/reports",
            "/api/admin/logs",
        ],
    })


@app.get("/api/admin/reports")
def admin_reports():
    payload, err = _verify_token()
    if err:
        return err
    if payload.get("role") != "admin":
        return jsonify({"error": "Insufficient privileges", "required_role": "admin"}), 403

    template_str = request.args.get("template", "No template provided.")
    try:
        # Intentionally vulnerable: user-controlled template via Flask's render_template_string
        rendered = render_template_string(template_str, flag=FLAG)
        return jsonify({"rendered": rendered, "engine": "jinja2"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.get("/flag.txt")
def flag_file():
    # Simulates /flag.txt being on disk (accessible via SSTI popen)
    return FLAG, 200, {"Content-Type": "text/plain"}


if __name__ == "__main__":
    print("\n[TOKEN GHOST] Local CTF server running on http://127.0.0.1:5555")
    print(f"[TOKEN GHOST] RSA public key (PEM):\n{PUBLIC_PEM.decode()}")
    print("[TOKEN GHOST] Credentials: alice / test1234\n")
    app.run(host="0.0.0.0", port=5555, debug=False)
