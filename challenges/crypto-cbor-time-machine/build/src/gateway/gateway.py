#!/usr/bin/env python3
"""C17 "CBOR Time Machine" — spaceport customs gateway.

Two services share one signed byte-string but decode it with different CBOR map
semantics:
  * /issue   (the issuer)  decodes FIRST-wins, refuses forbidden cargo, then signs
             the RAW bytes it received (it does NOT re-canonicalise — the bug).
  * /customs (the policy)  verifies the signature over those raw bytes, then decodes
             LAST-wins to read the cargo.
A duplicate-`cargo` badge (harmless first, antimatter last) is signed as harmless
but clears customs as antimatter. The signature is genuine Ed25519 (unforgeable);
the flaw is the parser disagreement over authenticated bytes.

The Ed25519 private key lives only here; the flag is the customs master token.
"""
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)
from cryptography.exceptions import InvalidSignature

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, "src", "lib"))
import cbor  # noqa: E402

CARGO_KEY = 3     # badge map key holding the declared cargo


def load_cfg():
    path = os.environ.get("INSTANCE", os.path.join(ROOT, "instance", "state", "instance.json"))
    with open(path) as f:
        return json.load(f)


class GW:
    def __init__(self, cfg):
        self.sk = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(cfg["issuer_seed"]))
        self.pub = self.sk.public_key()
        self.allowed = set(cfg["allowed_cargo"])
        self.target = cfg["target_cargo"]
        self.flag = cfg["flag"]

    def info(self):
        return {
            "id": "C17-cbor-time-machine",
            "issuer_pubkey": self.pub.public_bytes_raw().hex(),
            "allowed_cargo": sorted(self.allowed),
            "forbidden_target_cargo": self.target,
            "badge_schema": {"1": "version(uint)", "2": "holder(text)",
                             "3": "cargo(text)", "4": "nonce(text)"},
            "note": "Submit a CBOR-map badge to /issue for a signature; present the "
                    "signed bytes to /customs. Customs grants nothing for ordinary cargo.",
        }

    def issue(self, body):
        raw = bytes.fromhex(body["badge_hex"])
        try:
            badge = cbor.first_wins(raw)              # issuer's decoder
        except Exception:
            return 400, {"status": "error", "reason": "not a valid CBOR map"}
        cargo = badge.get(CARGO_KEY)
        if not isinstance(cargo, str):
            return 400, {"status": "error", "reason": "badge has no text cargo (key 3)"}
        if cargo not in self.allowed:
            return 200, {"status": "rejected", "reason": f"cargo {cargo!r} is not permitted"}
        # BUG: sign the exact bytes received, without re-serialising canonically
        sig = self.sk.sign(raw)
        return 200, {"status": "signed", "cargo_seen": cargo, "signature": sig.hex()}

    def customs(self, body):
        raw = bytes.fromhex(body["badge_hex"])
        sig = bytes.fromhex(body["signature"])
        try:
            self.pub.verify(sig, raw)
        except InvalidSignature:
            return 200, {"status": "denied", "reason": "invalid issuer signature"}
        try:
            badge = cbor.last_wins(raw)               # customs' decoder
        except Exception:
            return 400, {"status": "error", "reason": "not a valid CBOR map"}
        cargo = badge.get(CARGO_KEY)
        if cargo == self.target:
            return 200, {"status": "impossible_cargo_admitted", "cargo": cargo,
                         "credential": "CUSTOMS_MASTER", "flag": self.flag}
        return 200, {"status": "cleared", "cargo": cargo}


def make_handler(gw):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code, obj):
            data = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            if self.path == "/info":
                self._send(200, gw.info())
            else:
                self._send(404, {"status": "error", "reason": "no such route"})

        def do_POST(self):
            ln = int(self.headers.get("Content-Length", 0))
            try:
                body = json.loads(self.rfile.read(ln) or b"{}")
            except Exception:
                return self._send(400, {"status": "error", "reason": "bad JSON"})
            try:
                if self.path == "/issue":
                    code, obj = gw.issue(body)
                elif self.path == "/customs":
                    code, obj = gw.customs(body)
                else:
                    code, obj = 404, {"status": "error", "reason": "no such route"}
            except (KeyError, ValueError):
                code, obj = 400, {"status": "error", "reason": "malformed request"}
            self._send(code, obj)
    return H


def main():
    cfg = load_cfg()
    gw = GW(cfg)
    host = os.environ.get("GATEWAY_BIND", cfg["net"]["gateway_host"])
    port = cfg["net"]["gateway_port"]
    srv = ThreadingHTTPServer((host, port), make_handler(gw))
    print(f"gateway: listening {host}:{port} (target cargo {gw.target!r})", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
