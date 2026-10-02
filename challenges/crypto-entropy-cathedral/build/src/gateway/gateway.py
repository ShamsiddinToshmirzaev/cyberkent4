#!/usr/bin/env python3
"""C20 "Entropy Cathedral" — distributed cloud KMS.

Derives a per-epoch rotation root from four entropy sources via a SpongeMixer, and
authorises the RING_THE_ENTROPY_BELL capability under the CURRENT epoch's root. Two
things go wrong: on some epochs source D is health-excluded and sources A/B collapse
to the boot clock (so that epoch's root is enumerable from the published commitment),
and the ring authoriser reads the submitted epoch little-endian while the root lookup
reads it big-endian — so a recovered OLD-epoch root can authorise the current epoch.
"""
import hashlib
import hmac
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, "src", "lib"))
import kms  # noqa: E402


def load_cfg():
    path = os.environ.get("INSTANCE", os.path.join(ROOT, "instance", "state", "instance.json"))
    with open(path) as f:
        return json.load(f)


class GW:
    def __init__(self, cfg):
        self.salt = bytes.fromhex(cfg["salt"])
        self.clock = cfg["clock"]                       # secret
        self.c = cfg["c"]                               # secret
        self.current = cfg["current_epoch"]
        self.flag = cfg["flag"]
        # epochs: {e(int): {"D": hex|None, "healthy": bool}}
        self.epochs = {int(e): {"D": (bytes.fromhex(v["D"]) if v["D"] else None),
                                "healthy": v["healthy"]} for e, v in cfg["epochs"].items()}

    def _root(self, e):
        info = self.epochs[e]
        D = info["D"] if info["healthy"] else None
        return kms.derive_root(self.salt, self.clock, self.c, D, e)

    def info(self):
        commits = {str(e): kms.commitment(self._root(e), e).hex() for e in self.epochs}
        return {"id": "C20-entropy-cathedral",
                "salt": self.salt.hex(),
                "current_epoch": self.current,
                "clock_bits": kms.CLOCK_BITS, "c_source_bits": kms.C_BITS,
                "root_commitments": commits,
                "derivation": {
                    "A": "SHA256(salt|'A'|clock:3B)", "B": "SHA256(salt|'B'|clock:3B) (same clock as A)",
                    "C": "SHA256(salt|'C'|c:1B)", "D": "SHA256(salt|'D'|sample) — excluded when unhealthy",
                    "seed": "SHA256(salt| A|B|C[|D] |epoch:2B)",
                    "root": "SHA256('root'|seed)", "commitment": "SHA256('commit'|root|epoch:2B)[:10]",
                    "ring_mac": "HMAC-SHA256(root, 'RING_THE_ENTROPY_BELL'|epoch_bytes)"},
                "note": "Ring the bell for the current epoch: POST /ring {epoch, mac}."}

    def telemetry(self):
        # health dashboard: which epochs excluded source D (plus decoy metrics)
        rows = {}
        for e, v in self.epochs.items():
            rows[str(e)] = {"source_D_healthy": v["healthy"],
                            "sources_A_B_correlation": "high",
                            "mixer_lanes": 4 if v["healthy"] else 3}
        return {"epochs": rows, "note": "Excluded sources reduce the mixer to 3 lanes."}

    def ring(self, body):
        try:
            eb = bytes.fromhex(body["epoch"])
            mac = bytes.fromhex(body["mac"])
        except (KeyError, ValueError):
            return 400, {"status": "error", "reason": "need hex epoch + mac"}
        if len(eb) != 2:
            return 400, {"status": "error", "reason": "epoch must be 2 bytes"}
        e_authorizer = int.from_bytes(eb, "little")     # authoriser: little-endian
        e_validator = int.from_bytes(eb, "big")         # root lookup: big-endian
        if e_authorizer != self.current:
            return 200, {"status": "denied", "reason": "not the current epoch"}
        if e_validator not in self.epochs:
            return 200, {"status": "denied", "reason": "unknown rotation epoch"}
        root = self._root(e_validator)
        if hmac.compare_digest(mac, kms.ring_mac(root, eb)):
            return 200, {"status": "bell_rung", "credential": "RING_THE_ENTROPY_BELL", "flag": self.flag}
        return 200, {"status": "denied", "reason": "bad authorization"}


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
            elif self.path == "/telemetry":
                self._send(200, gw.telemetry())
            else:
                self._send(404, {"status": "error"})

        def do_POST(self):
            ln = int(self.headers.get("Content-Length", 0))
            try:
                body = json.loads(self.rfile.read(ln) or b"{}")
            except Exception:
                return self._send(400, {"status": "error", "reason": "bad JSON"})
            if self.path == "/ring":
                code, obj = gw.ring(body)
            else:
                code, obj = 404, {"status": "error"}
            self._send(code, obj)
    return H


def main():
    cfg = load_cfg()
    gw = GW(cfg)
    host = os.environ.get("GATEWAY_BIND", cfg["net"]["gateway_host"])
    port = cfg["net"]["gateway_port"]
    srv = ThreadingHTTPServer((host, port), make_handler(gw))
    print(f"gateway: listening {host}:{port} (current epoch {gw.current:#06x}, {len(gw.epochs)} epochs)", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
