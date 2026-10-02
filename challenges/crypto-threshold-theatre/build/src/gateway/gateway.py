#!/usr/bin/env python3
"""C08 "Threshold Theatre" — two-party threshold-ECDSA purchase authoriser.

The group key is Y = (d1 + d2)*G; the director's tablet holds d1, the signing server
holds d2 and a Paillier secret key. During the online round the tablet submits an
encrypted value; the server computes (d2 - t) mod N and a range check ABORTS on an
underflow. That abort leaks one bit — [d2 < t] — and the preprocessing is (buggily)
reusable, so the check is an unlimited adaptive oracle. Binary-searching it recovers d2;
with d1 the attacker forges the ECDSA authorization for the forbidden purchase.
"""
import hashlib
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, "src", "lib"))
import p256       # noqa: E402
import paillier   # noqa: E402


def load_cfg():
    path = os.environ.get("INSTANCE", os.path.join(ROOT, "instance", "state", "instance.json"))
    with open(path) as f:
        return json.load(f)


class GW:
    def __init__(self, cfg):
        self.sk = {"n": int(cfg["paillier"]["n"], 16), "lam": int(cfg["paillier"]["lam"], 16),
                   "mu": int(cfg["paillier"]["mu"], 16)}
        self.N = self.sk["n"]
        self.d2 = int(cfg["d2"], 16)                    # server signing share (secret)
        self.Y = (int(cfg["Y"]["x"], 16), int(cfg["Y"]["y"], 16))
        self.forbidden = cfg["forbidden_movie"]
        self.flag = cfg["flag"]

    def info(self):
        return {"id": "C08-threshold-theatre",
                "paillier_n": format(self.N, "x"),
                "group_pubkey": {"x": format(self.Y[0], "x"), "y": format(self.Y[1], "x")},
                "curve": {"name": "P-256", "n": format(p256.N, "x")},
                "forbidden_movie": self.forbidden,
                "protocol": "Two-party ECDSA. /sign-round takes a Paillier ciphertext (encrypt "
                            "under paillier_n); the online range check aborts on underflow. "
                            "/authorize checks an ECDSA signature over a movie title.",
                "note": "Preprocessing is reused across aborted rounds."}

    def sign_round(self, body):
        try:
            c = int(body["ciphertext"], 16)
        except (KeyError, ValueError):
            return 400, {"status": "error", "reason": "need hex Paillier ciphertext"}
        t = paillier.decrypt(self.sk, c)
        w = (self.d2 - t) % self.N
        # BUG: range check leaks [d2 < t] and the preprocessing is not invalidated,
        # so this is an unlimited adaptive oracle on d2.
        if w >= self.N // 2:
            return 200, {"status": "abort", "reason": "offline transcript failed range check"}
        return 200, {"status": "continue"}

    def authorize(self, body):
        movie = str(body.get("movie", ""))
        try:
            r = int(body["r"], 16)
            s = int(body["s"], 16)
        except (KeyError, ValueError):
            return 400, {"status": "error", "reason": "need hex r, s"}
        z = int.from_bytes(hashlib.sha256(movie.encode()).digest(), "big") % p256.N
        if movie == self.forbidden and p256.verify(self.Y, z, r, s):
            return 200, {"status": "authorized", "movie": movie,
                         "credential": "GREENLIT", "flag": self.flag}
        return 200, {"status": "denied"}


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
                self._send(404, {"status": "error"})

        def do_POST(self):
            ln = int(self.headers.get("Content-Length", 0))
            try:
                body = json.loads(self.rfile.read(ln) or b"{}")
            except Exception:
                return self._send(400, {"status": "error", "reason": "bad JSON"})
            if self.path == "/sign-round":
                code, obj = gw.sign_round(body)
            elif self.path == "/authorize":
                code, obj = gw.authorize(body)
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
    print(f"gateway: listening {host}:{port} (forbidden {gw.forbidden!r})", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
