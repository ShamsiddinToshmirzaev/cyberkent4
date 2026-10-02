#!/usr/bin/env python3
"""C06 "Nonce Funeral" — music-label ECDSA manifest signer.

The signing pipeline serialises its nonce state through a NonceContext that is
checkpointed on every maintenance reboot. The checkpoint field is too narrow: on
restore, the high bytes of the nonce are lost, so for the first few signatures
after a reboot the nonce is TRUNCATED (short). No nonce is ever repeated (each is
counter-derived), so a repeated-r attack is impossible — but the short post-reboot
nonces are recoverable via the Hidden Number Problem.

The signer refuses to sign the unreleased target album, so winning requires
recovering the private key from the post-reboot signatures and forging it.
"""
import hashlib
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, "src", "lib"))
import p256  # noqa: E402


def load_cfg():
    path = os.environ.get("INSTANCE", os.path.join(ROOT, "instance", "state", "instance.json"))
    with open(path) as f:
        return json.load(f)


def msg_of(track):
    return f"release-v1|track:{track}".encode()


def z_of(track):
    return int.from_bytes(hashlib.sha256(msg_of(track)).digest(), "big") % p256.N


class GW:
    def __init__(self, cfg):
        self.d = int(cfg["d"], 16)
        self.pub = p256.pubkey(self.d)
        self.target = cfg["target_track"]
        self.flag = cfg["flag"]
        self.K = cfg["reboot_window"]          # short-nonce signatures per reboot
        self.T = cfg["truncate_bits"]          # high bits lost on checkpoint restore
        self.cooldown = cfg["reboot_cooldown"]  # signs required between reboots
        self.lock = threading.Lock()
        self.counter = 0
        self.post_reboot = 0
        self.signs_since_reboot = self.cooldown  # allow the first reboot immediately

    def _k(self):
        self.counter += 1
        full = int.from_bytes(
            hashlib.sha512(self.d.to_bytes(32, "big") + b"|nonce|" + self.counter.to_bytes(8, "big")).digest(),
            "big") % p256.N
        if self.post_reboot > 0:
            self.post_reboot -= 1
            k = full & ((1 << (256 - self.T)) - 1)    # checkpoint truncation: high bits lost
            return k if k else 1
        return full if full else 1

    def info(self):
        return {"id": "C06-nonce-funeral",
                "pubkey": {"x": format(self.pub[0], "x"), "y": format(self.pub[1], "x")},
                "curve": {"name": "P-256", "n": format(p256.N, "x")},
                "target_track": self.target,
                "message_format": "release-v1|track:<track_id>  (signed hash = SHA256 of that, mod n)",
                "maintenance": {"reboot_window": self.K, "reboot_cooldown": self.cooldown,
                                "checkpoint": "the signing context is restored from a narrow checkpoint on reboot"},
                "note": "The label signs track manifests. The unreleased album cannot be signed. "
                        "A maintenance reboot restores the signing context from its checkpoint."}

    def sign(self, body):
        track = str(body.get("track", ""))
        if track == self.target:
            return 200, {"status": "rejected", "reason": "album is unreleased; cannot be signed"}
        with self.lock:
            self.signs_since_reboot += 1
            k = self._k()
        r, s = p256.sign(self.d, z_of(track), k)
        return 200, {"status": "signed", "track": track,
                     "r": format(r, "x"), "s": format(s, "x")}

    def maintenance(self, _body):
        with self.lock:
            if self.signs_since_reboot < self.cooldown:
                return 200, {"status": "cooldown",
                             "reason": f"need {self.cooldown} signatures since last reboot",
                             "signs_since_reboot": self.signs_since_reboot}
            self.signs_since_reboot = 0
            self.post_reboot = self.K
        return 200, {"status": "rebooted", "note": "signing context restored from checkpoint"}

    def release(self, body):
        track = str(body.get("track", ""))
        try:
            r = int(body["r"], 16)
            s = int(body["s"], 16)
        except (KeyError, ValueError):
            return 400, {"status": "error", "reason": "need hex r, s"}
        if track == self.target and p256.verify(self.pub, z_of(track), r, s):
            return 200, {"status": "released", "credential": "MASTER_RELEASE", "flag": self.flag}
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
            if self.path == "/sign":
                code, obj = gw.sign(body)
            elif self.path == "/maintenance":
                code, obj = gw.maintenance(body)
            elif self.path == "/release":
                code, obj = gw.release(body)
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
    print(f"gateway: listening {host}:{port} (target {gw.target!r}, window={gw.K}, "
          f"truncate={gw.T}b, cooldown={gw.cooldown})", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
