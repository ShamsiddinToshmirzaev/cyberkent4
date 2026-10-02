#!/usr/bin/env python3
"""C05 "Neon EM Oracle" — arcade token authenticator with an EM/power side channel.

The booth mints tokens by running AES-128 over a player-supplied challenge block under a
fixed booth key, and it hands back the EM trace of that operation "for calibration". The
trace leaks the Hamming weight of the round-1 S-box outputs, HW(SBox(pt[i] ^ k[i])), at a
fixed (per-booth) sample offset, buried under noise and per-trace timing jitter (each trace
carries a trigger spike for alignment). Averaging many aligned traces and running
Correlation Power Analysis byte-by-byte recovers the booth key.

The prize capability is an AES-CMAC tag over a command. There is no endpoint that returns a
CMAC, and the mint oracle returns only traces (never a ciphertext), so the key must be
recovered from the side channel; then the forbidden command's tag can be forged.

  GET  /info        trace length, tag scheme, forbidden command
  POST /mint        {plaintext} -> {trace}                 (EM side-channel oracle)
  POST /mint-batch  {plaintexts:[..]} -> {traces:[..]}
  POST /redeem      {command, tag} -> forbidden command + valid CMAC -> flag
"""
import json
import os
import random
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, "src", "lib"))
import aes  # noqa: E402

_NOISE = random.SystemRandom()  # fresh, non-reproducible measurement noise per trace


def load_cfg():
    path = os.environ.get("INSTANCE", os.path.join(ROOT, "instance", "state", "instance.json"))
    with open(path) as f:
        return json.load(f)


class Booth:
    def __init__(self, cfg):
        self.key = bytes.fromhex(cfg["key"])
        t = cfg["trace"]
        self.S = t["S"]; self.leak_off = t["leak_off"]; self.jitter = t["jitter"]; self.sigma = t["sigma"]
        self.forbidden = cfg["forbidden_command"]
        self.flag = cfg["flag"]

    def trace(self, pt):
        S, sig = self.S, self.sigma
        shift = _NOISE.randrange(self.jitter + 1)
        tr = [_NOISE.gauss(0.0, sig) for _ in range(S)]
        if shift < S:
            tr[shift] = 50.0                       # alignment trigger
        for i in range(16):
            v = aes.HW[aes.SBOX[pt[i] ^ self.key[i]]]
            idx = shift + self.leak_off + i
            if 0 <= idx < S:
                tr[idx] += v * 1.0 + _NOISE.gauss(0.0, sig)
        return [round(x, 3) for x in tr]


class GW:
    def __init__(self, cfg):
        self.b = Booth(cfg)

    def info(self):
        return {"id": "C05-neon-em-oracle",
                "cipher": "AES-128",
                "trace_len": self.b.S,
                "leak_hint": "round-1 EM trace; each mint has a trigger spike for alignment",
                "tag_scheme": "tag = AES-CMAC(booth_key, command_utf8)",
                "forbidden_command": self.b.forbidden,
                "note": "POST /mint {plaintext:hex16} -> {trace}. POST /mint-batch for a sweep. "
                        "POST /redeem {command, tag:hex} to spend a token."}

    def _pt(self, s):
        pt = bytes.fromhex(s)
        if len(pt) != 16:
            raise ValueError
        return pt

    def mint(self, body):
        try:
            pt = self._pt(str(body["plaintext"]))
        except (KeyError, ValueError):
            return 400, {"status": "error", "reason": "need plaintext: 16-byte hex"}
        return 200, {"status": "minted", "trace": self.b.trace(pt)}

    def mint_batch(self, body):
        pts = body.get("plaintexts")
        if not isinstance(pts, list) or not pts or len(pts) > 20000:
            return 400, {"status": "error", "reason": "need plaintexts: [hex16, ...] (<=20000)"}
        out = []
        for s in pts:
            try:
                pt = self._pt(str(s))
            except ValueError:
                return 400, {"status": "error", "reason": "each plaintext must be 16-byte hex"}
            out.append(self.b.trace(pt))
        return 200, {"status": "minted", "traces": out}

    def redeem(self, body):
        command = str(body.get("command", ""))
        tag = str(body.get("tag", ""))
        try:
            tag_b = bytes.fromhex(tag)
        except ValueError:
            return 400, {"status": "error", "reason": "tag must be hex"}
        expected = aes.cmac(self.b.key, command.encode())
        if tag_b != expected:
            return 200, {"status": "rejected", "reason": "invalid token (CMAC mismatch)"}
        if command == self.b.forbidden:
            return 200, {"status": "redeemed", "command": command,
                         "credential": "TOKEN-VALID", "flag": self.b.flag}
        return 200, {"status": "redeemed", "command": command,
                     "note": "valid token, but not a restricted command"}


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
            if self.path == "/mint":
                code, obj = gw.mint(body)
            elif self.path == "/mint-batch":
                code, obj = gw.mint_batch(body)
            elif self.path == "/redeem":
                code, obj = gw.redeem(body)
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
    print(f"gateway: listening {host}:{port} (forbidden {gw.b.forbidden!r})", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
