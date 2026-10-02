#!/usr/bin/env python3
"""C03 "Minerva FM" — player-facing gateway (Python).

Signs *track manifests* on request via the internal C signer, but refuses any
privileged manifest (the "ghost-dj" broadcast). Adds a network-jitter model to
every response so the per-signature timing leak is noisy. The win is a valid
signature over the forbidden manifest — which the honest signer never produces, so
it requires recovering the DRM key from the nonce leak.

The private key lives ONLY in the signer; this gateway holds the public key (to
verify a submission) and the flag (which it hands out on a win).

Wire (framed [u32 len][payload]); payload = op(1) + body:
  0x01 SIGN   : body = manifest bytes
  0x02 SUBMIT : body = u16 msglen | manifest | r(32) | s(32)
  0x03 STATS
"""
import hashlib
import json
import os
import queue
import random
import socket
import socketserver
import struct
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, "src", "lib"))
import p256  # noqa: E402

OP_SIGN, OP_SUBMIT, OP_STATS = 1, 2, 3


def load_cfg():
    path = os.environ.get("INSTANCE", os.path.join(ROOT, "instance", "state", "gateway.json"))
    with open(path) as f:
        return json.load(f)


def recvn(sock, n):
    b = b""
    while len(b) < n:
        c = sock.recv(n - len(b))
        if not c:
            raise ConnectionError("short read")
        b += c
    return b


class SignerPool:
    def __init__(self, host, port, size):
        self.host, self.port = host, port
        self.q = queue.Queue()
        for _ in range(size):
            self.q.put(self._new())

    def _new(self):
        s = socket.create_connection((self.host, self.port))
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        return s

    def sign(self, z32):
        s = self.q.get()
        try:
            s.sendall(struct.pack(">I", 32) + z32)
            resp = recvn(s, 64)
        except Exception:
            try:
                s.close()
            except Exception:
                pass
            s = self._new()
            s.sendall(struct.pack(">I", 32) + z32)
            resp = recvn(s, 64)
        finally:
            self.q.put(s)
        return int.from_bytes(resp[:32], "big"), int.from_bytes(resp[32:], "big")


class Bucket:
    def __init__(self, cap, refill, budget):
        self.cap, self.tokens, self.refill = cap, cap, refill
        self.budget, self.used = budget, 0
        self.t = time.monotonic()
        self.lock = threading.Lock()

    def take(self):
        while True:
            with self.lock:
                now = time.monotonic()
                self.tokens = min(self.cap, self.tokens + (now - self.t) * self.refill)
                self.t = now
                if self.used >= self.budget:
                    return False
                if self.tokens >= 1:
                    self.tokens -= 1
                    self.used += 1
                    return True
                wait = (1 - self.tokens) / self.refill
            time.sleep(min(wait, 0.02))


class GW:
    def __init__(self, cfg):
        self.cfg = cfg
        p = cfg["params"]
        self.pub = (int(cfg["pubkey"]["x"], 16), int(cfg["pubkey"]["y"], 16))
        self.target = cfg["target_manifest"]
        self.flag = cfg["flag"]
        self.forbidden = cfg["forbidden"]
        self.jit_mu = p["jitter_us_base"]
        self.jit_sigma = p["jitter_us_sigma"]
        host = os.environ.get("SIGNER_HOST", cfg["net"]["signer_host"])
        self.pool = SignerPool(host, cfg["net"]["signer_port"], p.get("signer_conns", 6))
        self.bucket = Bucket(p["rate_tokens"], p["rate_refill_hz"], p["query_budget"])
        self.counter = 0
        self.clock = threading.Lock()

    def jitter(self):
        us = self.jit_mu + random.gauss(0, self.jit_sigma)
        if us > 0:
            time.sleep(us / 1e6)

    def rid(self):
        with self.clock:
            self.counter += 1
            return self.counter

    def z_of(self, msg: bytes) -> bytes:
        return hashlib.sha256(msg).digest()

    def sign(self, msg: bytes):
        text = msg.decode("utf-8", "replace")
        if any(tok in text for tok in self.forbidden):
            return f"403 FORBIDDEN req={self.rid()}".encode()
        if not self.bucket.take():
            return f"429 BUDGET req={self.rid()}".encode()
        r, s = self.pool.sign(self.z_of(msg))
        return f"200 SIG {r:064x} {s:064x} req={self.rid()}".encode()

    def submit(self, body: bytes):
        if len(body) < 2:
            return b"403 DENIED"
        mlen = struct.unpack(">H", body[:2])[0]
        msg = body[2:2 + mlen]
        rest = body[2 + mlen:]
        if len(rest) != 64:
            return b"403 DENIED"
        r = int.from_bytes(rest[:32], "big")
        s = int.from_bytes(rest[32:], "big")
        z = int.from_bytes(self.z_of(msg), "big")
        if msg.decode("utf-8", "replace") == self.target and p256.verify(self.pub, z, r, s):
            return f"200 FLAG {self.flag} req={self.rid()}".encode()
        return f"403 DENIED req={self.rid()}".encode()

    def stats(self):
        with self.bucket.lock:
            return f"200 STATS used={self.bucket.used} budget={self.bucket.budget} req={self.rid()}".encode()


def make_handler(gw):
    class H(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            while True:
                try:
                    hdr = recvn(self.request, 4)
                except Exception:
                    return
                (ln,) = struct.unpack(">I", hdr)
                if ln == 0 or ln > 1 << 20:
                    return
                try:
                    body = recvn(self.request, ln)
                except Exception:
                    return
                op, rest = body[0], body[1:]
                if op == OP_SIGN:
                    out = gw.sign(rest)
                    gw.jitter()
                elif op == OP_SUBMIT:
                    out = gw.submit(rest)
                elif op == OP_STATS:
                    out = gw.stats()
                else:
                    out = b"400 BAD OP"
                self.request.sendall(struct.pack(">I", len(out)) + out)
    return H


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    cfg = load_cfg()
    gw = GW(cfg)
    host = os.environ.get("GATEWAY_BIND", cfg["net"]["gateway_host"])
    port = cfg["net"]["gateway_port"]
    srv = Server((host, port), make_handler(gw))
    print(f"gateway: listening {host}:{port} (signer "
          f"{cfg['net']['signer_host']}:{cfg['net']['signer_port']}, budget={cfg['params']['query_budget']})",
          flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
