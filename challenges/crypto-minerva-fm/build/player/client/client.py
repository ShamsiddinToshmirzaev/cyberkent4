#!/usr/bin/env python3
"""C03 reference client (shipped to players). Framed-TCP wrapper; measures the
round-trip time of each signature (the whole point). No crypto here."""
import socket
import struct
import time

OP_SIGN, OP_SUBMIT, OP_STATS = 1, 2, 3


class Client:
    def __init__(self, host="127.0.0.1", port=9030, timeout=10):
        self.host, self.port, self.timeout = host, port, timeout
        self.connect()

    def connect(self):
        self.sock = socket.create_connection((self.host, self.port), self.timeout)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    def _txn(self, payload):
        for attempt in (0, 1):
            try:
                t = time.perf_counter()
                self.sock.sendall(struct.pack(">I", len(payload)) + payload)
                (ln,) = struct.unpack(">I", self._recvn(4))
                resp = self._recvn(ln)
                return resp, time.perf_counter() - t
            except OSError:
                if attempt:
                    raise
                self.connect()

    def _recvn(self, n):
        b = b""
        while len(b) < n:
            c = self.sock.recv(n - len(b))
            if not c:
                raise ConnectionError("closed")
            b += c
        return b

    def sign(self, message: bytes):
        """Returns (r, s, rtt_seconds) or (None, None, rtt) if refused."""
        resp, rtt = self._txn(bytes([OP_SIGN]) + message)
        parts = resp.split()
        if len(parts) >= 3 and parts[0] == b"200":
            return int(parts[2], 16), int(parts[3], 16), rtt
        return None, None, rtt

    def submit(self, message: bytes, r: int, s: int):
        body = (bytes([OP_SUBMIT]) + struct.pack(">H", len(message)) + message
                + r.to_bytes(32, "big") + s.to_bytes(32, "big"))
        resp, _ = self._txn(body)
        return resp.decode("utf-8", "replace")

    def stats(self):
        resp, _ = self._txn(bytes([OP_STATS]))
        return resp.decode("utf-8", "replace")

    def close(self):
        try:
            self.sock.close()
        except Exception:
            pass


if __name__ == "__main__":
    import argparse
    import json
    import os
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default=None)
    ap.add_argument("--port", type=int, default=None)
    ap.add_argument("cmd", choices=["stats", "sign"])
    ap.add_argument("--msg", default='{"station":"88.5","title":"demo","mix":"x"}')
    a = ap.parse_args()
    host, port = a.host, a.port
    if host is None or port is None:
        p = os.path.join(os.path.dirname(__file__), "..", "samples", "instance_public.json")
        if os.path.exists(p):
            info = json.load(open(p))
            host = host or info["gateway_host"]
            port = port or info["gateway_port"]
    c = Client(host or "127.0.0.1", port or 9030)
    if a.cmd == "stats":
        print(c.stats())
    else:
        r, s, rtt = c.sign(a.msg.encode())
        print(f"r={r:x}\ns={s:x}\nrtt={rtt*1e3:.3f} ms" if r else f"refused ({rtt*1e3:.3f} ms)")
