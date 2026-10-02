#!/usr/bin/env python3
"""C02 reference client library + tiny CLI (shipped to players).

It ONLY speaks the wire protocol and measures round-trip latency. It contains no
crypto and no hints about the bug — building the padding-oracle classifier and the
DER forgery is the challenge.

    from client import Client
    c = Client("127.0.0.1", 9020)
    line, rtt = c.import_session(ciphertext_bytes)   # rtt in seconds
    line, rtt = c.use_session(handle_bytes, b"OPEN_ARCHIVE")
    line, rtt = c.stats()
"""
import socket
import struct
import time

OP_IMPORT, OP_USE, OP_STATS = 1, 2, 3


class Client:
    def __init__(self, host="127.0.0.1", port=9020, timeout=10.0):
        self.host, self.port, self.timeout = host, port, timeout
        self.sock = None
        self.connect()

    def connect(self):
        self.sock = socket.create_connection((self.host, self.port), self.timeout)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    def _txn(self, payload: bytes):
        """Send one framed request, return (response_line_bytes, rtt_seconds).
        Reconnects once on a broken connection."""
        for attempt in (0, 1):
            try:
                t = time.perf_counter()
                self.sock.sendall(struct.pack(">I", len(payload)) + payload)
                (ln,) = struct.unpack(">I", self._recvn(4))
                resp = self._recvn(ln)
                rtt = time.perf_counter() - t
                return resp, rtt
            except OSError:
                if attempt == 1:
                    raise
                self.connect()

    def _recvn(self, n):
        b = b""
        while len(b) < n:
            chunk = self.sock.recv(n - len(b))
            if not chunk:
                raise ConnectionError("connection closed")
            b += chunk
        return b

    def import_session(self, ciphertext: bytes):
        return self._txn(bytes([OP_IMPORT]) + ciphertext)

    def use_session(self, handle: bytes, command: bytes):
        body = bytes([OP_USE]) + struct.pack(">H", len(handle)) + handle + command
        return self._txn(body)

    def stats(self):
        return self._txn(bytes([OP_STATS]))

    def close(self):
        try:
            self.sock.close()
        except Exception:
            pass


if __name__ == "__main__":
    import argparse
    import json
    import os
    ap = argparse.ArgumentParser(description="C02 Padding Choir client")
    ap.add_argument("--host", default=None)
    ap.add_argument("--port", type=int, default=None)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("stats")
    pi = sub.add_parser("import"); pi.add_argument("hex")
    pu = sub.add_parser("use"); pu.add_argument("handle"); pu.add_argument("command")
    args = ap.parse_args()

    host, port = args.host, args.port
    if host is None or port is None:
        pub = os.path.join(os.path.dirname(__file__), "..", "samples", "instance_public.json")
        if os.path.exists(pub):
            info = json.load(open(pub))
            host = host or info["gateway_host"]
            port = port or info["gateway_port"]
    c = Client(host or "127.0.0.1", port or 9020)
    if args.cmd == "stats":
        line, rtt = c.stats()
    elif args.cmd == "import":
        line, rtt = c.import_session(bytes.fromhex(args.hex))
    elif args.cmd == "use":
        line, rtt = c.use_session(args.handle.encode(), args.command.encode())
    print(f"{line.decode(errors='replace')}   ({rtt*1e3:.2f} ms)")
