#!/usr/bin/env python3
"""C02 "Padding Choir" — player-facing gateway.

Contract with the player:
  * Every non-winning outcome is the SAME "403 AUTH FAILED" line. There is no
    valid/invalid boolean — the only leak is latency, and the latency is noisy
    (log-normal network jitter added to every response + cross-tenant queue
    contention on the shared appliance).
  * A win (an imported *archivist* session, reachable only via the DER
    differential, which itself needs the issuerTag recovered by Bleichenbacher)
    returns a session handle; USE_SESSION on it opens the archive and yields the
    flag.

The RSA private key lives ONLY in the appliance process. This gateway never sees
it and the flag is never on the gateway filesystem in a form a padding oracle
reaches — it is handed out solely by the archive-open path.

Wire (player<->gateway), framed as [u32 len][payload]:
  request  payload = op(1) + body
     0x01 IMPORT_SESSION : body = RSA ciphertext (k bytes)
     0x02 USE_SESSION    : body = u16 handle_len + handle + command
     0x03 STATS          : body = (empty)
  response payload = ASCII line, always ending " req=<id> ts=<ms>"
"""
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
import der  # noqa: E402

OP_IMPORT, OP_USE, OP_STATS = 1, 2, 3


def load_instance():
    path = os.environ.get("INSTANCE", os.path.join(ROOT, "instance", "state", "instance.json"))
    with open(path) as f:
        return json.load(f)


class AppliancePool:
    """Thread-safe pool of persistent connections to the internal appliance."""
    def __init__(self, host, port, size):
        self.host, self.port = host, port
        self.q = queue.Queue()
        for _ in range(size):
            self.q.put(self._new())

    def _new(self):
        s = socket.create_connection((self.host, self.port))
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        return s

    def call(self, ct: bytes):
        s = self.q.get()
        try:
            code, payload = self._roundtrip(s, ct)
        except Exception:
            try:
                s.close()
            except Exception:
                pass
            s = self._new()
            code, payload = self._roundtrip(s, ct)
        finally:
            self.q.put(s)
        return code, payload

    @staticmethod
    def _roundtrip(s, ct):
        s.sendall(struct.pack(">I", len(ct)) + ct)
        code = s.recv(1)
        if not code:
            raise ConnectionError("appliance closed")
        code = code[0]
        pl = _recvn(s, 4)
        (plen,) = struct.unpack(">I", pl)
        payload = _recvn(s, plen) if plen else b""
        return code, payload


def _recvn(s, n):
    b = b""
    while len(b) < n:
        chunk = s.recv(n - len(b))
        if not chunk:
            raise ConnectionError("short read")
        b += chunk
    return b


class Bucket:
    """Global token bucket + hard query budget shared across all players."""
    def __init__(self, capacity, refill_hz, budget):
        self.cap = capacity
        self.tokens = capacity
        self.refill = refill_hz
        self.budget = budget
        self.used = 0
        self.t = time.monotonic()
        self.lock = threading.Lock()

    def take(self):
        """Return True if a query is allowed (blocks briefly to smooth bursts)."""
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
            time.sleep(min(wait, 0.05))


class Gateway:
    def __init__(self, inst):
        self.inst = inst
        p = inst["params"]
        self.k = inst["rsa"]["k"]
        self.archive_role = inst["archive_role"]
        self.flag = inst["flag"]
        self.mu = p["jitter_ms_mu"]
        self.sigma = p["jitter_ms_sigma"]
        self.pool = AppliancePool(os.environ.get("APPLIANCE_HOST", inst["net"]["appliance_host"]),
                                  inst["net"]["appliance_port"],
                                  size=p["worker_count"] * 2 + 2)
        self.bucket = Bucket(p["rate_tokens"], p["rate_refill_hz"], p["query_budget"])
        self.sessions = {}
        self.slock = threading.Lock()
        self.counter = 0
        self.clock = threading.Lock()
        self._start_cross_traffic(p, inst)

    def _start_cross_traffic(self, p, inst):
        rate = p.get("cross_traffic_rate_hz", 0.0)
        if rate <= 0:
            return

        def run():
            rng = random.Random(0xC0FFEE)
            # decoys: half conforming (00 02 -> slow), half not (fast)
            conf = bytes([0x00, 0x02]) + bytes(rng.randrange(1, 256) for _ in range(self.k - 2))
            nonconf = bytes([0x41]) + bytes(rng.randrange(0, 256) for _ in range(self.k - 1))
            while True:
                try:
                    self.pool.call(conf if rng.random() < 0.5 else nonconf)
                except Exception:
                    pass
                time.sleep(rng.expovariate(rate))
        for _ in range(2):
            threading.Thread(target=run, daemon=True).start()

    def next_id(self):
        with self.clock:
            self.counter += 1
            return self.counter

    def jitter(self):
        time.sleep(random.lognormvariate(self.mu, self.sigma) / 1000.0)

    def reply(self, line: str):
        rid = self.next_id()
        ts = int(time.time() * 1000) % 1_000_000
        return f"{line} req={rid} ts={ts}".encode()

    # ---- op handlers ----
    def import_session(self, ct: bytes):
        if not self.bucket.take():
            return self.reply("429 BUDGET EXCEEDED")
        code, payload = self.pool.call(ct)
        # policy canonicaliser (last-wins) — independent of the appliance's view
        if code == 3 and payload:
            s = der.session_last_wins(payload)
            if s and s.get("role") == self.archive_role:
                handle = os.urandom(16).hex()
                with self.slock:
                    self.sessions[handle] = self.archive_role
                return self.reply(f"200 SESSION {handle}")
        return self.reply("403 AUTH FAILED")

    def use_session(self, body: bytes):
        if len(body) < 2:
            return self.reply("403 AUTH FAILED")
        hlen = struct.unpack(">H", body[:2])[0]
        handle = body[2:2 + hlen].decode("latin1")
        cmd = body[2 + hlen:]
        with self.slock:
            role = self.sessions.get(handle)
        if role == self.archive_role and cmd.strip() == b"OPEN_ARCHIVE":
            return self.reply(f"200 ARCHIVE {self.flag}")
        return self.reply("403 AUTH FAILED")

    def stats(self):
        with self.bucket.lock:
            used, budget = self.bucket.used, self.bucket.budget
        return self.reply(f"200 STATS used={used} budget={budget}")


def make_handler(gw: Gateway):
    class H(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            while True:
                hdr = self._recvn(4)
                if not hdr:
                    return
                (ln,) = struct.unpack(">I", hdr)
                if ln == 0 or ln > 70000:
                    return
                body = self._recvn(ln)
                if body is None:
                    return
                op, rest = body[0], body[1:]
                if op == OP_IMPORT:
                    out = gw.import_session(rest)
                elif op == OP_USE:
                    out = gw.use_session(rest)
                elif op == OP_STATS:
                    out = gw.stats()
                else:
                    out = gw.reply("400 BAD OP")
                gw.jitter()                                   # uniform network delay
                self.request.sendall(struct.pack(">I", len(out)) + out)

        def _recvn(self, n):
            b = b""
            while len(b) < n:
                try:
                    chunk = self.request.recv(n - len(b))
                except OSError:
                    return None
                if not chunk:
                    return None if b else b""
                b += chunk
            return b
    return H


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    inst = load_instance()
    gw = Gateway(inst)
    host = os.environ.get("GATEWAY_BIND", inst["net"]["gateway_host"])
    port = inst["net"]["gateway_port"]
    srv = Server((host, port), make_handler(gw))
    print(f"gateway: listening {host}:{port}  (appliance "
          f"{inst['net']['appliance_host']}:{inst['net']['appliance_port']}, "
          f"budget={inst['params']['query_budget']})", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
