#!/usr/bin/env python3
"""C04 "Fever Dream" — thermally throttled satellite command-signing module.

The ECDSA core is constant-time in instruction count. A separate DVFS governor, however,
sets the module's clock from a power estimate that leaks: while the scalar-multiplication
accumulator is still zero (the leading-zero region of the nonce) the core runs in a
low-power fast mode, so each signature's measured energy drops by a fixed amount per
leading-zero bit of the nonce. That is a Hertzbleed-style contract bug — the core team
proved constant-time; the governor reintroduced a data-dependent signal.

The module also has real thermal inertia: heat accumulates per signature and the governor
throttles above a temperature knee, multiplying every reading. The device only cools while
idle. So the energy leak is only legible once the caller drives the module back to a cool
baseline; hammering it keeps it hot and buries the signal in throttle drift.

Endpoints:
  GET  /info     curve, public key Q, forbidden command
  POST /sign     {command, cool} -> {r, s, power}   (refuses the forbidden command)
  POST /command  {command, r, s} -> executes; the forbidden command + a valid signature -> flag
"""
import json
import math
import os
import random
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, "src", "lib"))
import ecc  # noqa: E402

_JITTER = random.SystemRandom()  # fresh (non-reproducible) measurement noise per call


def load_cfg():
    path = os.environ.get("INSTANCE", os.path.join(ROOT, "instance", "state", "instance.json"))
    with open(path) as f:
        return json.load(f)


class Device:
    def __init__(self, cfg):
        self.d = int(cfg["d"], 16)
        self.Q = (int(cfg["Q"]["x"], 16), int(cfg["Q"]["y"], 16))
        self.th = cfg["thermal"]
        self.forbidden = cfg["forbidden_command"]
        self.flag = cfg["flag"]
        self.T = self.th["AMBIENT"]
        self._cache = {}

    def _sig(self, command):
        if command not in self._cache:
            self._cache[command] = ecc.sign(self.d, command.encode())
        return self._cache[command]

    def sign(self, command, cool):
        th = self.th
        cool = max(0, min(int(cool), 4096))
        # 1) idle-cool toward ambient
        self.T = th["AMBIENT"] + (self.T - th["AMBIENT"]) * (th["DECAY"] ** cool)
        # 2) DVFS throttle multiplies the reading above the temperature knee
        throttle = 1.0 + th["SLOPE"] * max(0.0, self.T - th["KNEE"])
        r, s, z, k = self._sig(command)
        lz = ecc.N.bit_length() - k.bit_length()             # leading-zero bits of the nonce
        work = th["W0"] - th["WSTEP"] * lz                    # the constant-time-core LEAK
        power = work * throttle * math.exp(_JITTER.gauss(0.0, th["SIGMA"]))
        # 3) this signature heats the module for next time
        self.T += th["HEAT"]
        return r, s, power

    def info(self):
        return {
            "id": "C04-fever-dream",
            "curve": {"name": "secp128r1", "p": format(ecc.P, "x"), "a": format(ecc.A, "x"),
                      "b": format(ecc.B, "x"), "n": format(ecc.N, "x"),
                      "G": {"x": format(ecc.GX, "x"), "y": format(ecc.GY, "x")}},
            "pubkey": {"x": format(self.Q[0], "x"), "y": format(self.Q[1], "x")},
            "hash_rule": "z = int(sha256(command)[:16]) mod n",
            "forbidden_command": self.forbidden,
            "note": "POST /sign {command, cool} returns (r, s, power). 'cool' is idle ticks "
                    "to wait before signing. POST /sign-batch {commands:[..], cool} for a "
                    "telemetry sweep. POST /command {command, r, s} to execute.",
        }


class GW:
    def __init__(self, cfg):
        self.dev = Device(cfg)

    def sign(self, body):
        command = str(body.get("command", ""))
        if not command:
            return 400, {"status": "error", "reason": "need command"}
        if command == self.dev.forbidden:
            return 200, {"status": "refused",
                         "reason": "this command is interlocked; the module will not sign it"}
        cool = body.get("cool", 0)
        r, s, power = self.dev.sign(command, cool)
        return 200, {"status": "signed", "command": command,
                     "r": format(r, "x"), "s": format(s, "x"),
                     "power_uj": round(power, 3)}

    def sign_batch(self, body):
        cmds = body.get("commands")
        if not isinstance(cmds, list) or not cmds or len(cmds) > 20000:
            return 400, {"status": "error", "reason": "need commands: [..] (<=20000)"}
        cool = body.get("cool", 0)
        out = []
        for c in cmds:
            c = str(c)
            if c == self.dev.forbidden:
                out.append({"status": "refused", "command": c})
                continue
            r, s, power = self.dev.sign(c, cool)
            out.append({"command": c, "r": format(r, "x"), "s": format(s, "x"),
                        "power_uj": round(power, 3)})
        return 200, {"status": "signed", "results": out}

    def command(self, body):
        command = str(body.get("command", ""))
        try:
            r = int(body["r"], 16)
            s = int(body["s"], 16)
        except (KeyError, ValueError):
            return 400, {"status": "error", "reason": "need hex r, s"}
        if not ecc.verify(self.dev.Q, command.encode(), r, s):
            return 200, {"status": "rejected", "reason": "signature does not verify"}
        if command == self.dev.forbidden:
            return 200, {"status": "executed", "command": command,
                         "credential": "COMMAND-AUTHENTICATED", "flag": self.dev.flag}
        return 200, {"status": "executed", "command": command,
                     "note": "authenticated, but not an interlocked command"}


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
                self._send(200, gw.dev.info())
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
            elif self.path == "/sign-batch":
                code, obj = gw.sign_batch(body)
            elif self.path == "/command":
                code, obj = gw.command(body)
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
    print(f"gateway: listening {host}:{port} (forbidden {gw.dev.forbidden!r})", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
