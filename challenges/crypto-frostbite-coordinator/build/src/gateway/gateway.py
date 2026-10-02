#!/usr/bin/env python3
"""C07 "Frostbite Coordinator" — ice-castle treasury, 3-of-5 FROST Schnorr.

The player drives the coordinator-facing protocol. Two implementation flaws compose:
  * round2 (partial signing) does NOT consume the cached nonce — only /commit does —
    so a partial response can be requested twice on the same nonce; and
  * the binding factor rho is derived from the signer SET + message only, not from the
    commitments B, so the group commitment/challenge changes with B while the signer's
    effective nonce r_i does not.
Two partial responses on the same r_i under different challenges reveal lambda_i * x_i;
summed over a valid signer set that yields the group secret, which forges the
OPEN_ICE_VAULT signature (which the signers refuse to produce honestly).
"""
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, "src", "lib"))
import frost  # noqa: E402


def load_cfg():
    path = os.environ.get("INSTANCE", os.path.join(ROOT, "instance", "state", "instance.json"))
    with open(path) as f:
        return json.load(f)


def pt_from_json(o):
    P = (int(o["x"], 16), int(o["y"], 16))
    if not frost.on_curve(P):
        raise ValueError("point not on curve")
    return P


def pt_to_json(P):
    return {"x": format(P[0], "x"), "y": format(P[1], "x")}


class GW:
    def __init__(self, cfg):
        self.shares = {int(k): int(v, 16) for k, v in cfg["shares"].items()}
        self.n = len(self.shares)
        self.t = cfg["threshold"]
        self.Y = (int(cfg["Y"]["x"], 16), int(cfg["Y"]["y"], 16))
        self.forbidden = cfg["forbidden_message"].encode()
        self.flag = cfg["flag"]
        self.nonces = {}                       # (session, target) -> (d, e)
        self.lock = threading.Lock()

    def info(self):
        return {"id": "C07-frostbite-coordinator",
                "group_pubkey": pt_to_json(self.Y),
                "signers": sorted(self.shares),
                "threshold": self.t,
                "curve": {"name": "P-256", "n": format(frost.Q, "x")},
                "forbidden_message": self.forbidden.decode(),
                "protocol": "FROST-style Schnorr; /round1 to commit a nonce, /round2 for a "
                            "partial response, /commit to finalise, /open to open the vault.",
                "hashes": {"challenge": "SHA256('FROST-chal'|R|Y|msg)",
                           "rho": "SHA256('FROST-rho'|i|msg|sorted(set))"}}

    def round1(self, body):
        session = str(body["session_id"])
        target = int(body["target"])
        if target not in self.shares:
            return 400, {"status": "error", "reason": "unknown signer"}
        d = 1 + int.from_bytes(os.urandom(32), "big") % (frost.Q - 1)
        e = 1 + int.from_bytes(os.urandom(32), "big") % (frost.Q - 1)
        with self.lock:
            self.nonces[(session, target)] = (d, e)
        return 200, {"status": "committed", "target": target,
                     "D": pt_to_json(frost.G_mul(d)), "E": pt_to_json(frost.G_mul(e))}

    def round2(self, body):
        session = str(body["session_id"])
        target = int(body["target"])
        S = [int(j) for j in body["set"]]
        msg = str(body["msg"]).encode()
        if msg == self.forbidden:
            return 200, {"status": "refused", "reason": "signers will not sign the vault-open message"}
        if target not in S or any(j not in self.shares for j in S):
            return 400, {"status": "error", "reason": "bad signer set"}
        try:
            B = [(int(e["j"]), pt_from_json(e["D"]), pt_from_json(e["E"])) for e in body["B"]]
        except (KeyError, ValueError):
            return 400, {"status": "error", "reason": "bad commitment list B"}
        with self.lock:
            nonce = self.nonces.get((session, target))
        if nonce is None:
            return 400, {"status": "error", "reason": "no committed nonce for this session/target (run /round1)"}
        d_i, e_i = nonce
        z_i, c, R = frost.partial(d_i, e_i, target, self.shares[target], S, msg, B, self.Y)
        # BUG: the nonce is NOT consumed here (only /commit consumes it).
        return 200, {"status": "partial", "target": target,
                     "z": format(z_i, "x"), "c": format(c, "x"), "R": pt_to_json(R)}

    def commit(self, body):
        session = str(body["session_id"])
        with self.lock:
            for key in [k for k in self.nonces if k[0] == session]:
                del self.nonces[key]
        return 200, {"status": "committed"}

    def open_vault(self, body):
        try:
            R = pt_from_json(body["R"])
            z = int(body["z"], 16)
        except (KeyError, ValueError):
            return 400, {"status": "error", "reason": "need point R and scalar z"}
        if frost.schnorr_verify(self.Y, self.forbidden, R, z):
            return 200, {"status": "vault_open", "credential": "OPEN_ICE_VAULT", "flag": self.flag}
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
            try:
                route = {"/round1": gw.round1, "/round2": gw.round2,
                         "/commit": gw.commit, "/open": gw.open_vault}.get(self.path)
                if route is None:
                    return self._send(404, {"status": "error"})
                code, obj = route(body)
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
    print(f"gateway: listening {host}:{port} ({gw.t}-of-{gw.n} FROST, forbidden {gw.forbidden.decode()!r})", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
