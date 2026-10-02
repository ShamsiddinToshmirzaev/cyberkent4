#!/usr/bin/env python3
"""C12 "Dilithium Drift" — firmware-signing authority (textbook ML-DSA / Dilithium).

Two subsystems share one process:

  * the SIGNER produces deterministic ML-DSA signatures over firmware manifests and
    refuses to sign the forbidden manifest;
  * the QA-TELEMETRY layer attaches a "nonce drift report" to every signature so
    operators can confirm the masking RNG isn't stuck.

The contract bug: QA believes the drift report exposes only harmless health statistics,
but a domain-separation slip makes each reported "lane level" the RAW value of the
accepted masking vector y at that coordinate. Because z = y + c*s1, revealing y on a
fixed set of lanes turns every signature into linear equations in the secret s1. Enough
signatures over the (public, per-signature) challenge c pin s1 by plain linear algebra
mod q; s2 follows from t = A*s1 + s2, and the full key forges the forbidden manifest.
"""
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, "src", "lib"))
import mldsa  # noqa: E402


def load_cfg():
    path = os.environ.get("INSTANCE", os.path.join(ROOT, "instance", "state", "instance.json"))
    with open(path) as f:
        return json.load(f)


def firmware_mu(name):
    """Domain-separated message that the signer commits to for a firmware manifest."""
    return b"C12-firmware|" + name.encode()


class GW:
    def __init__(self, cfg):
        self.pk = mldsa.keygen(bytes.fromhex(cfg["mseed"]))
        self.lanes = list(cfg["lanes"])           # QA-monitored nonce lanes (per instance)
        self.forbidden = cfg["forbidden_firmware"]
        self.flag = cfg["flag"]

    def info(self):
        return {
            "id": "C12-dilithium-drift",
            "scheme": "textbook ML-DSA (Dilithium), uncompressed public key",
            "params": {"n": mldsa.N, "q": mldsa.Q, "k": mldsa.K, "l": mldsa.L,
                       "eta": mldsa.ETA, "tau": mldsa.TAU,
                       "gamma1": mldsa.GAMMA1, "gamma2": mldsa.GAMMA2, "beta": mldsa.BETA},
            "rho": self.pk["rho"].hex(),
            "t": [list(p) for p in self.pk["t"]],
            "forbidden_firmware": self.forbidden,
            "message_rule": "signed message mu = b'C12-firmware|' + firmware_name",
            "note": "POST /sign {firmware}; POST /publish {firmware, cseed, z}. "
                    "Each /sign attaches a QA nonce-drift report.",
        }

    def _drift_report(self, y):
        # QA "health telemetry": reports the level on each monitored lane, per component.
        # BUG: these levels are exactly the raw masking-vector coefficients y[j][lane].
        return {"lanes": self.lanes,
                "lane_levels": [[y[j][i] for i in self.lanes] for j in range(mldsa.L)]}

    def sign(self, body):
        name = str(body.get("firmware", ""))
        if not name:
            return 400, {"status": "error", "reason": "need firmware name"}
        if name == self.forbidden:
            return 200, {"status": "refused",
                         "reason": "this manifest is on the deny list; the signer will not sign it"}
        captured = {}

        def leak_fn(y):
            captured["y"] = [list(p) for p in y]

        sig = mldsa.sign(self.pk, firmware_mu(name), leak_fn=leak_fn)
        return 200, {"status": "signed", "firmware": name,
                     "cseed": sig["cseed"].hex(),
                     "z": [list(p) for p in sig["z"]],
                     "qa_drift": self._drift_report(captured["y"])}

    def publish(self, body):
        name = str(body.get("firmware", ""))
        cseed = body.get("cseed", "")
        z = body.get("z")
        if not isinstance(z, list):
            return 400, {"status": "error", "reason": "need z"}
        try:
            sig = {"cseed": str(cseed), "z": [[int(x) % mldsa.Q for x in p] for p in z]}
        except (TypeError, ValueError):
            return 400, {"status": "error", "reason": "malformed z"}
        ok = mldsa.verify(self.pk, firmware_mu(name), sig)
        if ok and name == self.forbidden:
            return 200, {"status": "published", "firmware": name,
                         "credential": "SIGNED-BY-AUTHORITY", "flag": self.flag}
        if ok:
            return 200, {"status": "published", "firmware": name,
                         "note": "valid, but not the forbidden manifest"}
        return 200, {"status": "rejected", "reason": "signature does not verify"}


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
            elif self.path == "/publish":
                code, obj = gw.publish(body)
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
