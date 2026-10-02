#!/usr/bin/env python3
"""C18 "RSA Museum" — artifact-certificate signing HSM with a glitchable CRT signer.

The HSM signs museum artifact certificates with RSA-2048-CRT and EMSA-PSS. Two flaws combine:
  * the PSS salt is derived deterministically from the message (should be random), so a
    message re-signs to the same encoded EM;
  * under an out-of-spec supply-voltage 'glitch' the CRT recombination occasionally faults in
    one branch, producing a signature that is correct modulo one prime only.

A correct signature and a single-branch-faulty signature of the SAME certificate then satisfy
gcd(s_correct - s_faulty, N) = p (or q), factoring the modulus. The player must find the
glitch band (too low = no faults, too high = the HSM halts), catch a usable single-branch
fault, factor N, recover d, and forge the certificate for the interlocked artifact.

  GET  /info     modulus, PSS scheme, forbidden artifact
  POST /sign     {artifact, glitch} -> {signature}   (refuses the forbidden artifact; may halt/fault)
  POST /issue    {artifact, signature} -> forbidden artifact + valid PSS -> flag
"""
import json
import os
import random
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, "src", "lib"))
import rsa  # noqa: E402

_FAULT = random.SystemRandom()  # fresh, non-reproducible glitch behaviour per request


def load_cfg():
    path = os.environ.get("INSTANCE", os.path.join(ROOT, "instance", "state", "instance.json"))
    with open(path) as f:
        return json.load(f)


def cert_message(artifact):
    return b"CERT|" + artifact.encode()


class HSM:
    def __init__(self, cfg):
        r = cfg["rsa"]
        self.key = {"n": int(r["n"], 16), "e": r["e"], "d": int(r["d"], 16),
                    "p": int(r["p"], 16), "q": int(r["q"], 16), "dp": int(r["dp"], 16),
                    "dq": int(r["dq"], 16), "qinv": int(r["qinv"], 16),
                    "bits": r["bits"], "embits": r["embits"]}
        self.g0 = cfg["glitch"]["g0"]
        self.gmax = cfg["glitch"]["gmax"]
        self.forbidden = cfg["forbidden_artifact"]
        self.flag = cfg["flag"]

    def _double_fault(self, msg):
        # both CRT branches corrupted -> unusable (gcd trivial)
        k = self.key
        m = int.from_bytes(rsa.pss_encode(msg, k["embits"]), "big")
        sp = (pow(m, k["dp"], k["p"]) + _FAULT.randrange(1, k["p"])) % k["p"]
        sq = (pow(m, k["dq"], k["q"]) + _FAULT.randrange(1, k["q"])) % k["q"]
        return (sq + k["q"] * ((k["qinv"] * (sp - sq)) % k["p"])) % k["n"]

    def sign(self, artifact, glitch):
        if artifact == self.forbidden:
            return {"status": "refused", "reason": "interlocked artifact; the HSM will not certify it"}
        try:
            glitch = int(glitch)
        except (TypeError, ValueError):
            glitch = 0
        msg = cert_message(artifact)
        if glitch > self.gmax:
            return {"status": "halted", "reason": "supply glitch tripped the HSM brown-out latch"}
        frac = 0.0 if glitch <= self.g0 else (glitch - self.g0) / (self.gmax - self.g0)
        if _FAULT.random() < frac * 0.9:
            if _FAULT.random() < (1 - frac * 0.8):          # usable single-branch fault
                s = rsa.sign(self.key, msg, faulty=True, rng=_FAULT)
            else:                                            # double-branch fault (unusable)
                s = self._double_fault(msg)
        else:
            s = rsa.sign(self.key, msg)                       # correct
        return {"status": "signed", "artifact": artifact, "signature": format(s, "x")}

    def issue(self, artifact, sig_hex):
        try:
            s = int(sig_hex, 16)
        except (TypeError, ValueError):
            return {"status": "error", "reason": "signature must be hex"}
        if not rsa.verify(self.key, cert_message(artifact), s):
            return {"status": "rejected", "reason": "certificate signature does not verify"}
        if artifact == self.forbidden:
            return {"status": "issued", "artifact": artifact,
                    "credential": "CERTIFIED-AUTHENTIC", "flag": self.flag}
        return {"status": "issued", "artifact": artifact, "note": "valid, but not interlocked"}


class GW:
    def __init__(self, cfg):
        self.hsm = HSM(cfg)

    def info(self):
        k = self.hsm.key
        return {"id": "C18-rsa-museum",
                "rsa": {"n": format(k["n"], "x"), "e": k["e"], "bits": k["n"].bit_length()},
                "signature_scheme": "RSA-CRT + EMSA-PSS (SHA-256, sLen=32)",
                "cert_rule": "signed message = b'CERT|' + artifact",
                "forbidden_artifact": self.hsm.forbidden,
                "note": "POST /sign {artifact, glitch}. glitch is a supply-voltage offset (0 = nominal). "
                        "POST /issue {artifact, signature} to register a certificate."}


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
                self._send(200, gw.hsm.sign(str(body.get("artifact", "")), body.get("glitch", 0)))
            elif self.path == "/issue":
                self._send(200, gw.hsm.issue(str(body.get("artifact", "")), body.get("signature", "")))
            else:
                self._send(404, {"status": "error"})
    return H


def main():
    cfg = load_cfg()
    gw = GW(cfg)
    host = os.environ.get("GATEWAY_BIND", cfg["net"]["gateway_host"])
    port = cfg["net"]["gateway_port"]
    srv = ThreadingHTTPServer((host, port), make_handler(gw))
    print(f"gateway: listening {host}:{port} (forbidden {gw.hsm.forbidden!r})", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
