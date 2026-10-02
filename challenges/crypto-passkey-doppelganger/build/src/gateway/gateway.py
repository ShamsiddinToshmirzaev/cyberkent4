#!/usr/bin/env python3
"""C10 "Passkey Doppelganger" — festival WebAuthn kiosk.

Two components disagree about *which relying party* an assertion belongs to:
  * the VERIFIER binds the assertion to the credential's registered rpId (checks
    authData.rpIdHash == SHA256(cred.rpId), the origin is a valid registrable
    suffix of that rpId per the WebAuthn spec, and the ES256 signature);
  * the privilege MAPPER derives the profile from the origin's *subdomain label*.

Because a `festival.example` passkey legitimately works on a `staff.festival.example`
origin (rpId is a registrable suffix), a guest credential presented with a
staff-subdomain origin authenticates fine yet maps to the staff profile. The
signature is genuine ES256; the flaw is deriving privilege from the origin instead
of the authenticated rpId.
"""
import base64
import hashlib
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, "src", "lib"))
import p256   # noqa: E402
import cbor   # noqa: E402


def load_cfg():
    path = os.environ.get("INSTANCE", os.path.join(ROOT, "instance", "state", "instance.json"))
    with open(path) as f:
        return json.load(f)


def b64url_decode(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def host_of(origin):
    o = origin.split("://", 1)[-1]
    return o.split("/", 1)[0].split(":", 1)[0].lower()


class GW:
    def __init__(self, cfg):
        self.rp_id = cfg["rp_id"]
        self.privileged = cfg["privileged_profile"]
        self.flag = cfg["flag"]
        self.creds = {}
        for c in cfg["credentials"]:
            self.creds[c["cred_id"]] = {
                "pub": (int(c["x"], 16), int(c["y"], 16)),
                "rp_id": c["rp_id"], "account": c["account"], "profile": c["profile"]}
        self.pending = set()
        self.lock = threading.Lock()
        self._n = 0

    def info(self):
        return {"id": "C10-passkey-doppelganger", "rp_id": self.rp_id,
                "privileged_profile": self.privileged,
                "credentials": [{"cred_id": cid, "rp_id": c["rp_id"],
                                 "account": c["account"], "profile": c["profile"]}
                                for cid, c in self.creds.items()],
                "assertion_format": "CBOR map {1:credId, 2:authData, 3:sig(r||s,64B), 4:clientDataJSON}",
                "authData": "rpIdHash(32) || flags(1, UP=0x01) || signCount(4 BE)",
                "note": "Get a challenge, then POST a CTAP assertion. Privilege follows the origin."}

    def challenge(self):
        ch = base64.urlsafe_b64encode(os.urandom(24)).decode().rstrip("=")
        with self.lock:
            self.pending.add(ch)
        return {"challenge": ch}

    def authenticate(self, body):
        try:
            raw = bytes.fromhex(body["assertion_hex"])
            m = cbor.first_wins(raw)                       # verifier's decoder
            cred_id = m[1].decode() if isinstance(m[1], bytes) else m[1]
            auth_data = m[2]
            sig = m[3]
            client_data = m[4]
        except Exception:
            return 400, {"status": "error", "reason": "malformed assertion"}

        cred = self.creds.get(cred_id)
        if not cred:
            return 200, {"status": "denied", "reason": "unknown credential"}
        if len(auth_data) < 37 or auth_data[:32] != hashlib.sha256(cred["rp_id"].encode()).digest():
            return 200, {"status": "denied", "reason": "rpIdHash does not match the credential's rpId"}
        if not (auth_data[32] & 0x01):
            return 200, {"status": "denied", "reason": "user-presence flag not set"}

        try:
            cd = json.loads(client_data)
        except Exception:
            return 200, {"status": "denied", "reason": "bad clientDataJSON"}
        if cd.get("type") != "webauthn.get":
            return 200, {"status": "denied", "reason": "wrong clientData type"}
        ch = cd.get("challenge", "")
        with self.lock:
            if ch not in self.pending:
                return 200, {"status": "denied", "reason": "unknown or replayed challenge"}
            self.pending.discard(ch)                       # single-use

        host = host_of(cd.get("origin", ""))
        rp = cred["rp_id"]
        if not (host == rp or host.endswith("." + rp)):    # WebAuthn: rpId must be a registrable suffix
            return 200, {"status": "denied", "reason": "origin is not under the credential's rpId"}

        if len(sig) != 64:
            return 200, {"status": "denied", "reason": "signature must be raw r||s (64 bytes)"}
        r = int.from_bytes(sig[:32], "big")
        s = int.from_bytes(sig[32:], "big")
        z = int.from_bytes(hashlib.sha256(auth_data + hashlib.sha256(client_data).digest()).digest(), "big")
        if not p256.verify(cred["pub"], z, r, s):
            return 200, {"status": "denied", "reason": "invalid signature"}

        # BUG: privilege is taken from the origin subdomain, not the authenticated rpId
        if host == rp:
            profile = cred["profile"]
        else:
            sub_labels = host[:-(len(rp) + 1)].split(".")
            profile = sub_labels[-1]
        if profile == self.privileged:
            return 200, {"status": "authenticated", "account": f"{profile}@{host}",
                         "profile": profile, "credential": "STAGE_MANAGER", "flag": self.flag}
        return 200, {"status": "authenticated", "account": cred["account"], "profile": profile}


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
            elif self.path == "/challenge":
                self._send(200, gw.challenge())
            else:
                self._send(404, {"status": "error"})

        def do_POST(self):
            ln = int(self.headers.get("Content-Length", 0))
            try:
                body = json.loads(self.rfile.read(ln) or b"{}")
            except Exception:
                return self._send(400, {"status": "error", "reason": "bad JSON"})
            if self.path == "/authenticate":
                code, obj = gw.authenticate(body)
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
    print(f"gateway: listening {host}:{port} (rpId {gw.rp_id!r}, privileged {gw.privileged!r})", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
