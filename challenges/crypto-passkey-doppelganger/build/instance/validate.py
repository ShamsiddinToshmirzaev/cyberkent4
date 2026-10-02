#!/usr/bin/env python3
"""Sanity-check a C10 instance: the guest credential is registered, the privileged
profile names a valid subdomain of the rpId, and no staff credential exists (so the
escalation is genuinely via the origin, not a spare key)."""
import json
import os
import sys


def validate(path):
    inst = json.load(open(path))
    errs = []
    rp = inst["rp_id"]
    priv = inst["privileged_profile"]
    creds = inst["credentials"]
    if not creds or creds[0]["profile"] != "guest":
        errs.append("expected a single guest credential")
    if any(c["profile"] == priv for c in creds):
        errs.append("no credential should already hold the privileged profile")
    if not priv or "." in priv:
        errs.append("privileged profile must be a single subdomain label")
    if not f"{priv}.{rp}".endswith("." + rp):
        errs.append("privileged origin is not a subdomain of the rpId")
    if not inst["flag"].startswith("CTF4{"):
        errs.append("flag format")
    if errs:
        print("[validate] FAIL:")
        for e in errs:
            print("   -", e)
        return False
    print(f"[validate] ok  (rp_id={rp} privileged={priv!r} creds={len(creds)} seed={inst['seed']})")
    return True


if __name__ == "__main__":
    ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "instance", "state", "instance.json")
    sys.exit(0 if validate(path) else 1)
