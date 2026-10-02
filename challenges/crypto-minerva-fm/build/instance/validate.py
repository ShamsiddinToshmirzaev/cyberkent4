#!/usr/bin/env python3
"""Sanity-check a C03 instance: public key matches d, flag format, target is a
forbidden manifest, and the reduced gateway config has no private key."""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "src", "lib"))
import p256  # noqa: E402


def validate(path):
    inst = json.load(open(path))
    errs = []
    d = int(inst["signer"]["d"], 16)
    x, y = p256.pubkey(d)
    if format(x, "x") != inst["pubkey"]["x"] or format(y, "x") != inst["pubkey"]["y"]:
        errs.append("public key does not match d")
    if not (0 < d < p256.N):
        errs.append("d out of range")
    if not inst["flag"].startswith("CTF4{"):
        errs.append("flag format")
    if not any(tok in inst["target_manifest"] for tok in inst["forbidden"]):
        errs.append("target manifest must contain a forbidden token (else it could be signed directly)")

    gw_path = os.path.join(os.path.dirname(path), "gateway.json")
    if os.path.exists(gw_path):
        gw = json.load(open(gw_path))
        if "signer" in gw or "d" in gw.get("pubkey", {}):
            errs.append("gateway.json must not contain the private key")

    if errs:
        print("[validate] FAIL:")
        for e in errs:
            print("   -", e)
        return False
    print(f"[validate] ok  (profile={inst['profile']} seed={inst['seed']} "
          f"W={inst['params']['work_factor']} offset={inst['params']['signer_offset']})")
    return True


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "instance", "state", "instance.json")
    sys.exit(0 if validate(path) else 1)
