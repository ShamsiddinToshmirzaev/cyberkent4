#!/usr/bin/env python3
"""Sanity-check a C07 instance: the shares reconstruct to the group public key."""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "src", "lib"))
import frost  # noqa: E402


def validate(path):
    inst = json.load(open(path))
    errs = []
    Y = (int(inst["Y"]["x"], 16), int(inst["Y"]["y"], 16))
    shares = {int(k): int(v, 16) for k, v in inst["shares"].items()}
    if len(shares) < inst["threshold"]:
        errs.append("fewer shares than the threshold")
    # any threshold-sized subset must reconstruct the same secret -> Y
    x1 = frost.reconstruct({i: shares[i] for i in list(shares)[:inst["threshold"]]})
    x2 = frost.reconstruct({i: shares[i] for i in list(shares)[-inst["threshold"]:]})
    if x1 != x2 or frost.G_mul(x1) != Y:
        errs.append("shares do not consistently reconstruct the group public key")
    if not inst["forbidden_message"]:
        errs.append("no forbidden message")
    if not inst["flag"].startswith("CTF4{"):
        errs.append("flag format")
    if errs:
        print("[validate] FAIL:")
        for e in errs:
            print("   -", e)
        return False
    print(f"[validate] ok  ({inst['threshold']}-of-{len(shares)} FROST, shares reconstruct Y, seed={inst['seed']})")
    return True


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "instance", "state", "instance.json")
    sys.exit(0 if validate(path) else 1)
