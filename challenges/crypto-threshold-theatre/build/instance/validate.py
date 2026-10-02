#!/usr/bin/env python3
"""Sanity-check a C08 instance: the two shares reconstruct the group key, and the
Paillier modulus is large enough that its factorisation isn't the intended path."""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "src", "lib"))
import p256   # noqa: E402


def validate(path):
    inst = json.load(open(path))
    errs = []
    d1 = int(inst["d1"], 16)
    d2 = int(inst["d2"], 16)
    Y = (int(inst["Y"]["x"], 16), int(inst["Y"]["y"], 16))
    if p256.pubkey((d1 + d2) % p256.N) != Y:
        errs.append("d1 + d2 does not reconstruct the group public key")
    if int(inst["paillier"]["n"], 16).bit_length() < 1000:
        errs.append("Paillier modulus too small (factoring would be a shortcut)")
    if not (0 < d2 < p256.N):
        errs.append("server share out of range")
    if not inst["forbidden_movie"]:
        errs.append("no forbidden movie")
    if not inst["flag"].startswith("CTF4{"):
        errs.append("flag format")
    if errs:
        print("[validate] FAIL:")
        for e in errs:
            print("   -", e)
        return False
    print(f"[validate] ok  (d1+d2 -> Y, Paillier n {int(inst['paillier']['n'],16).bit_length()}b, seed={inst['seed']})")
    return True


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "instance", "state", "instance.json")
    sys.exit(0 if validate(path) else 1)
