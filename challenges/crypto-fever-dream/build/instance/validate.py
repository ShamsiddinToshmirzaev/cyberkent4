#!/usr/bin/env python3
"""Sanity-check a C04 instance: the key pair is consistent, a signature verifies, the
thermal constants are in the solvable range, and the flag/target are well-formed."""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "src", "lib"))
import ecc  # noqa: E402


def validate(path):
    inst = json.load(open(path))
    errs = []
    d = int(inst["d"], 16)
    Q = (int(inst["Q"]["x"], 16), int(inst["Q"]["y"], 16))
    if ecc.pubkey(d) != Q:
        errs.append("public key does not match d")
    r, s, z, k = ecc.sign(d, b"validate")
    if not ecc.verify(Q, b"validate", r, s):
        errs.append("signature failed to verify")
    th = inst["thermal"]
    # the leak must survive averaging: a single leading-zero energy step should exceed the
    # averaged jitter floor (the solver averages many samples, so this bound is generous).
    if th["WSTEP"] <= th["W0"] * th["SIGMA"] / 8:
        errs.append("WSTEP too small relative to jitter (leak unreadable even after averaging)")
    if not (0 < th["DECAY"] < 1):
        errs.append("cooling decay out of range")
    if not inst["forbidden_command"]:
        errs.append("no forbidden command")
    if not inst["flag"].startswith("CTF4{"):
        errs.append("flag format")
    if errs:
        print("[validate] FAIL:")
        for e in errs:
            print("   -", e)
        return False
    print(f"[validate] ok  (Q matches d, sig verifies, WSTEP={th['WSTEP']:.0f}, "
          f"forbidden={inst['forbidden_command']!r}, seed={inst['seed']})")
    return True


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "instance", "state", "instance.json")
    sys.exit(0 if validate(path) else 1)
