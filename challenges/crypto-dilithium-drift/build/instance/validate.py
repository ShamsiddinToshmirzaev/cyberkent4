#!/usr/bin/env python3
"""Sanity-check a C12 instance: the stored public key is consistent with the master
seed, a fresh signature verifies, and the flag/forbidden fields are well-formed."""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "src", "lib"))
import mldsa  # noqa: E402


def validate(path):
    inst = json.load(open(path))
    errs = []
    pk = mldsa.keygen(bytes.fromhex(inst["mseed"]))
    if pk["rho"].hex() != inst["rho"]:
        errs.append("stored rho does not match master seed")
    if [list(p) for p in pk["t"]] != [list(p) for p in inst["t"]]:
        errs.append("stored public key t does not match master seed")
    mu = b"C12|validate"
    sig = mldsa.sign(pk, mu)
    if not mldsa.verify(pk, mu, {"cseed": sig["cseed"], "z": sig["z"]}):
        errs.append("fresh signature failed to verify")
    if not (0 < len(inst["lanes"]) < mldsa.N) or len(set(inst["lanes"])) != len(inst["lanes"]):
        errs.append("monitored lanes malformed")
    if not inst["forbidden_firmware"]:
        errs.append("no forbidden firmware")
    if not inst["flag"].startswith("CTF4{"):
        errs.append("flag format")
    if errs:
        print("[validate] FAIL:")
        for e in errs:
            print("   -", e)
        return False
    print(f"[validate] ok  (pk matches seed, sig verifies, lanes={len(inst['lanes'])}, "
          f"forbidden={inst['forbidden_firmware']!r}, seed={inst['seed']})")
    return True


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "instance", "state", "instance.json")
    sys.exit(0 if validate(path) else 1)
