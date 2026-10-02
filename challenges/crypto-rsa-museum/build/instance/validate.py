#!/usr/bin/env python3
"""Sanity-check a C18 instance: the RSA key is consistent, a PSS signature verifies, the
glitch window is ordered, and the flag/target are well-formed."""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "src", "lib"))
import rsa  # noqa: E402


def _key(inst):
    r = inst["rsa"]
    return {"n": int(r["n"], 16), "e": r["e"], "d": int(r["d"], 16),
            "p": int(r["p"], 16), "q": int(r["q"], 16), "dp": int(r["dp"], 16),
            "dq": int(r["dq"], 16), "qinv": int(r["qinv"], 16),
            "bits": r["bits"], "embits": r["embits"]}


def validate(path):
    inst = json.load(open(path))
    errs = []
    key = _key(inst)
    if key["p"] * key["q"] != key["n"]:
        errs.append("n != p*q")
    if key["n"].bit_length() < 2048:
        errs.append("modulus smaller than 2048 bits")
    msg = b"CERT|validate"
    if not rsa.verify(key, msg, rsa.sign(key, msg)):
        errs.append("PSS sign/verify failed")
    g = inst["glitch"]
    if not (0 < g["g0"] < g["gmax"]):
        errs.append("glitch window malformed")
    if not inst["forbidden_artifact"]:
        errs.append("no forbidden artifact")
    if not inst["flag"].startswith("CTF4{"):
        errs.append("flag format")
    if errs:
        print("[validate] FAIL:")
        for e in errs:
            print("   -", e)
        return False
    print(f"[validate] ok  (n={key['n'].bit_length()}b, PSS verifies, "
          f"glitch=({g['g0']},{g['gmax']}), forbidden={inst['forbidden_artifact']!r}, seed={inst['seed']})")
    return True


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "instance", "state", "instance.json")
    sys.exit(0 if validate(path) else 1)
