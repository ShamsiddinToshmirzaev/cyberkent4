#!/usr/bin/env python3
"""Sanity-check a C05 instance: the key is 16 bytes, CMAC is well-defined, the trace
geometry fits, and the flag/target are well-formed."""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "src", "lib"))
import aes  # noqa: E402


def validate(path):
    inst = json.load(open(path))
    errs = []
    key = bytes.fromhex(inst["key"])
    if len(key) != 16:
        errs.append("key is not 16 bytes")
    tr = inst["trace"]
    if tr["S"] < tr["leak_off"] + 16 + tr["jitter"]:
        errs.append("trace too short for the leak window")
    if not (0.0 < tr["sigma"] < 6.0):
        errs.append("noise sigma out of range")
    # CMAC must be computable and deterministic
    t1 = aes.cmac(key, inst["forbidden_command"].encode())
    t2 = aes.cmac(key, inst["forbidden_command"].encode())
    if t1 != t2 or len(t1) != 16:
        errs.append("CMAC not well-defined")
    if not inst["forbidden_command"]:
        errs.append("no forbidden command")
    if not inst["flag"].startswith("CTF4{"):
        errs.append("flag format")
    if errs:
        print("[validate] FAIL:")
        for e in errs:
            print("   -", e)
        return False
    print(f"[validate] ok  (16-byte key, S={tr['S']}, sigma={tr['sigma']:.2f}, "
          f"forbidden={inst['forbidden_command']!r}, seed={inst['seed']})")
    return True


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "instance", "state", "instance.json")
    sys.exit(0 if validate(path) else 1)
