#!/usr/bin/env python3
"""Sanity-check a C20 instance: the endian target exists and is enumerable, and the
current epoch is not."""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "src", "lib"))
import kms  # noqa: E402


def bswap16(e):
    return ((e & 0xFF) << 8) | ((e >> 8) & 0xFF)


def validate(path):
    inst = json.load(open(path))
    errs = []
    current = inst["current_epoch"]
    e_old = bswap16(current)
    ep = inst["epochs"]
    if e_old == current:
        errs.append("current epoch is a byte-palindrome (no distinct endian target)")
    if str(e_old) not in ep or ep[str(e_old)]["healthy"]:
        errs.append("byte-swap target epoch missing or not source-D-excluded")
    if str(current) not in ep or not ep[str(current)]["healthy"]:
        errs.append("current epoch missing or not healthy (would be enumerable)")
    if inst["clock"] >= (1 << kms.CLOCK_BITS) or inst["c"] >= (1 << kms.C_BITS):
        errs.append("clock/c out of the declared enumeration range")
    if len(bytes.fromhex(inst["salt"])) != 16:
        errs.append("salt must be 16 bytes")
    if not inst["flag"].startswith("CTF4{"):
        errs.append("flag format")
    if errs:
        print("[validate] FAIL:")
        for e in errs:
            print("   -", e)
        return False
    space = (1 << kms.CLOCK_BITS) * (1 << kms.C_BITS)
    print(f"[validate] ok  (current={current:#06x} target={e_old:#06x} excluded; "
          f"enumeration space ~2^{(kms.CLOCK_BITS+kms.C_BITS)}={space}; seed={inst['seed']})")
    return True


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "instance", "state", "instance.json")
    sys.exit(0 if validate(path) else 1)
