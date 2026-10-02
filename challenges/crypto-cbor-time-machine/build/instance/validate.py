#!/usr/bin/env python3
"""Sanity-check a C17 instance."""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def validate(path):
    inst = json.load(open(path))
    errs = []
    if len(bytes.fromhex(inst["issuer_seed"])) != 32:
        errs.append("issuer_seed must be 32 bytes")
    if inst["target_cargo"] in inst["allowed_cargo"]:
        errs.append("target_cargo must NOT be in allowed_cargo (else it needs no differential)")
    if not inst["allowed_cargo"]:
        errs.append("allowed_cargo is empty")
    if not inst["flag"].startswith("CTF4{"):
        errs.append("flag format")
    if errs:
        print("[validate] FAIL:")
        for e in errs:
            print("   -", e)
        return False
    print(f"[validate] ok  (target={inst['target_cargo']!r} allowed={len(inst['allowed_cargo'])} seed={inst['seed']})")
    return True


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "instance", "state", "instance.json")
    sys.exit(0 if validate(path) else 1)
