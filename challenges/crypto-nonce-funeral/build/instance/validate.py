#!/usr/bin/env python3
"""Sanity-check a C06 instance: key valid, and the reboot window can actually yield
enough short nonces to solve the HNP."""
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
    d = int(inst["d"], 16)
    if not (0 < d < p256.N):
        errs.append("d out of range")
    T = inst["truncate_bits"]
    if not (4 <= T <= 32):
        errs.append("truncate_bits should be a modest high-bit loss")
    if inst["reboot_window"] < 1:
        errs.append("reboot_window must be >= 1")
    if inst["reboot_cooldown"] < inst["reboot_window"]:
        errs.append("cooldown should be >= window")
    # enough short nonces reachable in a reasonable number of reboots to beat 256 bits of bias
    m_needed = -(-256 // T) + 2
    if m_needed > inst["reboot_window"] * 12:
        errs.append("truncate_bits too small vs window: HNP would need too many reboots")
    if not inst["flag"].startswith("CTF4{"):
        errs.append("flag format")
    if errs:
        print("[validate] FAIL:")
        for e in errs:
            print("   -", e)
        return False
    print(f"[validate] ok  (T={T} window={inst['reboot_window']} cooldown={inst['reboot_cooldown']} "
          f"~{m_needed} short sigs needed, seed={inst['seed']})")
    return True


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "instance", "state", "instance.json")
    sys.exit(0 if validate(path) else 1)
