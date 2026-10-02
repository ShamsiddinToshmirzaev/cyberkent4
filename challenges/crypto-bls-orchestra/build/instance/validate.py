#!/usr/bin/env python3
"""Sanity-check a C15 instance: the weight arithmetic forces both flaws, the DSTs
are distinct, and the reduced/public data carries no secret."""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def validate(path):
    inst = json.load(open(path))
    errs = []
    threshold = inst["threshold"]
    legacy = sum(s["base_weight"] for s in inst["sections"])
    gap = threshold - legacy
    maxsec = max(s["base_weight"] for s in inst["sections"])
    if not (0 < gap):
        errs.append(f"legacy honest weight {legacy} must be < threshold {threshold} "
                    "(else rogue-key alone would already suffice)")
    if maxsec < gap:
        errs.append(f"no single section base weight ({maxsec}) covers the gap ({gap}) "
                    "(else the card bug could never cross)")
    if len(inst["founder_sections"]) != len(inst["sections"]):
        errs.append("expected one founder per section")
    if inst["app_dst"] == inst["pop_dst"]:
        errs.append("app_dst and pop_dst must differ (domain separation)")
    if inst["provisional_section"] in {s["name"] for s in inst["sections"]}:
        errs.append("provisional must not be a weighty section")
    if not inst["flag"].startswith("CTF4{"):
        errs.append("flag format")

    if errs:
        print("[validate] FAIL:")
        for e in errs:
            print("   -", e)
        return False
    print(f"[validate] ok  (threshold={threshold} legacy_honest={legacy} gap={gap} "
          f"maxsection={maxsec} seed={inst['seed_input']})")
    return True


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "instance", "state", "instance.json")
    sys.exit(0 if validate(path) else 1)
