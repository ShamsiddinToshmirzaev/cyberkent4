#!/usr/bin/env python3
"""Sanity-check a C16 instance: the public key matches d, the two chain ids
differ, and both stages share the verifying contract (so the legacy domain is
identical across chains = replayable)."""
import json
import os
import sys

from cryptography.hazmat.primitives.asymmetric import ec

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def validate(path):
    inst = json.load(open(path))
    errs = []
    d = int(inst["signer"]["d"], 16)
    pn = ec.derive_private_key(d, ec.SECP256R1()).public_key().public_numbers()
    if format(pn.x, "x") != inst["signer"]["x"] or format(pn.y, "x") != inst["signer"]["y"]:
        errs.append("public key does not match d")
    ch = inst["chains"]
    if ch["mainstage"]["chain_id"] == ch["teststage"]["chain_id"]:
        errs.append("main and test chain ids must differ")
    if len(bytes.fromhex(inst["domain"]["verifying_contract"])) != 20:
        errs.append("verifying_contract must be 20 bytes")
    p = inst["params"]
    # both flaws must be required: replay-only (budget) < threshold <= budget*2
    if not (p["free_budget"] * p["credit_per_ticket"] < p["mint_threshold"]
            <= p["free_budget"] * p["credit_per_ticket"] * 2):
        errs.append("threshold must force BOTH flaws: budget < threshold <= 2*budget")
    if not inst["flag"].startswith("CTF4{"):
        errs.append("flag format")

    if errs:
        print("[validate] FAIL:")
        for e in errs:
            print("   -", e)
        return False
    print(f"[validate] ok  (main={ch['mainstage']['chain_id']} test={ch['teststage']['chain_id']} "
          f"budget={p['free_budget']} threshold={p['mint_threshold']} seed={inst['seed']})")
    return True


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "instance", "state", "instance.json")
    sys.exit(0 if validate(path) else 1)
