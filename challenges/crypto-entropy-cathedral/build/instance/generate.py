#!/usr/bin/env python3
"""Generate one C20 instance, reproducible from --seed.

Invariant that makes it solvable: the current epoch's byte-swap is a real PAST epoch
whose source D was health-excluded (so its root is enumerable), while the current
epoch is healthy (its root is not). Decoy excluded epochs exist but do not byte-swap
to the current epoch, so only the real target works through the endian confusion.
"""
import argparse
import hashlib
import hmac
import json
import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "src", "lib"))
import kms  # noqa: E402


def bswap16(e):
    return ((e & 0xFF) << 8) | ((e >> 8) & 0xFF)


def build_instance(seed, port=9200):
    rng = random.Random(f"C20|{seed}")
    salt = bytes(rng.getrandbits(8) for _ in range(16))
    clock = rng.getrandbits(kms.CLOCK_BITS)
    c = rng.getrandbits(kms.C_BITS)
    # current epoch: two distinct nonzero bytes so its byte-swap is a different epoch
    b0 = rng.randint(1, 255)
    b1 = rng.randint(1, 255)
    while b1 == b0:
        b1 = rng.randint(1, 255)
    current = (b0 << 8) | b1
    e_old = bswap16(current)                     # the enumerable, endian-confusable target

    epochs = {}

    def add(e, healthy):
        epochs[e] = {"D": (bytes(rng.getrandbits(8) for _ in range(16)).hex() if healthy else None),
                     "healthy": healthy}

    add(current, True)     # current epoch: D healthy -> root NOT enumerable
    add(e_old, False)      # past target: D excluded -> root enumerable, byte-swaps to current
    # decoys: some healthy, some excluded — but excluded decoys must NOT byte-swap to current
    while len(epochs) < 8:
        e = rng.getrandbits(16)
        if e in epochs or e == 0:
            continue
        healthy = rng.random() < 0.5
        if not healthy and bswap16(e) == current:
            healthy = True    # don't create a second endian-target
        add(e, healthy)

    flag_key = hashlib.sha256(f"C20-flag|{seed}".encode()).digest()
    flag = os.environ.get("FLAG") or ("CTF4{" + hmac.new(flag_key, b"ring-the-entropy-bell", "sha256").hexdigest()[:24] + "}")
    return {
        "id": "C20-entropy-cathedral",
        "seed": seed,
        "salt": salt.hex(),
        "clock": clock, "c": c,                  # secret
        "current_epoch": current,
        "epochs": {str(e): v for e, v in epochs.items()},
        "flag": flag,
        "net": {"gateway_host": "127.0.0.1", "gateway_port": port},
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--port", type=int, default=9200)
    ap.add_argument("--out", default=os.path.join(ROOT, "instance", "state", "instance.json"))
    ap.add_argument("--player-dir", default=os.path.join(ROOT, "player", "samples"))
    args = ap.parse_args()

    inst = build_instance(args.seed, args.port)
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    os.makedirs(args.player_dir, exist_ok=True)
    with open(args.out, "w") as f:
        json.dump(inst, f, indent=2)
    with open(os.path.join(args.player_dir, "instance_public.json"), "w") as f:
        json.dump({"id": inst["id"], "gateway_host": inst["net"]["gateway_host"],
                   "gateway_port": inst["net"]["gateway_port"],
                   "note": "GET /info for salt, current epoch, root commitments and the derivation; "
                           "GET /telemetry for source-health per epoch."}, f, indent=2)
    print(f"[+] C20 instance seed={args.seed} current={inst['current_epoch']:#06x} "
          f"target(e_old)={bswap16(inst['current_epoch']):#06x} epochs={len(inst['epochs'])}")
    print(f"[+] flag = {inst['flag']}")


if __name__ == "__main__":
    main()
