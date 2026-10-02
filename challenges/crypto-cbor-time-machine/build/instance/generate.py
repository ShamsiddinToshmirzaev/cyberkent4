#!/usr/bin/env python3
"""Generate one C17 instance, reproducible from --seed."""
import argparse
import hashlib
import hmac
import json
import os
import random

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

CARGO_POOL = ["books", "food", "instruments", "textiles", "ore", "water",
              "seeds", "spices", "linens", "timber"]
TARGET_POOL = ["antimatter", "warp-core", "singularity", "dark-matter",
               "tachyons", "exotic-vacuum"]


def build_instance(seed, port=9170):
    rng = random.Random(f"C17|{seed}")
    issuer_seed = hashlib.sha256(f"C17-issuer|{seed}".encode()).digest()  # 32 bytes
    allowed = rng.sample(CARGO_POOL, 5) + ["harmless"]
    target = rng.choice(TARGET_POOL)
    flag_key = hashlib.sha256(f"C17-flag|{seed}".encode()).digest()
    flag = os.environ.get("FLAG") or ("CTF4{" + hmac.new(flag_key, b"impossible-antimatter", "sha256").hexdigest()[:24] + "}")
    return {
        "id": "C17-cbor-time-machine",
        "seed": seed,
        "issuer_seed": issuer_seed.hex(),
        "allowed_cargo": allowed,
        "target_cargo": target,
        "flag": flag,
        "net": {"gateway_host": "127.0.0.1", "gateway_port": port},
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--port", type=int, default=9170)
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
                   "note": "GET /info for the issuer public key, allowed cargo, and the forbidden target."},
                  f, indent=2)
    print(f"[+] C17 instance seed={args.seed} target_cargo={inst['target_cargo']!r} "
          f"allowed={inst['allowed_cargo']}")
    print(f"[+] flag = {inst['flag']}")


if __name__ == "__main__":
    main()
