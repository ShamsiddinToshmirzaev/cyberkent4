#!/usr/bin/env python3
"""Generate one C06 instance, reproducible from --seed."""
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
import p256  # noqa: E402


def build_instance(seed, port=9060):
    rng = random.Random(f"C06|{seed}")
    d = rng.randrange(1, p256.N)
    flag_key = hashlib.sha256(f"C06-flag|{seed}".encode()).digest()
    flag = os.environ.get("FLAG") or ("CTF4{" + hmac.new(flag_key, b"deadbeat-master", "sha256").hexdigest()[:24] + "}")
    return {
        "id": "C06-nonce-funeral",
        "seed": seed,
        "d": format(d, "x"),
        "target_track": "0xDEADBEAT",
        "reboot_window": 8,       # short-nonce signatures granted per reboot
        "truncate_bits": 16,      # high bits lost on checkpoint restore (k < 2^240)
        "reboot_cooldown": 30,    # signatures required between reboots
        "flag": flag,
        "net": {"gateway_host": "127.0.0.1", "gateway_port": port},
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--port", type=int, default=9060)
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
                   "note": "GET /info for the public key, the unreleasable target, and maintenance behavior."},
                  f, indent=2)
    print(f"[+] C06 instance seed={args.seed} target={inst['target_track']} "
          f"window={inst['reboot_window']} truncate={inst['truncate_bits']}b")
    print(f"[+] flag = {inst['flag']}")


if __name__ == "__main__":
    main()
