#!/usr/bin/env python3
"""Generate one C05 "Neon EM Oracle" instance, reproducible from --seed.

Secret: the AES-128 key. Per-instance nuisance parameters: the EM-trace geometry (leak
offset, jitter, sample count) and the noise level, so the player must locate the leak and
average per instance. Key, trace parameters, forbidden command, and flag live in the server
instance file; the player only receives the endpoint and the public description.
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
import aes  # noqa: E402

FORBIDDEN_POOL = ["JACKPOT-RELEASE", "OPEN-VAULT-DOOR", "COMP-INFINITE-CREDITS",
                  "DISABLE-AUDIT-LOG", "MASTER-REFUND"]


def build_instance(seed, port=9050):
    rng = random.Random(f"C05|{seed}")
    key = bytes(rng.randrange(256) for _ in range(16))
    leak_off = rng.randint(6, 12)
    jitter = rng.randint(4, 8)
    sigma = rng.uniform(2.0, 3.0)
    S = leak_off + 16 + jitter + 6
    forbidden = FORBIDDEN_POOL[rng.randrange(len(FORBIDDEN_POOL))]
    flag_key = hashlib.sha256(f"C05-flag|{seed}".encode()).digest()
    flag = os.environ.get("FLAG") or ("CTF4{" + hmac.new(flag_key, forbidden.encode(), "sha256").hexdigest()[:24] + "}")
    return {
        "id": "C05-neon-em-oracle",
        "seed": seed,
        "key": key.hex(),                  # secret AES-128 key
        "trace": {"S": S, "leak_off": leak_off, "jitter": jitter, "sigma": sigma},
        "forbidden_command": forbidden,
        "flag": flag,
        "net": {"gateway_host": "127.0.0.1", "gateway_port": port},
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--port", type=int, default=9050)
    ap.add_argument("--out", default=os.path.join(ROOT, "instance", "state", "instance.json"))
    ap.add_argument("--player-dir", default=os.path.join(ROOT, "player", "samples"))
    args = ap.parse_args()

    inst = build_instance(args.seed, args.port)
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    os.makedirs(args.player_dir, exist_ok=True)
    with open(args.out, "w") as f:
        json.dump(inst, f)
    with open(os.path.join(args.player_dir, "instance_public.json"), "w") as f:
        json.dump({"id": inst["id"], "gateway_host": inst["net"]["gateway_host"],
                   "gateway_port": inst["net"]["gateway_port"],
                   "note": "GET /info for the trace length, the tag scheme, and the forbidden command."},
                  f, indent=2)
    print(f"[+] C05 instance seed={args.seed} S={inst['trace']['S']} forbidden={inst['forbidden_command']!r}")
    print(f"[+] flag = {inst['flag']}")


if __name__ == "__main__":
    main()
