#!/usr/bin/env python3
"""Generate one C07 instance, reproducible from --seed."""
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
import frost  # noqa: E402


def build_instance(seed, port=9070):
    rng = random.Random(f"C07|{seed}")
    x = rng.randrange(1, frost.Q)
    Y = frost.G_mul(x)
    shares = frost.shamir_share(x, 3, 5, rng)
    flag_key = hashlib.sha256(f"C07-flag|{seed}".encode()).digest()
    flag = os.environ.get("FLAG") or ("CTF4{" + hmac.new(flag_key, b"open-ice-vault", "sha256").hexdigest()[:24] + "}")
    return {
        "id": "C07-frostbite-coordinator",
        "seed": seed,
        "threshold": 3,
        "shares": {str(i): format(s, "x") for i, s in shares.items()},
        "Y": {"x": format(Y[0], "x"), "y": format(Y[1], "x")},
        "forbidden_message": "OPEN_ICE_VAULT",
        "flag": flag,
        "net": {"gateway_host": "127.0.0.1", "gateway_port": port},
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--port", type=int, default=9070)
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
                   "note": "GET /info for the group public key, signer set, threshold and protocol."},
                  f, indent=2)
    print(f"[+] C07 instance seed={args.seed} threshold={inst['threshold']} signers={list(inst['shares'])}")
    print(f"[+] flag = {inst['flag']}")


if __name__ == "__main__":
    main()
