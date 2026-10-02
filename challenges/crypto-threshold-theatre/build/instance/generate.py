#!/usr/bin/env python3
"""Generate one C08 instance, reproducible from --seed."""
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
import p256       # noqa: E402
import paillier   # noqa: E402


def build_instance(seed, port=9080):
    rng = random.Random(f"C08|{seed}")
    pk, sk = paillier.keygen(1024, rng)
    d1 = rng.randrange(1, p256.N)      # tablet (player) share
    d2 = rng.randrange(1, p256.N)      # server share (secret)
    d = (d1 + d2) % p256.N
    Y = p256.pubkey(d)
    flag_key = hashlib.sha256(f"C08-flag|{seed}".encode()).digest()
    flag = os.environ.get("FLAG") or ("CTF4{" + hmac.new(flag_key, b"the-last-nonce", "sha256").hexdigest()[:24] + "}")
    return {
        "id": "C08-threshold-theatre",
        "seed": seed,
        "paillier": {"n": format(sk["n"], "x"), "lam": format(sk["lam"], "x"), "mu": format(sk["mu"], "x")},
        "d1": format(d1, "x"),         # -> shipped to the player (their tablet share)
        "d2": format(d2, "x"),         # secret server share
        "Y": {"x": format(Y[0], "x"), "y": format(Y[1], "x")},
        "forbidden_movie": "THE LAST NONCE",
        "flag": flag,
        "net": {"gateway_host": "127.0.0.1", "gateway_port": port},
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--port", type=int, default=9080)
    ap.add_argument("--out", default=os.path.join(ROOT, "instance", "state", "instance.json"))
    ap.add_argument("--player-dir", default=os.path.join(ROOT, "player", "samples"))
    args = ap.parse_args()

    inst = build_instance(args.seed, args.port)
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    os.makedirs(args.player_dir, exist_ok=True)
    # server keeps sk + d2 + Y; the player's share d1 is NOT in the server file it needs,
    # but we keep it in the instance for tests. The gateway only reads sk/d2/Y/flag.
    with open(args.out, "w") as f:
        json.dump(inst, f, indent=2)
    with open(os.path.join(args.player_dir, "my_share.json"), "w") as f:
        json.dump({"d1": inst["d1"], "note": "your tablet's ECDSA key share d1"}, f, indent=2)
    with open(os.path.join(args.player_dir, "instance_public.json"), "w") as f:
        json.dump({"id": inst["id"], "gateway_host": inst["net"]["gateway_host"],
                   "gateway_port": inst["net"]["gateway_port"],
                   "note": "GET /info for the Paillier public key, the group public key, and the target."},
                  f, indent=2)
    print(f"[+] C08 instance seed={args.seed} paillier_bits={inst['paillier']['n'].__len__()*4} "
          f"forbidden={inst['forbidden_movie']!r}")
    print(f"[+] flag = {inst['flag']}")


if __name__ == "__main__":
    main()
