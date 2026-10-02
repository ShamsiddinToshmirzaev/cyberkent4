#!/usr/bin/env python3
"""Generate one C04 "Fever Dream" instance, reproducible from --seed.

Secret: the ECDSA private key d. Per-instance nuisance parameters: the thermal/DVFS
constants of the power model (so the player must characterise each device live) and the
forbidden command. All of that plus the flag lives in the server instance file; the player
only receives the public key and the endpoint.
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
import ecc  # noqa: E402

FORBIDDEN_POOL = ["DEORBIT-NOW", "WIPE-KEYSTORE", "DISABLE-SAFEHOLD",
                  "VENT-PROPELLANT", "OVERRIDE-WATCHDOG"]


def build_instance(seed, port=9040):
    rng = random.Random(f"C04|{seed}")
    d = rng.randrange(1, ecc.N)
    Q = ecc.pubkey(d)
    thermal = {
        "W0": rng.uniform(8e5, 1.2e6),      # baseline energy per signature (lz=0)
        "WSTEP": rng.uniform(13000, 19000),  # energy saved per leading-zero nonce bit
        "SIGMA": rng.uniform(0.015, 0.028),  # multiplicative (log-normal) measurement jitter
        "AMBIENT": 40.0,
        "KNEE": rng.uniform(43, 47),         # temperature at which DVFS starts throttling
        "SLOPE": rng.uniform(0.03, 0.07),    # throttle strength above the knee
        "HEAT": rng.uniform(6, 12),          # temperature added per signature
        "DECAY": rng.uniform(0.45, 0.6),     # cooling factor per idle tick
    }
    forbidden = FORBIDDEN_POOL[rng.randrange(len(FORBIDDEN_POOL))]
    flag_key = hashlib.sha256(f"C04-flag|{seed}".encode()).digest()
    flag = os.environ.get("FLAG") or ("CTF4{" + hmac.new(flag_key, forbidden.encode(), "sha256").hexdigest()[:24] + "}")
    return {
        "id": "C04-fever-dream",
        "seed": seed,
        "d": format(d, "x"),                 # secret key
        "Q": {"x": format(Q[0], "x"), "y": format(Q[1], "x")},
        "thermal": thermal,                  # secret nuisance params (player characterises)
        "forbidden_command": forbidden,
        "flag": flag,
        "net": {"gateway_host": "127.0.0.1", "gateway_port": port},
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--port", type=int, default=9040)
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
                   "note": "GET /info for the curve, the public key, and the forbidden command."},
                  f, indent=2)
    print(f"[+] C04 instance seed={args.seed} forbidden={inst['forbidden_command']!r}")
    print(f"[+] flag = {inst['flag']}")


if __name__ == "__main__":
    main()
