#!/usr/bin/env python3
"""Generate one C12 "Dilithium Drift" instance, reproducible from --seed.

Everything secret (the ML-DSA master seed, and therefore s1/s2/signing key) plus the
per-instance set of QA-monitored nonce lanes and the flag live in the server instance
file. The player only ever sees the public key (rho, t) via /info and the QA telemetry
that the /sign endpoint attaches.
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
import mldsa  # noqa: E402

N_LANES = 16  # how many nonce coordinates the (buggy) QA telemetry reports per component

FORBIDDEN_POOL = [
    "UNLOCK-BOOTLOADER",
    "DISABLE-SECUREBOOT",
    "GRANT-ROOT-DEBUG",
    "FLASH-GOLDEN-KEY",
    "OVERRIDE-ROLLBACK",
]


def build_instance(seed, port=9120):
    rng = random.Random(f"C12|{seed}")
    mseed = hashlib.sha256(f"C12-mseed|{seed}".encode()).digest()
    pk = mldsa.keygen(mseed)
    lanes = sorted(rng.sample(range(mldsa.N), N_LANES))
    forbidden = FORBIDDEN_POOL[rng.randrange(len(FORBIDDEN_POOL))]
    flag_key = hashlib.sha256(f"C12-flag|{seed}".encode()).digest()
    flag = os.environ.get("FLAG") or ("CTF4{" + hmac.new(flag_key, forbidden.encode(), "sha256").hexdigest()[:24] + "}")
    return {
        "id": "C12-dilithium-drift",
        "seed": seed,
        "mseed": mseed.hex(),                 # secret: derives rho/s1/s2/signing key
        "lanes": lanes,                       # secret-ish: which nonce lanes QA telemetry leaks
        "forbidden_firmware": forbidden,      # the manifest the signer refuses
        "flag": flag,
        "net": {"gateway_host": "127.0.0.1", "gateway_port": port},
        # public key materialised for convenience (also recomputable from mseed):
        "rho": pk["rho"].hex(),
        "t": pk["t"],
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--port", type=int, default=9120)
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
                   "note": "GET /info for the public key and the forbidden firmware id."}, f, indent=2)
    print(f"[+] C12 instance seed={args.seed} lanes={len(inst['lanes'])} "
          f"forbidden={inst['forbidden_firmware']!r}")
    print(f"[+] flag = {inst['flag']}")


if __name__ == "__main__":
    main()
