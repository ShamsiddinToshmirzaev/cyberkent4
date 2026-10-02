#!/usr/bin/env python3
"""Generate one C18 "RSA Museum" instance, reproducible from --seed.

Secret: the RSA private key (p, q, d). Per-instance nuisance parameters: the glitch window
(g0, gmax) at which the signing HSM starts producing faults and then halts, so the player
must find the exploitable voltage band live. Key, window, forbidden artifact, and flag live
in the server instance file; the player only gets the public modulus and endpoint.
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
import rsa  # noqa: E402

FORBIDDEN_POOL = ["CROWN-JEWEL-LOAN", "DEACCESSION-MONA", "VAULT-MASTER-OVERRIDE",
                  "FORGE-PROVENANCE", "RELEASE-METEORITE"]


def build_instance(seed, port=9180):
    rng = random.Random(f"C18|{seed}")
    key = rsa.keygen(2048, rng)
    g0 = rng.randint(20, 35)
    gmax = rng.randint(70, 90)
    forbidden = FORBIDDEN_POOL[rng.randrange(len(FORBIDDEN_POOL))]
    flag_key = hashlib.sha256(f"C18-flag|{seed}".encode()).digest()
    flag = os.environ.get("FLAG") or ("CTF4{" + hmac.new(flag_key, forbidden.encode(), "sha256").hexdigest()[:24] + "}")
    return {
        "id": "C18-rsa-museum",
        "seed": seed,
        "rsa": {"n": format(key["n"], "x"), "e": key["e"], "d": format(key["d"], "x"),
                "p": format(key["p"], "x"), "q": format(key["q"], "x"),
                "dp": format(key["dp"], "x"), "dq": format(key["dq"], "x"),
                "qinv": format(key["qinv"], "x"), "bits": key["bits"], "embits": key["embits"]},
        "glitch": {"g0": g0, "gmax": gmax},   # secret fault window
        "forbidden_artifact": forbidden,
        "flag": flag,
        "net": {"gateway_host": "127.0.0.1", "gateway_port": port},
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--port", type=int, default=9180)
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
                   "note": "GET /info for the public modulus, the PSS scheme, and the forbidden artifact."},
                  f, indent=2)
    print(f"[+] C18 instance seed={args.seed} glitch_window=({inst['glitch']['g0']},{inst['glitch']['gmax']}) "
          f"forbidden={inst['forbidden_artifact']!r}")
    print(f"[+] flag = {inst['flag']}")


if __name__ == "__main__":
    main()
