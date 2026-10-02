#!/usr/bin/env python3
"""Generate one C15 instance, reproducible from --seed.

The Rust server derives the honest committee keypairs from `seed` and immediately
discards the secrets (only public keys live in the registry). Python only writes
the parameters + flag; it needs no BLS library.
"""
import argparse
import hashlib
import hmac
import json
import os
import random

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

SECTION_POOL = ["strings", "brass", "woodwinds", "percussion", "choir",
                "keys", "harps", "timpani"]
TARGET = "THE ROGUE SYMPHONY"


def split_weight(total, parts, lo, rng):
    """Random split of `total` into `parts` integers each >= lo."""
    while True:
        cuts = sorted(rng.randint(0, total - parts * lo) for _ in range(parts - 1))
        vals, prev = [], 0
        for c in cuts + [total - parts * lo]:
            vals.append(c - prev + lo)
            prev = c
        if all(v >= lo for v in vals) and sum(vals) == total:
            return vals


def build_instance(seed, gateway_port=9150):
    rng = random.Random(f"C15|{seed}")
    threshold = 51
    legacy_honest = 49            # sum of section base weights; threshold-2 => gap 2
    n_sections = 4
    names = rng.sample(SECTION_POOL, n_sections)
    weights = split_weight(legacy_honest, n_sections, 5, rng)  # each >= 5 >= gap
    sections = [{"name": n, "base_weight": w} for n, w in zip(names, weights)]

    def dst(kind):
        salt = "".join(rng.choice("0123456789abcdef") for _ in range(16))
        return f"C15-{kind}-{salt}_XMD:SHA-256_SSWU_RO_".encode().hex()

    seed_u64 = int(hashlib.sha256(f"C15-keys|{seed}".encode()).hexdigest()[:16], 16)
    flag_key = hashlib.sha256(f"C15-flag|{seed}".encode()).digest()
    flag = os.environ.get("FLAG") or ("CTF4{" + hmac.new(flag_key, b"rogue-symphony", "sha256").hexdigest()[:24] + "}")

    return {
        "id": "C15-bls-orchestra",
        "seed_input": seed,
        "seed": seed_u64,
        "threshold": threshold,
        "sections": sections,
        "founder_sections": list(range(n_sections)),   # one founder per section
        "provisional_section": "provisional",
        "target_title": TARGET,
        "app_dst": dst("APP"),
        "pop_dst": dst("POP"),
        "flag": flag,
        "net": {"gateway_host": "127.0.0.1", "gateway_port": gateway_port},
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--port", type=int, default=9150)
    ap.add_argument("--out", default=os.path.join(ROOT, "instance", "state", "instance.json"))
    ap.add_argument("--player-dir", default=os.path.join(ROOT, "player", "samples"))
    args = ap.parse_args()

    inst = build_instance(args.seed, args.port)
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    os.makedirs(args.player_dir, exist_ok=True)
    with open(args.out, "w") as f:
        json.dump(inst, f, indent=2)
    # players get only where to connect; everything public is served at GET /info
    with open(os.path.join(args.player_dir, "instance_public.json"), "w") as f:
        json.dump({"id": inst["id"], "gateway_host": inst["net"]["gateway_host"],
                   "gateway_port": inst["net"]["gateway_port"],
                   "note": "GET /info for the committee registry, sections, threshold, DSTs and target."},
                  f, indent=2)
    print(f"[+] C15 instance seed={args.seed} threshold={inst['threshold']} "
          f"sections={[s['name']+':'+str(s['base_weight']) for s in inst['sections']]}")
    print(f"[+] flag = {inst['flag']}")


if __name__ == "__main__":
    main()
