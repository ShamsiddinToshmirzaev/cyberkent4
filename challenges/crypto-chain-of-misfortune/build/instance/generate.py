#!/usr/bin/env python3
"""Generate one C16 instance, reproducible from --seed.

The signing service (Go) reads the full instance file (it IS the signer). Players
get only the public key, domain/chain parameters, and public params — never the
private scalar or the flag.
"""
import argparse
import hashlib
import hmac
import json
import os
import random

from cryptography.hazmat.primitives.asymmetric import ec

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

N_P256 = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def build_instance(seed, port=9160):
    rng = random.Random(f"C16|{seed}")
    d = rng.randrange(1, N_P256)
    key = ec.derive_private_key(d, ec.SECP256R1())
    pn = key.public_key().public_numbers()
    x, y = pn.x, pn.y
    addr = hashlib.sha256(x.to_bytes(32, "big") + y.to_bytes(32, "big")).digest()[-20:]
    contract = bytes(rng.getrandbits(8) for _ in range(20))

    # two distinct chain ids (main + test), from realistic-looking pools
    main_id = rng.choice([8899, 42161, 137, 10, 8453, 59144])
    test_id = rng.choice([11155111, 80001, 421614, 84532, 534351])

    seed_key = hashlib.sha256(f"C16-flag|{seed}".encode()).digest()
    flag = os.environ.get("FLAG") or ("CTF4{" + hmac.new(seed_key, b"backstage-zero", "sha256").hexdigest()[:24] + "}")

    inst = {
        "id": "C16-chain-of-misfortune",
        "seed": seed,
        "signer": {"d": format(d, "x"), "x": format(x, "x"), "y": format(y, "x"),
                   "address": addr.hex()},
        "domain": {"name": "NovaFest Tickets", "version": "1",
                   "verifying_contract": contract.hex()},   # same address on both chains (CREATE2)
        "chains": {"mainstage": {"chain_id": main_id, "name": "MainStage"},
                   "teststage": {"chain_id": test_id, "name": "TestStage"}},
        "params": {"free_budget": 3, "mint_threshold": 5, "credit_per_ticket": 1, "port": port},
        "flag": flag,
    }
    return inst


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--port", type=int, default=9160)
    ap.add_argument("--out", default=os.path.join(ROOT, "instance", "state", "instance.json"))
    ap.add_argument("--player-dir", default=os.path.join(ROOT, "player", "samples"))
    args = ap.parse_args()

    inst = build_instance(args.seed, args.port)
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    os.makedirs(args.player_dir, exist_ok=True)
    with open(args.out, "w") as f:
        json.dump(inst, f, indent=2)

    pub = {
        "id": inst["id"],
        "signer": {"x": inst["signer"]["x"], "y": inst["signer"]["y"],
                   "address": inst["signer"]["address"]},
        "domain": inst["domain"],
        "chains": inst["chains"],
        "curve": {"name": "P-256", "n": format(N_P256, "x")},
        "types": {
            "legacy_domain": "EIP712Domain(string name,string version,address verifyingContract)",
            "modern_domain": "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
            "ticket": "Ticket(uint256 ticketId,address holder,string action,uint256 tier)",
        },
        "params": inst["params"],
        "gateway_host": "127.0.0.1",
        "gateway_port": args.port,
    }
    with open(os.path.join(args.player_dir, "instance_public.json"), "w") as f:
        json.dump(pub, f, indent=2)

    print(f"[+] C16 instance seed={args.seed} main={inst['chains']['mainstage']['chain_id']} "
          f"test={inst['chains']['teststage']['chain_id']}")
    print(f"[+] flag = {inst['flag']}")


if __name__ == "__main__":
    main()
