#!/usr/bin/env python3
"""Generate one C10 instance, reproducible from --seed.

The player is the authenticator, so they receive their own credential's PRIVATE key
(in player/samples/my_credential.json) — the challenge is RP-binding confusion, not
key recovery. The server stores only public keys.
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
import p256  # noqa: E402

RP_POOL = ["neonfest", "starlight", "moonwake", "auroramusic", "novafest"]
PRIV_POOL = ["staff", "backstage", "crew", "production"]


def build_instance(seed, port=9100):
    rng = random.Random(f"C10|{seed}")
    rp_id = rng.choice(RP_POOL) + ".example"
    privileged = rng.choice(PRIV_POOL)
    d = rng.randrange(1, p256.N)
    x, y = p256.pubkey(d)
    cred_id = "cred-" + "".join(rng.choice("0123456789abcdef") for _ in range(16))
    flag_key = hashlib.sha256(f"C10-flag|{seed}".encode()).digest()
    flag = os.environ.get("FLAG") or ("CTF4{" + hmac.new(flag_key, b"stage-manager", "sha256").hexdigest()[:24] + "}")
    inst = {
        "id": "C10-passkey-doppelganger",
        "seed": seed,
        "rp_id": rp_id,
        "privileged_profile": privileged,
        "credentials": [{"cred_id": cred_id, "x": format(x, "x"), "y": format(y, "x"),
                         "rp_id": rp_id, "account": f"guest@{rp_id}", "profile": "guest"}],
        "flag": flag,
        "_player_credential": {"cred_id": cred_id, "rp_id": rp_id, "account": f"guest@{rp_id}",
                               "d": format(d, "x"), "x": format(x, "x"), "y": format(y, "x")},
        "net": {"gateway_host": "127.0.0.1", "gateway_port": port},
    }
    return inst


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--port", type=int, default=9100)
    ap.add_argument("--out", default=os.path.join(ROOT, "instance", "state", "instance.json"))
    ap.add_argument("--player-dir", default=os.path.join(ROOT, "player", "samples"))
    args = ap.parse_args()

    inst = build_instance(args.seed, args.port)
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    os.makedirs(args.player_dir, exist_ok=True)
    # server instance keeps everything except the player's private key
    server_inst = {k: v for k, v in inst.items() if k != "_player_credential"}
    with open(args.out, "w") as f:
        json.dump(server_inst, f, indent=2)

    # the player's own authenticator (their private key) + connection info
    with open(os.path.join(args.player_dir, "my_credential.json"), "w") as f:
        json.dump(inst["_player_credential"], f, indent=2)
    with open(os.path.join(args.player_dir, "instance_public.json"), "w") as f:
        json.dump({"id": inst["id"], "gateway_host": inst["net"]["gateway_host"],
                   "gateway_port": inst["net"]["gateway_port"],
                   "note": "GET /info for the rpId, your registered credential, and the privileged profile."},
                  f, indent=2)
    print(f"[+] C10 instance seed={args.seed} rp_id={inst['rp_id']} privileged={inst['privileged_profile']!r}")
    print(f"[+] flag = {inst['flag']}")


if __name__ == "__main__":
    main()
