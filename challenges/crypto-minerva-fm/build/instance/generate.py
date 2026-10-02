#!/usr/bin/env python3
"""Generate one C03 instance, reproducible from --seed.

The C signer reads the full instance (it holds d). The gateway reads a reduced
config (public key + flag, no d). Players get only public parameters.
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

TARGET = '{"station":"13.37","role":"ghost-dj"}'
FORBIDDEN = ["ghost-dj", '"13.37"']

# work_factor W and signer_offset shape the leak: signing time ~ W*(bitlen(k)-offset).
# jitter is the gateway's per-response network noise (microseconds). dev keeps the
# per-bit step >> jitter so the reference solver ranks the tail cleanly; prod makes
# the signal subtle so a human must collect far more and select carefully.
PROFILES = {
    "dev":  dict(work_factor=120_000, signer_offset=240, jitter_us_base=0, jitter_us_sigma=8,
                 rate_tokens=40_000, rate_refill_hz=40_000, query_budget=2_000_000, signer_conns=6),
    "prod": dict(work_factor=30_000, signer_offset=236, jitter_us_base=200, jitter_us_sigma=120,
                 rate_tokens=3_000, rate_refill_hz=1_200, query_budget=3_000_000, signer_conns=8),
}


def build_instance(seed, profile="dev", gateway_port=9030, signer_port=9031):
    prof = dict(PROFILES[profile])
    rng = random.Random(f"C03|{seed}|{profile}")
    d = rng.randrange(1, p256.N)
    x, y = p256.pubkey(d)
    seed_key = hashlib.sha256(f"C03-flag|{seed}|{profile}".encode()).digest()
    flag = os.environ.get("FLAG") or ("CTF4{" + hmac.new(seed_key, b"ghost-dj-midnight", "sha256").hexdigest()[:24] + "}")
    inst = {
        "id": "C03-minerva-fm", "seed": seed, "profile": profile,
        "signer": {"d": format(d, "x")},
        "pubkey": {"x": format(x, "x"), "y": format(y, "x")},
        "curve": {"name": "P-256", "n": format(p256.N, "x")},
        "target_manifest": TARGET,
        "forbidden": FORBIDDEN,
        "flag": flag,
        "params": prof,
        "net": {"gateway_host": "127.0.0.1", "gateway_port": gateway_port,
                "signer_host": "127.0.0.1", "signer_port": signer_port},
    }
    return inst


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--profile", choices=list(PROFILES), default="dev")
    ap.add_argument("--gateway-port", type=int, default=9030)
    ap.add_argument("--signer-port", type=int, default=9031)
    ap.add_argument("--out", default=os.path.join(ROOT, "instance", "state", "instance.json"))
    ap.add_argument("--gateway-out", default=None)
    ap.add_argument("--player-dir", default=os.path.join(ROOT, "player", "samples"))
    args = ap.parse_args()

    inst = build_instance(args.seed, args.profile, args.gateway_port, args.signer_port)
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    os.makedirs(args.player_dir, exist_ok=True)
    with open(args.out, "w") as f:
        json.dump(inst, f, indent=2)

    gw = {"pubkey": inst["pubkey"], "target_manifest": inst["target_manifest"],
          "forbidden": inst["forbidden"], "flag": inst["flag"],
          "params": inst["params"], "net": inst["net"]}
    gw_out = args.gateway_out or os.path.join(os.path.dirname(args.out), "gateway.json")
    with open(gw_out, "w") as f:
        json.dump(gw, f, indent=2)

    pub = {"id": inst["id"], "pubkey": inst["pubkey"], "curve": inst["curve"],
           "target_manifest": inst["target_manifest"],
           "manifest_hint": 'Signable track manifests look like {"station":"88.5","title":"...","mix":"..."}. '
                            'The signer refuses anything containing the privileged tokens.',
           "gateway_host": inst["net"]["gateway_host"], "gateway_port": inst["net"]["gateway_port"],
           "query_budget": inst["params"]["query_budget"]}
    with open(os.path.join(args.player_dir, "instance_public.json"), "w") as f:
        json.dump(pub, f, indent=2)

    print(f"[+] C03 instance seed={args.seed} profile={args.profile}")
    print(f"[+] flag = {inst['flag']}")


if __name__ == "__main__":
    main()
