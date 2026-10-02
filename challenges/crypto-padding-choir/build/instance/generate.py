#!/usr/bin/env python3
"""Generate one C02 instance — fully reproducible from --seed.

Everything an instance needs is derived from the seed (RSA primes included) so CI
can replay any of 30-100 instances deterministically. Secrets go into the author
instance file + the appliance private key; players only ever get the public key,
the sample "guest" ticket ciphertext, and public parameters.
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
import der    # noqa: E402
import pkcs   # noqa: E402

from cryptography.hazmat.primitives.asymmetric import rsa            # noqa: E402
from cryptography.hazmat.primitives import serialization             # noqa: E402


# ---- deterministic RSA keygen (seeded) --------------------------------------
def _is_probable_prime(n, rng, rounds=40):
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = rng.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def _gen_prime(bits, rng):
    while True:
        cand = rng.getrandbits(bits) | (1 << (bits - 1)) | 1
        if _is_probable_prime(cand, rng):
            return cand


def _gen_rsa(bits, rng, e=65537):
    half = bits // 2
    while True:
        p = _gen_prime(half, rng)
        q = _gen_prime(bits - half, rng)
        if p == q:
            continue
        n = p * q
        if n.bit_length() != bits:
            continue
        phi = (p - 1) * (q - 1)
        if phi % e == 0:
            continue
        return n, e, pow(e, -1, phi), p, q


def _pem(n, e, d, p, q):
    if p < q:
        p, q = q, p
    pub = rsa.RSAPublicNumbers(e, n)
    priv = rsa.RSAPrivateNumbers(
        p, q, d, rsa.rsa_crt_dmp1(d, p), rsa.rsa_crt_dmq1(d, q),
        rsa.rsa_crt_iqmp(p, q), pub).private_key()
    return (priv.private_bytes(serialization.Encoding.PEM,
                               serialization.PrivateFormat.TraditionalOpenSSL,
                               serialization.NoEncryption()),
            priv.public_key().public_bytes(serialization.Encoding.PEM,
                                            serialization.PublicFormat.SubjectPublicKeyInfo))


# jitter_ms_mu / jitter_ms_sigma are the (mu, sigma) of a log-normal delay in ms
# added by the gateway to EVERY response (secret-independent network model). The
# secret-dependent signal is the appliance's stable, work-proportional gap; the
# ratio of the two sets how many samples per oracle decision a solver needs.
PROFILES = {
    # dev/CI: large clean gap so the reference solver converges in a few samples
    # per decision and CI is fast; effectively unthrottled.
    "dev":  dict(bits=1024, der_work_factor=8_000, worker_count=4,
                 cross_traffic_rate_hz=0.0, jitter_ms_mu=-2.12, jitter_ms_sigma=0.5,
                 rate_tokens=100_000, rate_refill_hz=100_000, query_budget=5_000_000),
    # prod: real deployment — 2048-bit (not casually factorable), subtler gap,
    # heavier jitter + cross-tenant queue contention => more samples/decision.
    # (k=256 => ~4x work per iteration vs dev's k=128, so a smaller factor.)
    "prod": dict(bits=2048, der_work_factor=2_500, worker_count=6,
                 cross_traffic_rate_hz=140.0, jitter_ms_mu=-0.69, jitter_ms_sigma=0.6,
                 rate_tokens=300, rate_refill_hz=150, query_budget=5_000_000),
}


def build_instance(seed, profile="dev", bits=0, gateway_port=9020, appliance_port=9021):
    """Build one instance (dict + PEMs) in memory, deterministically from seed."""
    prof = dict(PROFILES[profile])
    if bits:
        prof["bits"] = bits
    rng = random.Random(f"C02|{seed}|{profile}|{prof['bits']}")

    n, e, d, p, q = _gen_rsa(prof["bits"], rng)
    k = (n.bit_length() + 7) // 8
    priv_pem, pub_pem = _pem(n, e, d, p, q)

    issuer_tag = bytes(rng.getrandbits(8) for _ in range(16))
    seed_key = hashlib.sha256(f"C02-flag|{seed}|{profile}".encode()).digest()
    flag = os.environ.get("FLAG") or ("CTF4{" + hmac.new(seed_key, b"phantom-performance", "sha256").hexdigest()[:24] + "}")
    seat = "R" + str(rng.randint(1, 40)) + "-" + str(rng.randint(1, 30))

    def seeded_bytes(m):
        return bytes(rng.randint(0, 255) for _ in range(m))
    sample_payload = der.build_session(1, issuer_tag, "guest", seat)
    em = pkcs.pkcs1v15_pad_type2(sample_payload, k, rng=seeded_bytes)
    assert len(em) == k and pkcs.pkcs1v15_unpad_type2(em) == sample_payload
    ciphertext = pkcs.i2osp(pkcs.rsa_pub(pkcs.os2ip(em), e, n), k)

    instance = {
        "id": "C02-padding-choir",
        "profile": profile,
        "seed": seed,
        "rsa": {"bits": prof["bits"], "e": e, "k": k,
                "n": hex(n), "d": hex(d), "p": hex(p), "q": hex(q)},
        "appliance_key_pem": os.path.join("instance", "state", "appliance_key.pem"),
        "issuer_tag": issuer_tag.hex(),
        "flag": flag,
        "allowlist_roles": ["guest", "subscriber"],
        "archive_role": "archivist",
        "params": {k2: prof[k2] for k2 in (
            "der_work_factor", "worker_count", "cross_traffic_rate_hz",
            "jitter_ms_mu", "jitter_ms_sigma", "rate_tokens", "rate_refill_hz",
            "query_budget")} | {"coarse_ts_ms": 1},
        "net": {"gateway_host": "127.0.0.1", "gateway_port": gateway_port,
                "appliance_host": "127.0.0.1", "appliance_port": appliance_port},
        "sample": {"role": "guest", "seat": seat,
                   "plaintext_em_hex": em.hex(), "ciphertext_hex": ciphertext.hex()},
    }
    return {"instance": instance, "priv_pem": priv_pem, "pub_pem": pub_pem}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--profile", choices=list(PROFILES), default="dev")
    ap.add_argument("--bits", type=int, default=0, help="override profile key size")
    ap.add_argument("--gateway-port", type=int, default=9020)
    ap.add_argument("--appliance-port", type=int, default=9021)
    ap.add_argument("--out", default=os.path.join(ROOT, "instance", "state", "instance.json"))
    ap.add_argument("--pem", default=os.path.join(ROOT, "instance", "state", "appliance_key.pem"))
    ap.add_argument("--player-dir", default=os.path.join(ROOT, "player", "samples"))
    ap.add_argument("--gateway-out", default=None,
                    help="path for the reduced gateway config (default: next to --out)")
    args = ap.parse_args()

    res = build_instance(args.seed, args.profile, args.bits, args.gateway_port, args.appliance_port)
    instance, priv_pem, pub_pem = res["instance"], res["priv_pem"], res["pub_pem"]
    instance["appliance_key_pem"] = os.path.relpath(args.pem, ROOT)
    n, e, k = int(instance["rsa"]["n"], 16), instance["rsa"]["e"], instance["rsa"]["k"]

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    os.makedirs(args.player_dir, exist_ok=True)
    with open(args.out, "w") as f:
        json.dump(instance, f, indent=2)
    with open(args.pem, "wb") as f:
        f.write(priv_pem)
    os.chmod(args.pem, 0o600)

    with open(os.path.join(args.player_dir, "public_key.pem"), "wb") as f:
        f.write(pub_pem)
    with open(os.path.join(args.player_dir, "sample_ticket.hex"), "w") as f:
        f.write(instance["sample"]["ciphertext_hex"] + "\n")
    with open(os.path.join(args.player_dir, "instance_public.json"), "w") as f:
        json.dump({"n": hex(n), "e": e, "k": k,
                   "gateway_host": instance["net"]["gateway_host"],
                   "gateway_port": instance["net"]["gateway_port"],
                   "query_budget": instance["params"]["query_budget"]}, f, indent=2)

    # reduced config for the gateway process: it must NOT hold the RSA private key
    # or the issuerTag secret (those live only in the appliance). It legitimately
    # holds the flag, since it is the service that hands it out on a win.
    gw = {"rsa": {"k": k, "e": e, "n": hex(n)}, "flag": instance["flag"],
          "archive_role": instance["archive_role"], "params": instance["params"],
          "net": instance["net"]}
    gw_out = args.gateway_out or os.path.join(os.path.dirname(args.out), "gateway.json")
    os.makedirs(os.path.dirname(gw_out), exist_ok=True)
    with open(gw_out, "w") as f:
        json.dump(gw, f, indent=2)

    print(f"[+] instance seed={args.seed} profile={args.profile} "
          f"bits={instance['rsa']['bits']} k={k}")
    print(f"[+] flag = {instance['flag']}")
    print(f"[+] wrote {os.path.relpath(args.out, ROOT)}, appliance key, and player/samples/*")


if __name__ == "__main__":
    main()
