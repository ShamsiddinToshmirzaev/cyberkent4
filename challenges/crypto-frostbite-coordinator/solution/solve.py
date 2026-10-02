#!/usr/bin/env python3
"""C07 full reference solver — recover the treasury key and open the ice vault.

For each signer i in a valid set S, the coordinator (us) obtains two partial
responses on the SAME cached nonce (round2 never consumes it) under two different
commitment lists B (the binding factor ignores B, so r_i is unchanged while the
challenge c changes). Then lambda_i*x_i = (z1 - z2)/(c1 - c2). Summed over S that is
the group secret, which forges the OPEN_ICE_VAULT signature.
"""
import json
import os
import random
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, "src", "lib"))
sys.path.insert(0, os.path.join(ROOT, "player", "client"))
import frost                    # noqa: E402
from client import Client        # noqa: E402

Q = frost.Q


def ptj(P):
    return {"x": format(P[0], "x"), "y": format(P[1], "x")}


def solve_once(host, port, verbose=True):
    def log(*a):
        if verbose:
            print(*a, flush=True)

    c = Client(host, port)
    info = c.info()
    Y = (int(info["group_pubkey"]["x"], 16), int(info["group_pubkey"]["y"], 16))
    t = info["threshold"]
    S = sorted(info["signers"])[:t]                 # a valid signing set
    forbidden = info["forbidden_message"]
    rng = random.Random(1234)
    msg = "withdraw:ledger-sync"
    log(f"[*] set S={S}, threshold {t}, forbidden={forbidden!r}")

    def rand_B(target, D, E):
        # arbitrary on-curve commitments; only their POINT VALUES matter (they feed c)
        return [{"j": target, "D": ptj(D), "E": ptj(E)},
                {"j": 99, "D": ptj(frost.G_mul(rng.randrange(1, Q))),
                 "E": ptj(frost.G_mul(rng.randrange(1, Q)))}]

    x = 0
    for i in S:
        sess = f"attack-{i}"
        r1 = c.round1(sess, i)                       # commit a nonce for signer i
        D = (int(r1["D"]["x"], 16), int(r1["D"]["y"], 16))
        E = (int(r1["E"]["x"], 16), int(r1["E"]["y"], 16))
        # two partial responses on the SAME nonce (round2 does not consume it),
        # with two different B (=> different challenge, same r_i)
        p1 = c.round2(sess, i, S, msg, rand_B(i, D, E))
        p2 = c.round2(sess, i, S, msg, rand_B(i, frost.G_mul(rng.randrange(1, Q)),
                                              frost.G_mul(rng.randrange(1, Q))))
        z1, c1 = int(p1["z"], 16), int(p1["c"], 16)
        z2, c2 = int(p2["z"], 16), int(p2["c"], 16)
        w_i = (z1 - z2) * pow(c1 - c2, -1, Q) % Q    # = lambda_i * x_i
        x = (x + w_i) % Q
        log(f"    signer {i}: recovered lambda_i*x_i")
    if frost.G_mul(x) != Y:
        raise RuntimeError("recovered secret does not match the group public key")
    log(f"[+] recovered group secret (x*G == Y)")

    R, z = frost.schnorr_sign(x, Y, forbidden.encode(), rng.randrange(1, Q))
    res = c.open_vault(ptj(R), format(z, "x"))
    log(f"[*] open -> {res.get('status')}")
    if "flag" in res:
        log(f"\n[+] FLAG: {res['flag']}")
        return res["flag"]
    raise RuntimeError(f"vault did not open: {res}")


def main():
    info = json.load(open(os.path.join(ROOT, "player", "samples", "instance_public.json")))
    try:
        solve_once(info["gateway_host"], info["gateway_port"], verbose=True)
        return 0
    except Exception as ex:
        print(f"[-] solve failed: {ex}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
