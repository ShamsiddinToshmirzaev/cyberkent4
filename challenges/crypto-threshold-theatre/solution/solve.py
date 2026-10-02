#!/usr/bin/env python3
"""C08 full reference solver — recover the server share via the abort oracle and forge
the purchase authorization, using only player-visible data (+ the tablet's own d1).

The online range check aborts iff (d2 - t) mod N underflows, i.e. iff t > d2. Binary
search that oracle to recover d2, add the tablet share d1 to get the full ECDSA key,
then forge the signature over the forbidden movie.
"""
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, "src", "lib"))
sys.path.insert(0, os.path.join(ROOT, "player", "client"))
import p256       # noqa: E402
import paillier   # noqa: E402
from client import Client        # noqa: E402


def solve_once(host, port, verbose=True):
    def log(*a):
        if verbose:
            print(*a, flush=True)

    my = json.load(open(os.path.join(ROOT, "player", "samples", "my_share.json")))
    d1 = int(my["d1"], 16)

    c = Client(host, port)
    info = c.info()
    pk = {"n": int(info["paillier_n"], 16)}
    Y = (int(info["group_pubkey"]["x"], 16), int(info["group_pubkey"]["y"], 16))
    forbidden = info["forbidden_movie"]
    n = p256.N

    def aborts(t):
        # submit Enc(t); abort  <=>  t > d2
        return c.sign_round(paillier.encrypt(pk, t).__format__("x"))["status"] == "abort"

    log("[*] binary-searching the abort oracle for the server share d2 ...")
    lo, hi, q = 0, n, 0
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if aborts(mid):          # mid > d2
            hi = mid - 1
        else:                    # mid <= d2
            lo = mid
        q += 1
    d2 = lo
    log(f"[*] recovered d2 in {q} oracle queries")

    d = (d1 + d2) % n
    if p256.pubkey(d) != Y:
        raise RuntimeError("d1 + d2 does not match the group public key")
    log("[+] full signing key recovered (d1 + d2)*G == Y")

    z = int.from_bytes(hashlib.sha256(forbidden.encode()).digest(), "big") % n
    k = 1 + (int.from_bytes(os.urandom(32), "big") % (n - 1))
    r, s = p256.sign(d, z, k)
    res = c.authorize(forbidden, format(r, "x"), format(s, "x"))
    log(f"[*] authorize -> {res.get('status')}")
    if "flag" in res:
        log(f"\n[+] FLAG: {res['flag']}")
        return res["flag"]
    raise RuntimeError(f"authorization denied: {res}")


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
