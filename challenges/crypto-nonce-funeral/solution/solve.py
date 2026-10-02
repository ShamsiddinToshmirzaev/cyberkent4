#!/usr/bin/env python3
"""C06 full reference solver — recovers the label's key from post-reboot truncated
nonces and forges the unreleased album, using only player-visible data.

  1. read /info -> the reboot window + cooldown, and the unreleasable target.
  2. for each reboot: the first `window` signatures use truncated (short) nonces;
     collect them, then spend the cooldown to earn another reboot.
  3. the short nonces are an HNP instance (reuses C03's lattice) -> recover d.
  4. forge an ECDSA signature over the target album and POST /release -> flag.
"""
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, "src", "lib"))
sys.path.insert(0, os.path.join(ROOT, "player", "client"))
sys.path.insert(0, HERE)
import p256                       # noqa: E402
from client import Client         # noqa: E402
from hnp import recover_d         # noqa: E402

# (m, T): bias m*T must exceed 256 with margin; loosen T if the truncation is milder
ATTEMPTS = [(20, 16), (28, 12), (34, 10), (44, 8)]


def z_of(track):
    return int.from_bytes(hashlib.sha256(f"release-v1|track:{track}".encode()).digest(), "big") % p256.N


def solve_once(host, port, want=36, verbose=True):
    def log(*a):
        if verbose:
            print(*a, flush=True)

    c = Client(host, port)
    info = c.info()
    target = info["target_track"]
    window = info["maintenance"]["reboot_window"]
    cooldown = info["maintenance"]["reboot_cooldown"]
    pub = (int(info["pubkey"]["x"], 16), int(info["pubkey"]["y"], 16))
    log(f"[*] reboot window={window} cooldown={cooldown}; target={target!r}")

    shorts = []
    cycle = 0
    while len(shorts) < want:
        m = c.maintenance()
        if m.get("status") != "rebooted":
            # not enough signs since last reboot yet; burn some and retry
            for i in range(cooldown):
                c.sign(f"filler-{cycle}-{i}")
            continue
        # the first `window` signatures after a reboot are the short-nonce ones
        for i in range(window):
            tr = f"warmup-{cycle}-{i}"
            resp = c.sign(tr)
            shorts.append((int(resp["r"], 16), int(resp["s"], 16), z_of(tr)))
        # spend the rest of the cooldown to earn the next reboot
        for i in range(max(0, cooldown - window)):
            c.sign(f"filler-{cycle}-{i}")
        cycle += 1
    log(f"[*] collected {len(shorts)} post-reboot signatures over {cycle} reboots")

    d = None
    for (m, T) in ATTEMPTS:
        if m > len(shorts):
            continue
        bound = 1 << (256 - T)
        log(f"[*] HNP attempt m={m} T={T} (dim {m+2}) ...")
        d = recover_d(shorts[:m], p256.N, bound, pub_check=lambda dd: p256.pubkey(dd) == pub)
        if d:
            break
    if not d:
        raise RuntimeError("key recovery failed")
    log(f"[+] private key d = {d:x}")

    zt = z_of(target)
    k = 1 + (int.from_bytes(os.urandom(32), "big") % (p256.N - 1))
    r, s = p256.sign(d, zt, k)
    res = c.release(target, format(r, "x"), format(s, "x"))
    log(f"[*] release -> {res.get('status')}")
    if "flag" in res:
        log(f"\n[+] FLAG: {res['flag']}")
        return res["flag"]
    raise RuntimeError(f"release rejected: {res}")


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
