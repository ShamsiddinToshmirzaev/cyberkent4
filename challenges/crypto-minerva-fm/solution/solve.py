#!/usr/bin/env python3
"""C03 full reference solver — recovers the DRM key from the nonce timing leak and
forges the ghost-dj broadcast, using only player-visible data.

  1. request many signatures on a benign manifest, measuring each round-trip time;
  2. the fastest signatures used the shortest nonces (bitlen ~ signing time);
  3. take the fastest m, build an HNP lattice with a bound loose enough to cover
     them, LLL-reduce, and read off the private key (adaptive over the bound);
  4. sign the forbidden ghost-dj manifest with the recovered key and submit it.
"""
import hashlib
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, "src", "lib"))
sys.path.insert(0, os.path.join(ROOT, "player", "client"))
sys.path.insert(0, HERE)
import p256                       # noqa: E402
from client import Client         # noqa: E402
from hnp import recover_d         # noqa: E402

BENIGN = b'{"station":"88.5","title":"calibration","mix":"night"}'
# (m, T) attempts: bias = m*T must exceed 256 with margin; loosen T if selection is noisy
ATTEMPTS = [(48, 7), (56, 6), (64, 6)]


def solve_once(host, port, n_collect=16000, verbose=True):
    def log(*a):
        if verbose:
            print(*a, flush=True)

    info = json.load(open(os.path.join(ROOT, "player", "samples", "instance_public.json")))
    N = int(info["curve"]["n"], 16)
    pub = (int(info["pubkey"]["x"], 16), int(info["pubkey"]["y"], 16))
    target = info["target_manifest"].encode()

    cli = Client(host, port)
    z = int.from_bytes(hashlib.sha256(BENIGN).digest(), "big")

    log(f"[*] collecting {n_collect} signatures (timing the leak) ...")
    t0 = time.time()
    data = []
    for _ in range(n_collect):
        r, s, rtt = cli.sign(BENIGN)
        if r is not None:
            data.append((r, s, rtt))
    log(f"    collected {len(data)} in {time.time()-t0:.1f}s")
    data.sort(key=lambda x: x[2])                       # fastest first

    d = None
    for (m, T) in ATTEMPTS:
        if m > len(data):
            continue
        sigs = [(r, s, z) for (r, s, _) in data[:m]]
        bound = 1 << (256 - T)
        log(f"[*] HNP attempt m={m} T={T} (dim {m+2}) ...")
        t1 = time.time()
        d = recover_d(sigs, N, bound, pub_check=lambda dd: p256.pubkey(dd) == pub)
        log(f"    {'recovered' if d else 'failed'} in {time.time()-t1:.1f}s")
        if d:
            break
    if not d:
        raise RuntimeError("key recovery failed (try collecting more signatures)")
    log(f"[+] private key d = {d:x}")

    log("[*] forging the ghost-dj broadcast manifest ...")
    zt = int.from_bytes(hashlib.sha256(target).digest(), "big")
    k = 1 + (int.from_bytes(os.urandom(32), "big") % (N - 1))
    r, s = p256.sign(d, zt, k)
    line = cli.submit(target, r, s)
    log(f"    submit -> {line}")
    cli.close()
    if "flag{" in line:
        flag = line[line.index("flag{"):line.index("}", line.index("flag{")) + 1]
        log(f"\n[+] FLAG: {flag}")
        return flag
    raise RuntimeError("submission rejected")


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
