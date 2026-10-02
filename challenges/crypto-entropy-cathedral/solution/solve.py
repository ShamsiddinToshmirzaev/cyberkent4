#!/usr/bin/env python3
"""C20 full reference solver — recover an old rotation root from the reduced entropy
and ring the bell via the endian epoch confusion, using only player-visible data.

Stages: (A) read telemetry -> which epochs excluded source D; (B) pick the excluded
epoch whose byte-swap is the current epoch (the endian-confusion target e_old);
(C) enumerate (clock, C) against e_old's published commitment -> recover the root;
(D) ring the bell with epoch bytes that the authoriser reads (little-endian) as the
current epoch while the root lookup reads (big-endian) as e_old.
"""
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, "src", "lib"))
sys.path.insert(0, os.path.join(ROOT, "player", "client"))
import kms                       # noqa: E402
from client import Client        # noqa: E402


def bswap16(e):
    return ((e & 0xFF) << 8) | ((e >> 8) & 0xFF)


def solve_once(host, port, verbose=True):
    def log(*a):
        if verbose:
            print(*a, flush=True)

    c = Client(host, port)
    info = c.info()
    salt = bytes.fromhex(info["salt"])
    current = info["current_epoch"]
    commits = {int(e): bytes.fromhex(v) for e, v in info["root_commitments"].items()}
    clock_bits, c_bits = info["clock_bits"], info["c_source_bits"]

    tel = c.telemetry()["epochs"]
    excluded = [int(e) for e, v in tel.items() if not v["source_D_healthy"]]
    log(f"[*] source-D excluded on epochs: {[hex(e) for e in excluded]}")
    targets = [e for e in excluded if bswap16(e) == current]
    if not targets:
        raise RuntimeError("no excluded epoch byte-swaps to the current epoch")
    e_old = targets[0]
    log(f"[*] target e_old={e_old:#06x} (byte-swap of current {current:#06x})")

    # enumerate the reduced seed space (clock, C) against e_old's commitment
    want = commits[e_old]
    t = time.time()
    found = None
    for clock in range(1 << clock_bits):
        for cc in range(1 << c_bits):
            if kms.commitment(kms.derive_root(salt, clock, cc, None, e_old), e_old) == want:
                found = (clock, cc)
                break
        if found:
            break
    if not found:
        raise RuntimeError("enumeration failed")
    log(f"[*] recovered (clock, C) in {time.time()-t:.1f}s")

    root_old = kms.derive_root(salt, found[0], found[1], None, e_old)
    eb = e_old.to_bytes(2, "big")   # big-endian == e_old (root lookup); little-endian == current
    res = c.ring(eb.hex(), kms.ring_mac(root_old, eb).hex())
    log(f"[*] ring -> {res.get('status')}")
    if "flag" in res:
        log(f"\n[+] FLAG: {res['flag']}")
        return res["flag"]
    raise RuntimeError(f"bell did not ring: {res}")


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
