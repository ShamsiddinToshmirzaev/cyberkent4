#!/usr/bin/env python3
"""C15 full reference solver — proves solvability from player-visible data only.

Attack (both flaws required):
  1. Read the public registry (GET /info) -> honest legacy founder public keys.
  2. Rogue-key (flaw a, no PoP on /legacy/import): register pk* = x*G1 - sum(pk_i)
     via the Rust `orchestra forge` helper, so the legacy aggregate collapses to
     x*G1 and we forge asig = x*H(title) with no honest cooperation.
  3. Attendance-card weight (flaw b): the tally reads each card's section, deduped
     by (section,pubkey). Submit founder cards in their real sections (captured by
     the forged aggregate) plus rogue cards claiming weighty sections -> cross the
     threshold and approve THE ROGUE SYMPHONY.
"""
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, "player", "client"))
from client import Client  # noqa: E402

BIN = os.path.join(ROOT, "src", "orchestra", "target", "release", "orchestra")


def solve_once(host, port, verbose=True):
    def log(*a):
        if verbose:
            print(*a, flush=True)

    c = Client(host, port)
    info = c.info()
    threshold = info["threshold"]
    target = info["target_title"]
    app_dst = info["app_dst"]
    founders = [m for m in info["members"] if m["committee"] == "legacy"]
    honest = [m["pubkey"] for m in founders]
    sections = [s["name"] for s in info["sections"]]
    log(f"[*] {len(founders)} founders, threshold {threshold}, target {target!r}")

    # flaw (a): forge the legacy aggregate via a rogue cancellation key
    out = subprocess.run([BIN, "forge", "--honest", ",".join(honest),
                          "--app-dst", app_dst, "--title", target],
                         capture_output=True, text=True, check=True)
    forged = json.loads(out.stdout)
    rogue, asig = forged["rogue_pubkey"], forged["asig"]
    log(f"[*] rogue key = {rogue[:24]}...  asig = {asig[:24]}...")

    imp = c.legacy_import(rogue)
    log(f"[*] legacy import -> {imp.get('status')} (section={imp.get('section')}, weight={imp.get('weight')})")

    # flaw (b): attendance cards. Founders in their real sections (captured by the
    # forged aggregate) + rogue claims every weighty section (multi-role).
    cards = [{"pubkey": m["pubkey"], "section": m["section"]} for m in founders]
    cards += [{"pubkey": rogue, "section": s} for s in sections]

    res = c.approve(target, honest + [rogue], asig, cards)
    log(f"[*] approve -> {res.get('status')} (tally={res.get('tally')}/{res.get('threshold')})")
    if res.get("status") == "approved" and "flag" in res:
        log(f"\n[+] FLAG: {res['flag']}")
        return res["flag"]
    raise RuntimeError(f"approval failed: {res}")


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
