#!/usr/bin/env python3
"""C16 reference solver — proves solvability from player-visible data only.

Attack (both flaws are required):
  1. Cross-chain replay: free tickets are the LEGACY EIP-712 type whose domain
     omits chainId, so a TestStage signature is also valid on MainStage. Only
     MainStage credits count toward the mint, and MainStage tickets aren't free —
     so replay is the only way to earn MainStage credit at all.
  2. ECDSA s-malleability + byte-dedup: the verifier accepts (r, n-s) too, and the
     per-chain dedup keys on signature bytes, so each ticket can be redeemed twice.

Replay alone (budget tickets) < threshold; malleability doubles it over the line.
"""
import json
import os
import secrets
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, "player", "client"))
from client import Client  # noqa: E402


def solve_once(host, port, verbose=True):
    def log(*a):
        if verbose:
            print(*a, flush=True)

    c = Client(host, port)
    info = c.info()
    N = int(info["curve"]["n"], 16)
    threshold = info["params"]["mint_threshold"]
    budget = info["params"]["free_budget"]
    holder = secrets.token_hex(20)
    log(f"[*] holder={holder}  threshold={threshold} MainStage credits, free budget={budget}")

    tickets = []
    for _ in range(budget):
        resp = c.freeticket(holder)
        if resp.get("status") != "issued":
            break
        tickets.append(resp)
    log(f"[*] obtained {len(tickets)} free TestStage tickets")

    for t in tickets:
        tk, sig = t["ticket"], t["signature"]
        r, s = sig["r"], sig["s"]
        s_mall = format((N - int(s, 16)) % N, "x")            # malleable counterpart
        a = c.submit("mainstage", tk, r, s)                   # bug 1: replay to MainStage
        b = c.submit("mainstage", tk, r, s_mall)              # bug 2: malleability -> 2nd credit
        log(f"    ticket {tk['ticket_id']}: replay={a['status']} malleable={b['status']}")

    have = c.credits("mainstage", holder)["credits"]
    log(f"[*] MainStage credits = {have} (need {threshold})")
    m = c.mint(holder)
    if m.get("status") == "minted":
        log(f"[+] minted {m['credential']}")
        log(f"\n[+] FLAG: {m['flag']}")
        return m["flag"]
    raise RuntimeError(f"mint failed: {m}")


def main():
    p = os.path.join(ROOT, "player", "samples", "instance_public.json")
    info = json.load(open(p))
    try:
        solve_once(info["gateway_host"], info["gateway_port"], verbose=True)
        return 0
    except Exception as ex:
        print(f"[-] solve failed: {ex}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
