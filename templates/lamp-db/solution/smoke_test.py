#!/usr/bin/env python3
"""
__SLUG__ smoke test (PLACEHOLDER). Rewrite solve() to perform your intended exploit.
Contract: driven by TARGET + FLAGS_ENV; exit 0 = PASS.
"""
import os
import re
import sys
import time

import requests

TARGET = os.environ.get("TARGET", "http://127.0.0.1:__PORT__").rstrip("/")
FLAG_RE = re.compile(r"CTF4\{[^}]+\}")


def expected_flag():
    path = os.environ.get("FLAGS_ENV", "")
    if path and os.path.exists(path):
        for line in open(path):
            m = re.match(r"\s*FLAG=(.*)", line)
            if m:
                return m.group(1).strip()
    return None


def wait_up():
    # MariaDB warms up inside the container; give it time.
    for _ in range(45):
        try:
            if requests.get(f"{TARGET}/", timeout=5).status_code < 500:
                return
        except requests.RequestException:
            pass
        time.sleep(2)


def solve():
    # PLACEHOLDER: the scaffold discloses the flag in an HTML comment on /.
    # Replace this with the real exploit against TARGET.
    r = requests.get(f"{TARGET}/", timeout=10)
    m = FLAG_RE.search(r.text)
    return m.group(0) if m else ""


def main():
    wait_up()
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
