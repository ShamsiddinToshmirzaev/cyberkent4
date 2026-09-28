#!/usr/bin/env python3
"""
web-silent-channel liveness + provisioning smoke test.

The full intended solve (media-upload XXE -> wp-config creds -> webshell -> /flag.txt)
requires an attacker-hosted DTD and is kept in the other solution/ scripts
(1_create_wav.py, 2_evil.dtd, 3_solve.py). This smoke test confirms the stack is up
and correctly provisioned so ctfctl can gate deploys and post-reset health:
  - WordPress responds and is installed (wp-login.php present)
  - the REST API (the XXE trigger surface) is reachable
Exit 0 = PASS.
"""
import os
import sys

import requests

TARGET = os.environ.get("TARGET", "http://127.0.0.1:10002").rstrip("/")


def check():
    # 1) Must be fully installed, i.e. NOT redirecting to the WP installer.
    r = requests.get(f"{TARGET}/", timeout=10, allow_redirects=True)
    if "wp-admin/install.php" in r.url or "wp-admin/setup-config.php" in r.url:
        print(f"[!] WordPress not installed yet (landed on {r.url})")
        return False
    print("[+] WordPress is installed (no installer redirect)")

    # 2) Login page present (the site the XXE targets).
    r = requests.get(f"{TARGET}/wp-login.php", timeout=10)
    if r.status_code != 200 or ("log in" not in r.text.lower() and "wordpress" not in r.text.lower()):
        print(f"[!] wp-login.php unexpected: {r.status_code}")
        return False
    print("[+] wp-login.php OK")

    # 3) REST API reachable and reports a live site name (the XXE trigger surface).
    #    WP 5.6 defaults to plain permalinks, so use the always-available rest_route form.
    r = requests.get(f"{TARGET}/?rest_route=/", timeout=10)
    try:
        name = r.json().get("name")
    except ValueError:
        name = None
    if r.status_code != 200 or not name:
        print(f"[!] REST API not reporting a site: {r.status_code}")
        return False
    print(f"[+] REST API live: site name = {name!r}")
    return True


def main():
    ok = check()
    print("PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
