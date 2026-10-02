#!/usr/bin/env python3
"""End-to-end smoke test (fleet canary) for a socat-fronted pwn service.

Runs the intended exploit (solution/exploit.py) against the LIVE container and
captures the flag over the wire. Driven by two env vars:
  TARGET     host:port (an optional scheme like tcp:// or http:// is stripped)
  FLAGS_ENV  path to flags.env, to compare the captured flag against.
Exit 0 = PASS.
"""
import os
import re
import sys
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))


def parse_target():
    t = os.environ.get("TARGET", "127.0.0.1:5000")
    t = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", t).strip().rstrip("/")
    host, sep, port = t.rpartition(":")
    if not sep:
        return t, "5000"
    return (host or "127.0.0.1"), port


def expected_flag():
    p = os.environ.get("FLAGS_ENV", "")
    if p and os.path.exists(p):
        for line in open(p):
            m = re.match(r"\s*FLAG=(.*)", line)
            if m:
                return m.group(1).strip()
    return None


def run_once(host, port):
    env = dict(os.environ, REMOTE_HOST=host, REMOTE_PORT=str(port))
    out = subprocess.run(
        [sys.executable, os.path.join(HERE, "exploit.py")],
        capture_output=True, text=True, timeout=180, env=env,
    )
    blob = out.stdout + out.stderr
    m = re.search(r"CTF4\{[^}]*\}", blob)
    return m.group(0) if m else ""


def main():
    host, port = parse_target()
    want = expected_flag()
    got = ""
    for i in range(5):
        try:
            got = run_once(host, port)
        except subprocess.TimeoutExpired:
            got = ""
        if got:
            break
        print(f"[*] attempt {i+1} did not capture a flag; retrying", file=sys.stderr)
    print(f"[captured] {got!r}")
    if got and (want is None or got == want):
        print("PASS")
        return 0
    print(f"FAIL expected={want!r}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
