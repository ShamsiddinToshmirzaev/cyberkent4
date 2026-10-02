#!/usr/bin/env python3
"""End-to-end smoke test (fleet canary) for a pwn challenge.
Runs the intended exploit against a live container over TCP.
Driven by TARGET (host:port, scheme stripped) and FLAGS_ENV. Exit 0 = PASS.
"""
import os, re, sys, subprocess

HERE = os.path.dirname(os.path.abspath(__file__))


def parse_target():
    t = os.environ.get("TARGET", "127.0.0.1:11006")
    t = re.sub(r"^[a-zA-Z]+://", "", t).strip().rstrip("/")
    if ":" in t:
        host, port = t.rsplit(":", 1)
    else:
        host, port = t, "11006"
    return host, port


def expected_flag():
    p = os.environ.get("FLAGS_ENV", "")
    if p and os.path.exists(p):
        for line in open(p):
            m = re.match(r"\s*FLAG=(.*)", line)
            if m:
                return m.group(1).strip()
    return None


def run_exploit(host, port):
    env = dict(os.environ, PWNLIB_NOTERM="1")
    out = subprocess.run(
        [sys.executable, os.path.join(HERE, "exploit.py"), host, port],
        capture_output=True, text=True, timeout=180, env=env,
    )
    return out.stdout + out.stderr


def main():
    host, port = parse_target()
    want = expected_flag()
    got = ""
    for attempt in range(1, 4):
        blob = run_exploit(host, port)
        m = re.search(r"CTF4\{[^}]*\}", blob)
        if m:
            got = m.group(0)
            break
        print(f"[retry] attempt {attempt} did not capture a flag")
    print(f"[captured] {got!r}")
    if got and (want is None or got == want):
        print(f"[captured] {got}")
        print("PASS")
        return 0
    print(f"FAIL expected={want!r}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
