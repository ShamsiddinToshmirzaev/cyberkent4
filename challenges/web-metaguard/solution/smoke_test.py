#!/usr/bin/env python3
"""web-metaguard end-to-end smoke test (fleet canary).
Runs the intended SSRF->IMDS->AWS4-sign chain against a live container.
Driven by TARGET and FLAGS_ENV. Exit 0 = PASS.
"""
import os, re, sys, subprocess

TARGET = os.environ.get("TARGET", "http://127.0.0.1:10001").rstrip("/")
HERE = os.path.dirname(os.path.abspath(__file__))

def expected_flag():
    p = os.environ.get("FLAGS_ENV", "")
    if p and os.path.exists(p):
        for line in open(p):
            m = re.match(r"\s*FLAG=(.*)", line)
            if m:
                return m.group(1).strip()
    return None

def solve():
    # solve_impl.py takes the base URL as argv[1] and prints the captured flag.
    out = subprocess.run(
        [sys.executable, os.path.join(HERE, "solve_impl.py"), TARGET],
        capture_output=True, text=True, timeout=120,
    )
    blob = out.stdout + out.stderr
    m = re.search(r"CTF4\{[^}]*\}", blob)
    return m.group(0) if m else ""

def main():
    got = solve()
    want = expected_flag()
    print(f"[captured] {got!r}")
    if got and (want is None or got == want):
        print("PASS"); return 0
    print(f"FAIL expected={want!r}"); return 1

if __name__ == "__main__":
    sys.exit(main())
