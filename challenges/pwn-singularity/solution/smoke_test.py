#!/usr/bin/env python3
"""pwn-singularity fleet smoke test (canary).
Runs the intended exploit end-to-end against a live container.
Driven by TARGET (host:port) and FLAGS_ENV. Exit 0 = PASS, non-zero = FAIL.
"""
import os, re, sys, time, subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
RAW = os.environ.get("TARGET", "127.0.0.1:11025")


def parse_target(raw):
    raw = raw.strip()
    for pfx in ("http://", "https://", "tcp://"):
        if raw.startswith(pfx):
            raw = raw[len(pfx):]
    raw = raw.rstrip("/")
    if ":" in raw:
        host, port = raw.rsplit(":", 1)
    else:
        host, port = raw, "5000"
    return host, port


def expected_flag():
    p = os.environ.get("FLAGS_ENV", "")
    if p and os.path.exists(p):
        for line in open(p):
            m = re.match(r"\s*FLAG=(.*)", line)
            if m:
                return m.group(1).strip()
    return None


def run_once(host, port):
    cmd = [sys.executable, os.path.join(HERE, "exploit.py"), host, port] + [os.path.join(HERE, "chall_dbg_docker"), "/tmp/flag"]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    except subprocess.TimeoutExpired as e:
        return "", "timeout: %s" % e
    blob = (out.stdout or "") + (out.stderr or "")
    m = re.search(r"CTF4\{[^}]*\}", blob)
    return (m.group(0) if m else ""), blob


def main():
    host, port = parse_target(RAW)
    want = expected_flag()
    got, blob = "", ""
    for attempt in range(3):
        got, blob = run_once(host, port)
        if got:
            break
        sys.stderr.write("[retry %d/3] no flag yet\n" % (attempt + 1))
        time.sleep(2)
    print("[captured] %r" % got)
    if got and (want is None or got == want):
        print("PASS")
        return 0
    sys.stderr.write(blob[-2000:] + "\n")
    print("FAIL expected=%r" % want)
    return 1


if __name__ == "__main__":
    sys.exit(main())
