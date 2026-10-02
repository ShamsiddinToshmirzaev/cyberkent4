#!/usr/bin/env python3
"""Fleet canary smoke test for a Crypto Gauntlet challenge.

Drives the challenge's own reference solver (copied into this folder) against a
LIVE container. Driven only by TARGET (host:port, http:// optional) and FLAGS_ENV.
Exit 0 = PASS. Prints the captured flag for debuggability.

Per-instance public data that the original solver read from a local
player/samples/instance_public.json handout is reconstructed here from the live
service's `GET /info` endpoint, then solve.ROOT is pointed at that synthetic tree.
Some solvers need a per-instance secret handout (my_share / my_credential) or use
a raw-TCP protocol with no /info; those are reported as blocked rather than forced.
"""
import contextlib
import inspect
import io
import json
import os
import re
import signal
import sys
import tempfile
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT_SLUG = os.path.dirname(HERE)
BUILD = os.path.join(ROOT_SLUG, "build")

for p in (os.path.join(BUILD, "src", "lib"),
          os.path.join(BUILD, "player", "client"),
          os.path.join(BUILD, "src"),
          HERE):
    if os.path.isdir(p):
        sys.path.insert(0, p)

RAW = os.environ.get("TARGET", "127.0.0.1:5000")
RAW = RAW.replace("http://", "").replace("https://", "").rstrip("/")
HOST, _, PORTS = RAW.partition(":")
PORT = int(PORTS or "5000")
BASEURL = f"http://{HOST}:{PORT}"


def expected_flag():
    p = os.environ.get("FLAGS_ENV", "")
    if p and os.path.exists(p):
        for line in open(p):
            m = re.match(r"\s*FLAG=(.*)", line)
            if m:
                return m.group(1).strip()
    return None


def fetch_info():
    try:
        with urllib.request.urlopen(BASEURL + "/info", timeout=10) as r:
            return json.load(r)
    except Exception:
        return None


def synth_root(info):
    """Build a temp ROOT with player/samples/instance_public.json from /info."""
    d = tempfile.mkdtemp(prefix="smoke_")
    samples = os.path.join(d, "player", "samples")
    os.makedirs(samples, exist_ok=True)
    pub = dict(info or {})
    pub.setdefault("gateway_host", HOST)
    pub.setdefault("gateway_port", PORT)
    pub["gateway_host"] = HOST
    pub["gateway_port"] = PORT
    with open(os.path.join(samples, "instance_public.json"), "w") as f:
        json.dump(pub, f)
    # opportunistically expose per-instance handouts if the service leaked them
    for key, fn in (("my_share", "my_share.json"), ("my_credential", "my_credential.json")):
        if isinstance(info, dict) and key in info:
            with open(os.path.join(samples, fn), "w") as f:
                json.dump(info[key], f)
    return d


class _Timeout(Exception):
    pass


def _alarm(signum, frame):
    raise _Timeout()


def run_solver(max_seconds=90):
    import solve
    info = fetch_info()
    troot = synth_root(info)
    solve.ROOT = troot
    # inst_path-form solvers need a net-only instance file
    inst_path = os.path.join(troot, "instance.json")
    with open(inst_path, "w") as f:
        json.dump({"net": {"gateway_host": HOST, "gateway_port": PORT}}, f)

    params = inspect.signature(solve.solve_once).parameters
    if "host" in params and "port" in params:
        call = lambda: solve.solve_once(HOST, PORT)
    elif "inst_path" in params:
        call = lambda: solve.solve_once(inst_path=inst_path)
    elif "samples_dir" in params:
        call = lambda: solve.solve_once(os.path.join(troot, "player", "samples"))
    else:
        call = lambda: solve.solve_once()

    buf = io.StringIO()
    ret = None
    err = None
    signal.signal(signal.SIGALRM, _alarm)
    signal.alarm(max_seconds)
    try:
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            ret = call()
    except _Timeout:
        err = f"solver exceeded {max_seconds}s"
    except Exception as ex:
        err = f"{type(ex).__name__}: {ex}"
    finally:
        signal.alarm(0)
    blob = buf.getvalue() + "\n" + repr(ret) + "\n" + (err or "")
    return blob, err


def main():
    try:
        blob, err = run_solver(int(os.environ.get("SMOKE_TIMEOUT", "90")))
    except Exception as ex:
        print(f"[smoke] solver harness error: {ex}")
        print("BLOCKED")
        return 2
    m = re.search(r"CTF4\{[^}]*\}", blob)
    got = m.group(0) if m else ""
    want = expected_flag()
    print(f"[captured] {got!r}")
    if got and (want is None or got == want):
        print("PASS")
        return 0
    if err:
        print(f"[smoke] solver did not capture flag: {err}")
    print(f"FAIL expected={want!r}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
