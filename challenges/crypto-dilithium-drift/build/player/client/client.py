#!/usr/bin/env python3
"""Minimal client for C12 "Dilithium Drift".

  python3 client.py info
  python3 client.py sign  <firmware-name>
  python3 client.py publish <firmware-name> <cseed-hex> <z.json>
"""
import json
import os
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
SAMPLES = os.path.join(os.path.dirname(HERE), "samples")


def base():
    pub = json.load(open(os.path.join(SAMPLES, "instance_public.json")))
    return f"http://{pub['gateway_host']}:{pub['gateway_port']}"


def _get(path):
    with urllib.request.urlopen(base() + path, timeout=30) as r:
        return json.load(r)


def _post(path, obj):
    data = json.dumps(obj).encode()
    req = urllib.request.Request(base() + path, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def main(argv):
    if not argv:
        print(__doc__)
        return 2
    cmd = argv[0]
    if cmd == "info":
        print(json.dumps(_get("/info"), indent=2)[:2000])
    elif cmd == "sign":
        print(json.dumps(_post("/sign", {"firmware": argv[1]}), indent=2)[:2000])
    elif cmd == "publish":
        z = json.load(open(argv[3]))
        print(json.dumps(_post("/publish", {"firmware": argv[1], "cseed": argv[2], "z": z}), indent=2))
    else:
        print(__doc__)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
