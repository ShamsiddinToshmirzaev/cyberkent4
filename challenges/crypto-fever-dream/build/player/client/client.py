#!/usr/bin/env python3
"""Minimal client for C04 "Fever Dream".

  python3 client.py info
  python3 client.py sign <command> [cool]
  python3 client.py command <command> <r-hex> <s-hex>
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
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)


def main(argv):
    if not argv:
        print(__doc__)
        return 2
    cmd = argv[0]
    if cmd == "info":
        print(json.dumps(_get("/info"), indent=2)[:2000])
    elif cmd == "sign":
        cool = int(argv[2]) if len(argv) > 2 else 0
        print(json.dumps(_post("/sign", {"command": argv[1], "cool": cool}), indent=2))
    elif cmd == "command":
        print(json.dumps(_post("/command", {"command": argv[1], "r": argv[2], "s": argv[3]}), indent=2))
    else:
        print(__doc__)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
