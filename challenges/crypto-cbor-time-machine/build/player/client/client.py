#!/usr/bin/env python3
"""C17 reference client (shipped to players). Thin JSON/HTTP wrapper — no CBOR, no
crypto. Crafting the polyglot badge is the challenge (bring your own CBOR encoder)."""
import json
import urllib.request


class Client:
    def __init__(self, host="127.0.0.1", port=9170, timeout=15):
        self.base = f"http://{host}:{port}"
        self.timeout = timeout

    def _get(self, path):
        with urllib.request.urlopen(self.base + path, timeout=self.timeout) as r:
            return json.load(r)

    def _post(self, path, obj):
        req = urllib.request.Request(self.base + path, data=json.dumps(obj).encode(),
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            return json.load(e)

    def info(self):
        return self._get("/info")

    def issue(self, badge_hex):
        return self._post("/issue", {"badge_hex": badge_hex})

    def customs(self, badge_hex, signature):
        return self._post("/customs", {"badge_hex": badge_hex, "signature": signature})


if __name__ == "__main__":
    import argparse
    import os
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default=None)
    ap.add_argument("--port", type=int, default=None)
    ap.add_argument("cmd", choices=["info"])
    a = ap.parse_args()
    host, port = a.host, a.port
    if host is None or port is None:
        p = os.path.join(os.path.dirname(__file__), "..", "samples", "instance_public.json")
        if os.path.exists(p):
            info = json.load(open(p))
            host = host or info["gateway_host"]
            port = port or info["gateway_port"]
    print(json.dumps(Client(host or "127.0.0.1", port or 9170).info(), indent=2))
