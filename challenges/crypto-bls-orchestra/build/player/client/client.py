#!/usr/bin/env python3
"""C15 reference client (shipped to players). Thin JSON/HTTP wrapper over the
orchestra API. No crypto — constructing the rogue key and forged aggregate is the
challenge (bring your own BLS12-381 library)."""
import json
import urllib.request


class Client:
    def __init__(self, host="127.0.0.1", port=9150, timeout=15):
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

    def legacy_import(self, pubkey):
        return self._post("/legacy/import", {"pubkey": pubkey})

    def enroll(self, pubkey, section, pop):
        return self._post("/enroll", {"pubkey": pubkey, "section": section, "pop": pop})

    def approve(self, title, pubkeys, asig, cards):
        return self._post("/approve", {"title": title, "pubkeys": pubkeys, "asig": asig, "cards": cards})


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
    print(json.dumps(Client(host or "127.0.0.1", port or 9150).info(), indent=2))
