#!/usr/bin/env python3
"""C07 reference client (shipped to players). Thin JSON/HTTP wrapper; no crypto."""
import json
import urllib.request


class Client:
    def __init__(self, host="127.0.0.1", port=9070, timeout=15):
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

    def round1(self, session_id, target):
        return self._post("/round1", {"session_id": session_id, "target": target})

    def round2(self, session_id, target, signer_set, msg, B):
        return self._post("/round2", {"session_id": session_id, "target": target,
                                      "set": signer_set, "msg": msg, "B": B})

    def commit(self, session_id):
        return self._post("/commit", {"session_id": session_id})

    def open_vault(self, R, z):
        return self._post("/open", {"R": R, "z": z})


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
    print(json.dumps(Client(host or "127.0.0.1", port or 9070).info(), indent=2))
