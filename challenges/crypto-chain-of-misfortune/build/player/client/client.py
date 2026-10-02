#!/usr/bin/env python3
"""C16 reference client (shipped to players). Thin JSON/HTTP wrapper over the
NovaFest API — no crypto, no hints. Figuring out the ticket economy is the
challenge.

    from client import Client
    c = Client("127.0.0.1", 9160)
    c.info(); c.freeticket(holder_hex)
    c.submit("mainstage", ticket_dict, r_hex, s_hex)
    c.credits("mainstage", holder_hex); c.mint(holder_hex)
"""
import json
import urllib.request


class Client:
    def __init__(self, host="127.0.0.1", port=9160, timeout=10):
        self.base = f"http://{host}:{port}"
        self.timeout = timeout

    def _get(self, path):
        with urllib.request.urlopen(self.base + path, timeout=self.timeout) as r:
            return json.load(r)

    def _post(self, path, obj):
        req = urllib.request.Request(self.base + path, data=json.dumps(obj).encode(),
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            return json.load(r)

    def info(self):
        return self._get("/info")

    def freeticket(self, holder):
        return self._post("/freeticket", {"holder": holder})

    def submit(self, chain, ticket, r, s):
        return self._post("/submit", {"chain": chain, "ticket": ticket,
                                      "signature": {"r": r, "s": s}})

    def credits(self, chain, holder):
        return self._get(f"/credits?chain={chain}&holder={holder}")

    def mint(self, holder):
        return self._post("/mint", {"holder": holder})


if __name__ == "__main__":
    import argparse
    import os
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default=None)
    ap.add_argument("--port", type=int, default=None)
    ap.add_argument("cmd", choices=["info", "credits"])
    ap.add_argument("--chain", default="mainstage")
    ap.add_argument("--holder", default="")
    a = ap.parse_args()
    host, port = a.host, a.port
    if host is None or port is None:
        p = os.path.join(os.path.dirname(__file__), "..", "samples", "instance_public.json")
        if os.path.exists(p):
            info = json.load(open(p))
            host = host or info["gateway_host"]
            port = port or info["gateway_port"]
    c = Client(host or "127.0.0.1", port or 9160)
    print(json.dumps(c.info() if a.cmd == "info" else c.credits(a.chain, a.holder), indent=2))
