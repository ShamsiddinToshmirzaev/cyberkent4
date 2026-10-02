#!/usr/bin/env python3
"""Container entrypoint for the signer: read the (secret) instance file, set the
signer's environment, exec the compiled binary."""
import json
import os

inst = json.load(open(os.environ.get("INSTANCE", "/key/instance.json")))
net, p = inst["net"], inst["params"]
env = dict(os.environ,
           SIGNER_PORT=str(net["signer_port"]),
           SIGNER_D=inst["signer"]["d"],
           WORK_FACTOR=str(p["work_factor"]),
           SIGNER_OFFSET=str(p["signer_offset"]),
           SIGNER_BIND=os.environ.get("SIGNER_BIND", "0.0.0.0"))
os.execve("/app/build/signer/signer", ["signer"], env)
