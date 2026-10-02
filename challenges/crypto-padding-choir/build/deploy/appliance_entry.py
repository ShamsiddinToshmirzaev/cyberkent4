#!/usr/bin/env python3
"""Container entrypoint for the appliance: read the (secret) instance file, set
the appliance's environment, and exec the compiled binary. Keeps the C++ binary
free of any JSON dependency."""
import json
import os

inst = json.load(open(os.environ.get("INSTANCE", "/key/instance.json")))
p, net = inst["params"], inst["net"]
env = dict(os.environ,
           APPLIANCE_KEY=os.environ.get("APPLIANCE_KEY", "/key/appliance_key.pem"),
           APPLIANCE_PORT=str(net["appliance_port"]),
           APPLIANCE_BIND=os.environ.get("APPLIANCE_BIND", "0.0.0.0"),
           DER_WORK_FACTOR=str(p["der_work_factor"]),
           WORKER_COUNT=str(p["worker_count"]),
           ISSUER_TAG=inst["issuer_tag"],
           ALLOWLIST=",".join(inst["allowlist_roles"]))
os.execve("/app/build/appliance/appliance", ["appliance"], env)
