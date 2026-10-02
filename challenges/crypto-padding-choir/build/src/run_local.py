#!/usr/bin/env python3
"""Local launcher: read an instance file, start the appliance (with the right
env) then the gateway, and shut both down cleanly on Ctrl-C. `make run` calls
this. In Docker the two run as separate compose services instead."""
import json
import os
import signal
import socket
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def wait_port(host, port, timeout=10.0):
    end = time.time() + timeout
    while time.time() < end:
        try:
            socket.create_connection((host, port), 0.3).close()
            return True
        except OSError:
            time.sleep(0.1)
    return False


def main():
    def _term(*_a):
        raise SystemExit(0)
    signal.signal(signal.SIGTERM, _term)
    signal.signal(signal.SIGINT, _term)

    inst_path = os.environ.get("INSTANCE", os.path.join(ROOT, "instance", "state", "instance.json"))
    if not os.path.exists(inst_path):
        sys.exit(f"no instance at {inst_path}; run `make instance` first")
    inst = json.load(open(inst_path))
    net, p = inst["net"], inst["params"]
    appliance_bin = os.path.join(ROOT, "build", "appliance", "appliance")
    if not os.path.exists(appliance_bin):
        sys.exit("appliance not built; run `make build` first")

    ap_env = dict(os.environ,
                  APPLIANCE_KEY=os.path.join(ROOT, inst["appliance_key_pem"]),
                  APPLIANCE_PORT=str(net["appliance_port"]),
                  DER_WORK_FACTOR=str(p["der_work_factor"]),
                  WORKER_COUNT=str(p["worker_count"]),
                  ISSUER_TAG=inst["issuer_tag"],
                  ALLOWLIST=",".join(inst["allowlist_roles"]))
    # the gateway gets the reduced config (no RSA private key / issuerTag)
    gw_cfg = os.path.join(os.path.dirname(inst_path), "gateway.json")
    gw_env = dict(os.environ, INSTANCE=gw_cfg if os.path.exists(gw_cfg) else inst_path)

    procs = []
    try:
        procs.append(subprocess.Popen([appliance_bin], env=ap_env))
        if not wait_port(net["appliance_host"], net["appliance_port"]):
            sys.exit("appliance failed to come up")
        procs.append(subprocess.Popen([sys.executable, os.path.join(HERE, "gateway", "gateway.py")], env=gw_env))
        if not wait_port(net["gateway_host"], net["gateway_port"]):
            sys.exit("gateway failed to come up")
        print(f"[+] C02 up. gateway on {net['gateway_host']}:{net['gateway_port']}  (Ctrl-C to stop)")
        while True:
            for pr in procs:
                if pr.poll() is not None:
                    raise SystemExit(f"child {pr.pid} exited ({pr.returncode})")
            time.sleep(0.5)
    finally:
        for pr in procs:
            try:
                pr.send_signal(signal.SIGTERM)
            except Exception:
                pass
        for pr in procs:
            try:
                pr.wait(timeout=3)
            except Exception:
                pr.kill()


if __name__ == "__main__":
    main()
