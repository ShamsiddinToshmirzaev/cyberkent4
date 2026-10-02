#!/usr/bin/env python3
"""Local launcher: read the instance, start the C signer (with d in its env) and
the Python gateway (reduced config), shut both down cleanly on signal."""
import json
import os
import signal
import socket
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def wait_port(host, port, timeout=10):
    end = time.time() + timeout
    while time.time() < end:
        try:
            socket.create_connection((host, port), 0.3).close()
            return True
        except OSError:
            time.sleep(0.1)
    return False


def main():
    def _term(*_):
        raise SystemExit(0)
    signal.signal(signal.SIGTERM, _term)
    signal.signal(signal.SIGINT, _term)

    inst_path = os.environ.get("INSTANCE", os.path.join(ROOT, "instance", "state", "instance.json"))
    inst = json.load(open(inst_path))
    net, p = inst["net"], inst["params"]
    signer_bin = os.path.join(ROOT, "build", "signer", "signer")
    if not os.path.exists(signer_bin):
        sys.exit("signer not built; run `make build`")

    senv = dict(os.environ, SIGNER_PORT=str(net["signer_port"]), SIGNER_D=inst["signer"]["d"],
                WORK_FACTOR=str(p["work_factor"]), SIGNER_OFFSET=str(p["signer_offset"]),
                SIGNER_BIND="127.0.0.1")
    gw_cfg = os.path.join(os.path.dirname(inst_path), "gateway.json")
    genv = dict(os.environ, INSTANCE=gw_cfg)

    procs = []
    try:
        procs.append(subprocess.Popen([signer_bin], env=senv))
        if not wait_port(net["signer_host"], net["signer_port"]):
            sys.exit("signer failed to come up")
        procs.append(subprocess.Popen([sys.executable, os.path.join(HERE, "gateway", "gateway.py")], env=genv))
        if not wait_port(net["gateway_host"], net["gateway_port"]):
            sys.exit("gateway failed to come up")
        print(f"[+] C03 up. gateway on {net['gateway_host']}:{net['gateway_port']} (Ctrl-C to stop)")
        while True:
            for pr in procs:
                if pr.poll() is not None:
                    raise SystemExit(f"child exited ({pr.returncode})")
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
