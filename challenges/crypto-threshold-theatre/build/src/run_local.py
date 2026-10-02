#!/usr/bin/env python3
"""Local launcher: run the signing gateway with the instance file."""
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
    net = json.load(open(inst_path))["net"]
    env = dict(os.environ, INSTANCE=inst_path, GATEWAY_BIND="127.0.0.1")
    p = subprocess.Popen([sys.executable, os.path.join(HERE, "gateway", "gateway.py")], env=env)
    try:
        if not wait_port(net["gateway_host"], net["gateway_port"]):
            sys.exit("gateway failed to come up")
        print(f"[+] C08 up. gateway on {net['gateway_host']}:{net['gateway_port']} (Ctrl-C to stop)")
        while True:
            if p.poll() is not None:
                raise SystemExit(f"gateway exited ({p.returncode})")
            time.sleep(0.5)
    finally:
        try:
            p.send_signal(signal.SIGTERM)
            p.wait(timeout=3)
        except Exception:
            p.kill()


if __name__ == "__main__":
    main()
