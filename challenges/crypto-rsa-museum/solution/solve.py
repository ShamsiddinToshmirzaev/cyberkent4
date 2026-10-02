#!/usr/bin/env python3
"""C18 "RSA Museum" reference solver.

1. Get a correct certificate signature of a probe artifact (glitch=0).
2. Sweep the glitch offset upward to find the fault band (too low = no faults, too high = the
   HSM halts). At a working level, sign the SAME probe repeatedly until a signature fails to
   verify (a fault).
3. For each faulty signature, gcd(s_correct - s_faulty, N): a single-branch CRT fault yields a
   nontrivial factor of N (double-branch faults give a trivial gcd and are skipped).
4. Factor -> recover d -> forge the EMSA-PSS certificate for the forbidden artifact -> /issue.

This works because the HSM's PSS salt is deterministic, so the probe re-signs to the same EM.
"""
import json
import math
import os
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, "src", "lib"))
import rsa  # noqa: E402

PROBE = "artifact-probe-7"


def _url(net):
    return f"http://{net['gateway_host']}:{net['gateway_port']}"


def _get(base, path):
    with urllib.request.urlopen(base + path, timeout=60) as r:
        return json.load(r)


def _post(base, path, obj):
    data = json.dumps(obj).encode()
    req = urllib.request.Request(base + path, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)


def solve_once(inst_path=None):
    inst_path = inst_path or os.environ.get(
        "INSTANCE", os.path.join(ROOT, "instance", "state", "instance.json"))
    net = json.load(open(inst_path))["net"]
    base = _url(net)

    info = _get(base, "/info")
    n = int(info["rsa"]["n"], 16)
    e = info["rsa"]["e"]
    forbidden = info["forbidden_artifact"]
    pubkey = {"n": n, "e": e, "embits": n.bit_length() - 1}

    # 1) correct signature of the probe
    s0 = int(_post(base, "/sign", {"artifact": PROBE, "glitch": 0})["signature"], 16)

    # 2+3) sweep glitch, catch a usable single-branch fault, gcd -> factor
    probe_msg = b"CERT|" + PROBE.encode()
    factor, queries, halted = None, 0, False
    for glitch in range(1, 100):
        if factor or halted:
            break
        for _ in range(30):
            r = _post(base, "/sign", {"artifact": PROBE, "glitch": glitch})
            queries += 1
            st = r.get("status")
            if st == "halted":
                halted = True    # climbed past gmax; usable faults are below this band
                break
            if st != "signed":
                continue
            s = int(r["signature"], 16)
            if rsa.verify(pubkey, probe_msg, s):
                continue         # correct signature, no fault
            g = math.gcd((s0 - s) % n, n)
            if 1 < g < n:
                factor = g
                break
    if not factor:
        return {"status": "failed", "reason": "no usable fault found"}, queries

    # 4) recover d and forge
    p = factor
    q = n // p
    d = pow(e, -1, (p - 1) * (q - 1))
    key = {"n": n, "e": e, "d": d, "p": p, "q": q, "dp": d % (p - 1), "dq": d % (q - 1),
           "qinv": pow(q, -1, p), "bits": n.bit_length(), "embits": n.bit_length() - 1}
    forged = format(rsa.sign(key, b"CERT|" + forbidden.encode()), "x")
    out = _post(base, "/issue", {"artifact": forbidden, "signature": forged})
    out["_queries"] = queries
    return out, queries


def main():
    t0 = time.time()
    out, q = solve_once()
    dt = time.time() - t0
    if out.get("flag"):
        print(f"[+] factored N via a CRT fault in {q} glitch queries, {dt:.1f}s")
        print(f"[+] FLAG: {out['flag']}")
        return 0
    print(f"[-] no flag: {out}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
