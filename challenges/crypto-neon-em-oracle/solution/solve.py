#!/usr/bin/env python3
"""C05 "Neon EM Oracle" reference solver.

1. Mint many tokens with known random plaintexts; keep each mint's EM trace.
2. Align every trace on its trigger spike (kills the per-trace timing jitter).
3. Correlation Power Analysis, byte by byte: the correct key byte guess maximises the
   Pearson correlation between HW(SBox(pt[i] ^ guess)) and the trace at the leak sample.
   The leak sample is located once (from byte 0) and reused as a small window for the rest.
4. Forge an AES-CMAC token over the forbidden command and POST /redeem -> flag.
"""
import json
import math
import os
import random
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, "src", "lib"))
import aes  # noqa: E402
from aes import SBOX, HW  # noqa: E402

N = 800            # traces collected
BATCH = 400        # plaintexts per mint sweep


def _url(net):
    return f"http://{net['gateway_host']}:{net['gateway_port']}"


def _get(base, path):
    with urllib.request.urlopen(base + path, timeout=60) as r:
        return json.load(r)


def _post(base, path, obj):
    data = json.dumps(obj).encode()
    req = urllib.request.Request(base + path, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.load(r)


def collect(base, n):
    rng = random.Random(1234)
    pts, traces = [], []
    for i in range(0, n, BATCH):
        chunk = [bytes(rng.randrange(256) for _ in range(16)) for _ in range(min(BATCH, n - i))]
        resp = _post(base, "/mint-batch", {"plaintexts": [p.hex() for p in chunk]})
        pts.extend(chunk)
        traces.extend(resp["traces"])
    return pts, traces


def align(traces, S):
    out = []
    for tr in traces:
        peak = max(range(min(S, len(tr))), key=lambda j: tr[j])
        out.append(tr[peak:] + [0.0] * peak)
    return out


def corr(h, t):
    n = len(h)
    sh = sum(h); st = sum(t)
    shh = sum(x * x for x in h); stt = sum(x * x for x in t)
    sht = sum(h[i] * t[i] for i in range(n))
    den = math.sqrt((n * shh - sh * sh) * (n * stt - st * st))
    return (n * sht - sh * st) / den if den else 0.0


def cpa(pts, traces, S):
    n = len(pts)
    cols = [[traces[r][s] for r in range(n)] for s in range(S)]
    # byte 0: scan every sample to locate the leak
    best = (-1.0, 0, 0)
    for g in range(256):
        h = [HW[SBOX[pts[r][0] ^ g]] for r in range(n)]
        for s in range(S):
            c = abs(corr(h, cols[s]))
            if c > best[0]:
                best = (c, g, s)
    _, g0, s0 = best
    key = [g0]
    for i in range(1, 16):
        bb = (-1.0, 0)
        for g in range(256):
            h = [HW[SBOX[pts[r][i] ^ g]] for r in range(n)]
            for s in range(max(0, s0 + i - 4), min(S, s0 + i + 5)):
                c = abs(corr(h, cols[s]))
                if c > bb[0]:
                    bb = (c, g)
        key.append(bb[1])
    return bytes(key)


def solve_once(inst_path=None):
    inst_path = inst_path or os.environ.get(
        "INSTANCE", os.path.join(ROOT, "instance", "state", "instance.json"))
    net = json.load(open(inst_path))["net"]
    base = _url(net)

    info = _get(base, "/info")
    S = info["trace_len"]
    forbidden = info["forbidden_command"]

    pts, traces = collect(base, N)
    key = cpa(pts, align(traces, S), S)

    tag = aes.cmac(key, forbidden.encode())
    out = _post(base, "/redeem", {"command": forbidden, "tag": tag.hex()})
    return out, key


def main():
    t0 = time.time()
    out, key = solve_once()
    dt = time.time() - t0
    if out.get("flag"):
        print(f"[+] recovered AES key {key.hex()} via CPA in {dt:.1f}s")
        print(f"[+] FLAG: {out['flag']}")
        return 0
    print(f"[-] no flag: {out}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
