#!/usr/bin/env python3
"""C04 "Fever Dream" reference solver.

The signing module's DVFS power leak reveals, per signature, an energy drop proportional to
the number of leading-zero bits of the (deterministic) nonce k. The plan:

1. Drive the module to a cool baseline before every measurement (send a large `cool`), so
   the throttle factor is constant and the energy leak is legible.
2. Screen many commands with one measurement each, keep the lowest-energy candidates, then
   average repeated measurements of each candidate to beat the log-normal jitter.
3. Rank candidates by averaged energy: the smallest energies are the nonces with the most
   leading zeros, i.e. the shortest nonces (known high zero bits).
4. Feed those short-nonce ECDSA signatures to the Hidden Number Problem lattice. Try a few
   uniform nonce bounds (most leading zeros first) and let the public key filter the answer.
5. Forge a signature over the forbidden command and POST /command -> flag.
"""
import json
import os
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, "src", "lib"))
sys.path.insert(0, HERE)
import ecc  # noqa: E402
from hnp import recover_d  # noqa: E402

COOL = 60          # idle ticks: enough to return to ambient before each measurement
M = 8000           # commands screened
KEEP = 320         # candidates kept after the single-shot screen
KCONF = 16         # averaged measurements per candidate
T = 22             # short-nonce signatures fed to the HNP lattice
BATCH = 2000       # commands per telemetry-sweep request


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


def measure(base, command, cool=COOL):
    resp = _post(base, "/sign", {"command": command, "cool": cool})
    return resp["power_uj"], (int(resp["r"], 16), int(resp["s"], 16))


def measure_batch(base, commands, cool=COOL):
    """Return list of (power, (r, s)) for a telemetry sweep, in chunks."""
    out = []
    for i in range(0, len(commands), BATCH):
        chunk = commands[i:i + BATCH]
        resp = _post(base, "/sign-batch", {"commands": chunk, "cool": cool})
        for res in resp["results"]:
            out.append((res["power_uj"], (int(res["r"], 16), int(res["s"], 16))))
    return out


def solve_once(inst_path=None):
    inst_path = inst_path or os.environ.get(
        "INSTANCE", os.path.join(ROOT, "instance", "state", "instance.json"))
    net = json.load(open(inst_path))["net"]
    base = _url(net)

    info = _get(base, "/info")
    Q = (int(info["pubkey"]["x"], 16), int(info["pubkey"]["y"], 16))
    forbidden = info["forbidden_command"]

    # 1+2) screen at cool baseline (one telemetry sweep), keep the lowest-energy candidates
    names = [f"probe-{i}" for i in range(M)]
    swept = measure_batch(base, names)
    scores = sorted((p, names[i]) for i, (p, _) in enumerate(swept))
    cands = [name for _, name in scores[:KEEP]]

    # 3) average candidates (repeat each KCONF times in a sweep), rank, take shortest nonces
    rep = [name for name in cands for _ in range(KCONF)]
    reps = measure_batch(base, rep)
    acc = {name: 0.0 for name in cands}
    for k, (p, _) in enumerate(reps):
        acc[rep[k]] += p
    avg = sorted((total / KCONF, name) for name, total in acc.items())
    chosen = [name for _, name in avg[:T]]

    sigs = []
    for name in chosen:
        z = ecc.zhash(name.encode())
        _, (p_r, p_s) = measure(base, name)
        sigs.append((p_r, p_s, z))

    # 4) HNP over a few uniform bounds (most leading zeros first)
    d = None
    for ell in (7, 6, 8, 5, 9):
        bound = 1 << (ecc.N.bit_length() - ell)
        d = recover_d(sigs, ecc.N, bound, pub_check=lambda dd: ecc.pubkey(dd) == Q)
        if d:
            break
    if not d:
        return {"status": "failed", "reason": "HNP did not recover the key"}, M + KEEP * KCONF

    # 5) forge over the forbidden command and submit
    r, s, z, k = ecc.sign(d, forbidden.encode())
    out = _post(base, "/command", {"command": forbidden, "r": format(r, "x"), "s": format(s, "x")})
    out["_ell"] = ell
    return out, M + KEEP * KCONF


def main():
    t0 = time.time()
    out, calls = solve_once()
    dt = time.time() - t0
    if out.get("flag"):
        print(f"[+] recovered key (ell={out.get('_ell')}) in ~{calls} device calls, {dt:.1f}s")
        print(f"[+] FLAG: {out['flag']}")
        return 0
    print(f"[-] no flag: {out}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
