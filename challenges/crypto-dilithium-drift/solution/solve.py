#!/usr/bin/env python3
"""C12 "Dilithium Drift" reference solver.

1. GET /info -> public key (rho, t) and the forbidden manifest.
2. POST /sign on many distinct manifests. Each response carries a QA drift report whose
   "lane_levels" are the raw masking coefficients y[j][lane]. Since z = y + c*s1, each
   monitored lane gives a linear equation  (c*s1_j)[lane] = z_j[lane] - y_j[lane]  (mod q).
3. The map s1_j |-> (c*s1_j)[i] is linear with public (negacyclic) coefficients from c,
   and the monitored lane set is the same across components, so one Gaussian elimination
   mod q (with L right-hand sides) recovers every s1_j exactly.
4. Recover s2 = t - A*s1, giving the full secret key, then sign the forbidden manifest
   and POST /publish -> flag.
"""
import json
import os
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, "src", "lib"))
import mldsa  # noqa: E402
from mldsa import N, Q, K, L  # noqa: E402


def _url(net):
    return f"http://{net['gateway_host']}:{net['gateway_port']}"


def _get(base, path):
    with urllib.request.urlopen(base + path, timeout=30) as r:
        return json.load(r)


def _post(base, path, obj):
    data = json.dumps(obj).encode()
    req = urllib.request.Request(base + path, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def conv_row(c, i):
    """Coefficients of s (length N) in (c*s)[i] for the negacyclic ring Z_q[X]/(X^N+1)."""
    row = [0] * N
    for a in range(N):
        d = i - a
        row[a] = c[d] % Q if d >= 0 else (-c[N + d]) % Q
    return row


def solve_mod_q(rows, rhs_cols):
    """Solve rows @ x = rhs (mod q) for each column of rhs. Returns (solutions, rank)."""
    m = len(rows)
    nc = len(rhs_cols)
    A = [list(rows[i]) + [rhs_cols[c][i] for c in range(nc)] for i in range(m)]
    r = 0
    piv = [-1] * N
    for col in range(N):
        sel = next((i for i in range(r, m) if A[i][col] % Q != 0), -1)
        if sel < 0:
            continue
        A[r], A[sel] = A[sel], A[r]
        inv = pow(A[r][col], Q - 2, Q)
        A[r] = [(x * inv) % Q for x in A[r]]
        for i in range(m):
            if i != r and A[i][col] % Q != 0:
                f = A[i][col]
                A[i] = [(A[i][k] - f * A[r][k]) % Q for k in range(N + nc)]
        piv[col] = r
        r += 1
        if r == m:
            break
    sols = [[0] * N for _ in range(nc)]
    for col in range(N):
        if piv[col] >= 0:
            for c in range(nc):
                sols[c][col] = A[piv[col]][N + c]
    return sols, r


def solve_once(inst_path=None):
    inst_path = inst_path or os.environ.get(
        "INSTANCE", os.path.join(ROOT, "instance", "state", "instance.json"))
    net = json.load(open(inst_path))["net"]
    base = _url(net)

    info = _get(base, "/info")
    forbidden = info["forbidden_firmware"]
    # Rebuild the public key object from public parameters (rho -> A, t as given).
    A = mldsa.expand_A(bytes.fromhex(info["rho"]))
    t = [[int(x) % Q for x in p] for p in info["t"]]
    pk = {"A": A, "t": t, "rho": bytes.fromhex(info["rho"])}

    # 1) collect signatures + drift reports until the linear system is full rank
    rows, rhs = [], [[] for _ in range(L)]
    lanes = None
    n = 0
    while True:
        resp = _post(base, "/sign", {"firmware": f"build-{n}"})
        n += 1
        if resp.get("status") != "signed":
            continue
        c = mldsa.sample_in_ball(bytes.fromhex(resp["cseed"]))
        z = [[int(x) % Q for x in p] for p in resp["z"]]
        drift = resp["qa_drift"]
        lanes = drift["lanes"]
        levels = drift["lane_levels"]
        for k, i in enumerate(lanes):
            rows.append(conv_row(c, i))
            for j in range(L):
                rhs[j].append((z[j][i] - int(levels[j][k])) % Q)
        if len(rows) >= N + 2 * len(lanes):  # comfortable margin over N unknowns
            sols, rank = solve_mod_q(rows, rhs)
            if rank == N:
                break
        if n > 200:
            raise RuntimeError("failed to reach full rank")

    s1 = [[x % Q for x in sols[j]] for j in range(L)]
    # 2) s2 = t - A*s1
    As1 = mldsa._mv(A, s1)
    s2 = [mldsa.vsub(t[i], As1[i]) for i in range(K)]

    # 3) forge: sign the forbidden manifest with the recovered key. The signing seed
    #    'key' only picks which nonce is tried first, so any 32 bytes yield a fresh
    #    valid signature once s1/s2 are known.
    forged = {"A": A, "t": t, "rho": pk["rho"], "s1": s1, "s2": s2, "key": b"\x00" * 32}
    mu = b"C12-firmware|" + forbidden.encode()
    fsig = mldsa.sign(forged, mu)
    assert mldsa.verify(pk, mu, {"cseed": fsig["cseed"], "z": fsig["z"]}), "local verify failed"

    out = _post(base, "/publish", {"firmware": forbidden,
                                   "cseed": fsig["cseed"].hex(),
                                   "z": [list(p) for p in fsig["z"]]})
    return out, n


def main():
    t0 = time.time()
    out, n = solve_once()
    dt = time.time() - t0
    if out.get("flag"):
        print(f"[+] recovered key from {n} signatures in {dt:.1f}s")
        print(f"[+] FLAG: {out['flag']}")
        return 0
    print(f"[-] no flag: {out}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
