"""Hidden Number Problem solver for ECDSA with short nonces.

Each signature (r, s, z) with a nonce bounded by `bound` (0 <= k < bound) gives
    k = u + t*d  (mod n),   t = r/s,  u = z/s,   with k small.
Stacking m of them into a lattice and LLL-reducing exposes the short vector
    (k_0, ..., k_{m-1},  d*bound/n,  bound),
from which the private key d falls out. `pub_check(d)` filters candidates.
"""
from fractions import Fraction as Fr

from lll import lll


def recover_d(sigs, n, bound, pub_check=None):
    m = len(sigs)
    t, u = [], []
    for (r, s, z) in sigs:
        si = pow(s, -1, n)
        t.append(si * r % n)
        u.append(si * z % n)

    B = Fr(bound)
    M = [[Fr(0)] * (m + 2) for _ in range(m + 2)]
    for i in range(m):
        M[i][i] = Fr(n)
    M[m] = [Fr(t[i]) for i in range(m)] + [B / Fr(n), Fr(0)]
    M[m + 1] = [Fr(u[i]) for i in range(m)] + [Fr(0), B]

    reduced = lll(M)
    cands = set()
    for row in reduced:
        last = row[m + 1]
        if last != 0:
            d = int((row[m] / last) * n) % n     # d/n = row[m]/row[last]
            cands.add(d)
            cands.add((-d) % n)
        # also try reading d directly from the d-column against the bound scale
        if row[m] != 0:
            d2 = int(row[m] * n / B) % n
            cands.add(d2)
            cands.add((-d2) % n)
    if pub_check is None:
        return cands
    for d in cands:
        if 0 < d < n and pub_check(d):
            return d
    return None
