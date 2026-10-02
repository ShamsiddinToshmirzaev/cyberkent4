"""Bleichenbacher (1998) adaptive-chosen-ciphertext attack against PKCS#1 v1.5.

Oracle-agnostic: `oracle(c_int) -> bool` returns whether the plaintext of c is
PKCS#1 conforming (starts 0x00 0x02). The caller supplies either a perfect
in-process oracle (tests) or the noisy timing classifier (the live solver).
"""


def _ceil(a, b):
    return -(-a // b)


def _update(M, s, n, B2, B3):
    out = set()
    for (a, b) in M:
        r_lo = _ceil(a * s - B3 + 1, n)
        r_hi = (b * s - B2) // n
        for r in range(r_lo, r_hi + 1):
            na = max(a, _ceil(B2 + r * n, s))
            nb = min(b, (B3 - 1 + r * n) // s)
            if na <= nb:
                out.add((na, nb))
    merged = []
    for (a, b) in sorted(out):
        if merged and a <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], b))
        else:
            merged.append((a, b))
    return merged


def bleichenbacher(n, e, k, c, oracle, max_queries=None, on_progress=None):
    """Recover the integer plaintext m of a *conforming* ciphertext c.

    Returns m with `pow(m,e,n)==c`. Raises RuntimeError if the query budget is hit.
    """
    B = 1 << (8 * (k - 2))
    B2, B3 = 2 * B, 3 * B
    n_q = [0]

    def O(s):
        cc = (c * pow(s, e, n)) % n
        n_q[0] += 1
        if max_queries and n_q[0] > max_queries:
            raise RuntimeError(f"query budget {max_queries} exceeded")
        return oracle(cc)

    M = [(B2, B3 - 1)]
    # step 2a: smallest s >= ceil(n/3B) that is conforming
    s = _ceil(n, B3)
    while not O(s):
        s += 1
    M = _update(M, s, n, B2, B3)

    while True:
        if len(M) > 1:                       # step 2b
            s += 1
            while not O(s):
                s += 1
        else:                                # step 2c
            (a, b) = M[0]
            if a == b:
                return a % n                 # done
            r = _ceil(2 * (b * s - B2), n)
            found = False
            while not found:
                s = _ceil(B2 + r * n, b)
                s_hi = (B3 - 1 + r * n) // a
                while s <= s_hi:
                    if O(s):
                        found = True
                        break
                    s += 1
                if not found:
                    r += 1
        M = _update(M, s, n, B2, B3)
        if on_progress:
            on_progress(n_q[0], M)
    # unreachable


def queries_estimate():
    return None
