"""Exact LLL over the rationals (pure Python, no deps).

Uses the standard incrementally-maintained Gram-Schmidt (size-reduction updates mu
in place; swaps use the O(n) update formulas) so it stays fast enough for the
HNP lattices this challenge needs (dimension up to ~50). Exact Fraction arithmetic
avoids the precision failures float GSO hits on 256-bit entries."""
from fractions import Fraction as Fr


def lll(basis, delta=Fr(99, 100)):
    B = [[Fr(x) for x in row] for row in basis]
    n = len(B)

    def dot(u, v):
        return sum(a * b for a, b in zip(u, v))

    # initial Gram-Schmidt
    Bstar = [None] * n
    mu = [[Fr(0)] * n for _ in range(n)]
    Bn = [Fr(0)] * n
    for i in range(n):
        Bstar[i] = B[i][:]
        for j in range(i):
            mu[i][j] = dot(B[i], Bstar[j]) / Bn[j]
            Bstar[i] = [a - mu[i][j] * b for a, b in zip(Bstar[i], Bstar[j])]
        Bn[i] = dot(Bstar[i], Bstar[i])

    k = 1
    while k < n:
        for j in range(k - 1, -1, -1):
            if abs(mu[k][j]) > Fr(1, 2):
                q = round(mu[k][j])
                if q:
                    B[k] = [a - q * b for a, b in zip(B[k], B[j])]
                    for i in range(j):
                        mu[k][i] -= q * mu[j][i]
                    mu[k][j] -= q
        if Bn[k] >= (delta - mu[k][k - 1] ** 2) * Bn[k - 1]:
            k += 1
        else:
            mu_ = mu[k][k - 1]
            Bnew = Bn[k] + mu_ * mu_ * Bn[k - 1]
            mu[k][k - 1] = mu_ * Bn[k - 1] / Bnew
            Bn[k] = Bn[k - 1] * Bn[k] / Bnew
            Bn[k - 1] = Bnew
            B[k], B[k - 1] = B[k - 1], B[k]
            for j in range(k - 1):
                mu[k][j], mu[k - 1][j] = mu[k - 1][j], mu[k][j]
            for i in range(k + 1, n):
                t = mu[i][k]
                mu[i][k] = mu[i][k - 1] - mu_ * t
                mu[i][k - 1] = t + mu[k][k - 1] * mu[i][k]
            k = max(k - 1, 1)
    return B
