"""Minimal P-256 (secp256r1) with ECDSA where the nonce k is caller-controlled.

No stdlib API lets you set k, and the whole challenge is about k, so we hand-roll
it. Jacobian coordinates keep it fast enough for the solver (verify a recovered
key, forge one target signature) and the tests (a few dozen signatures)."""

P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A = P - 3
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5


def inv(x, m):
    return pow(x % m, m - 2, m)


# ---- Jacobian point arithmetic (X:Y:Z), point at infinity = (1,1,0) ----
def _dbl(pt):
    X1, Y1, Z1 = pt
    if Y1 == 0:
        return (1, 1, 0)
    S = (4 * X1 * Y1 * Y1) % P
    M = (3 * X1 * X1 + A * pow(Z1, 4, P)) % P
    X3 = (M * M - 2 * S) % P
    Y3 = (M * (S - X3) - 8 * pow(Y1, 4, P)) % P
    Z3 = (2 * Y1 * Z1) % P
    return (X3, Y3, Z3)


def _add(p1, p2):
    if p1[2] == 0:
        return p2
    if p2[2] == 0:
        return p1
    X1, Y1, Z1 = p1
    X2, Y2, Z2 = p2
    Z1Z1 = Z1 * Z1 % P
    Z2Z2 = Z2 * Z2 % P
    U1 = X1 * Z2Z2 % P
    U2 = X2 * Z1Z1 % P
    S1 = Y1 * Z2 % P * Z2Z2 % P
    S2 = Y2 * Z1 % P * Z1Z1 % P
    if U1 == U2:
        if S1 != S2:
            return (1, 1, 0)
        return _dbl(p1)
    H = (U2 - U1) % P
    R = (S2 - S1) % P
    HH = H * H % P
    HHH = H * HH % P
    V = U1 * HH % P
    X3 = (R * R - HHH - 2 * V) % P
    Y3 = (R * (V - X3) - S1 * HHH) % P
    Z3 = H * Z1 % P * Z2 % P
    return (X3, Y3, Z3)


def _mul(k, pt):
    r = (1, 1, 0)
    k %= N
    while k:
        if k & 1:
            r = _add(r, pt)
        pt = _dbl(pt)
        k >>= 1
    return r


def _to_affine(pt):
    if pt[2] == 0:
        return None
    zi = inv(pt[2], P)
    zi2 = zi * zi % P
    return (pt[0] * zi2 % P, pt[1] * zi2 % P * zi % P)


G = (GX, GY, 1)


def scalar_mult(k, point_affine=None):
    pt = G if point_affine is None else (point_affine[0], point_affine[1], 1)
    return _to_affine(_mul(k, pt))


def pubkey(d):
    return scalar_mult(d)


def sign(d, z, k):
    """ECDSA with an explicit nonce k. z is the message hash reduced mod N."""
    x, _ = scalar_mult(k)
    r = x % N
    if r == 0:
        return None
    s = (inv(k, N) * (z + r * d)) % N
    if s == 0:
        return None
    return r, s


def verify(pub, z, r, s):
    if not (0 < r < N and 0 < s < N):
        return False
    w = inv(s, N)
    u1, u2 = z * w % N, r * w % N
    pt = _add(_mul(u1, G), _mul(u2, (pub[0], pub[1], 1)))
    aff = _to_affine(pt)
    if aff is None:
        return False
    return aff[0] % N == r
