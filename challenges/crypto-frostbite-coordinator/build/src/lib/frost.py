"""FROST-style threshold Schnorr over P-256 (built on the reused p256.py).

Schnorr: secret x, public Y = x*G. Signature (R, z) over msg verifies iff
    z*G == R + c*Y,   c = H(R, Y, msg).
Threshold: x is Shamir-shared (t of n); a signing set S combines partial responses
    z_i = r_i + c*lambda_i(S)*x_i,   R = sum_i (D_i + rho_i*E_i),   r_i = d_i + rho_i*e_i.

The INTENDED bug lives in this challenge's coordinator, not here: the binding factor
rho is computed over the signer SET only (not the commitments), and the per-signature
nonce is not consumed until a final commit — together they let a coordinator obtain
two partial responses on the same r_i under different challenges and solve for x_i.
"""
import hashlib

import p256

Q = p256.N


# ---- group helpers (affine points as (x, y); None = identity) ----
def G_mul(k):
    return p256.scalar_mult(k % Q)


def pt_mul(k, P):
    return p256.scalar_mult(k % Q, P)


def pt_add(P, Q_):
    if P is None:
        return Q_
    if Q_ is None:
        return P
    return p256._to_affine(p256._add((P[0], P[1], 1), (Q_[0], Q_[1], 1)))


def enc_point(P):
    if P is None:
        return b"\x00" * 64
    return P[0].to_bytes(32, "big") + P[1].to_bytes(32, "big")


def on_curve(P):
    if P is None:
        return False
    x, y = P
    if not (0 <= x < p256.P and 0 <= y < p256.P):
        return False
    return (y * y - (x * x * x + p256.A * x + p256.B)) % p256.P == 0


def _h(*parts):
    m = hashlib.sha256()
    for p in parts:
        m.update(len(p).to_bytes(4, "big"))
        m.update(p)
    return int.from_bytes(m.digest(), "big") % Q


def canon_set(S):
    return b",".join(str(int(j)).encode() for j in sorted(S))


def challenge(R, Y, msg):
    return _h(b"FROST-chal", enc_point(R), enc_point(Y), msg)


def rho(i, msg, S):
    # BUG (as used by the coordinator): binds only (i, msg, set) — NOT the commitments.
    return _h(b"FROST-rho", int(i).to_bytes(4, "big"), msg, canon_set(S))


def lagrange0(i, S):
    """Lagrange coefficient for participant i in set S, evaluated at 0."""
    num, den = 1, 1
    for j in S:
        if j == i:
            continue
        num = num * (-j) % Q
        den = den * (i - j) % Q
    return num * pow(den, -1, Q) % Q


# ---- Shamir (t-of-n) over the scalar field ----
def shamir_share(secret, t, n, rng):
    coeffs = [secret] + [rng.randrange(1, Q) for _ in range(t - 1)]
    def f(x):
        acc = 0
        for c in reversed(coeffs):
            acc = (acc * x + c) % Q
        return acc
    return {i: f(i) for i in range(1, n + 1)}


def reconstruct(shares_dict):
    S = list(shares_dict)
    x = 0
    for i in S:
        x = (x + lagrange0(i, S) * shares_dict[i]) % Q
    return x


# ---- plain Schnorr (for the forgery once x is recovered) ----
def schnorr_sign(x, Y, msg, k):
    R = G_mul(k)
    c = challenge(R, Y, msg)
    z = (k + c * x) % Q
    return R, z


def schnorr_verify(Y, msg, R, z):
    c = challenge(R, Y, msg)
    return G_mul(z) == pt_add(R, pt_mul(c, Y))


# ---- one signer's partial response, as the (buggy) coordinator would obtain it ----
def partial(d_i, e_i, i, x_i, S, msg, B, Y):
    """B is the coordinator-supplied commitment list [(j, Dj, Ej), ...]."""
    rho_i = rho(i, msg, S)
    r_i = (d_i + rho_i * e_i) % Q
    R = None
    for (j, Dj, Ej) in B:
        R = pt_add(R, pt_add(Dj, pt_mul(rho(j, msg, S), Ej)))
    c = challenge(R, Y, msg)
    z_i = (r_i + c * lagrange0(i, S) * x_i) % Q
    return z_i, c, R
