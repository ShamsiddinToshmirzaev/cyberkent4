"""Minimal Paillier (additively-homomorphic) for the C08 two-party ECDSA transport.

Standard scheme with g = n+1, so Enc(m) = (1 + m*n) * r^n mod n^2. Players only need
the public key (n) to encrypt; the server holds the secret key to decrypt.
"""
import os
import random


def _is_probable_prime(x, rng, rounds=32):
    if x < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if x % p == 0:
            return x == p
    d, r = x - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = rng.randrange(2, x - 1)
        v = pow(a, d, x)
        if v in (1, x - 1):
            continue
        for _ in range(r - 1):
            v = v * v % x
            if v == x - 1:
                break
        else:
            return False
    return True


def _gen_prime(bits, rng):
    while True:
        cand = rng.getrandbits(bits) | (1 << (bits - 1)) | 1
        if _is_probable_prime(cand, rng):
            return cand


def keygen(bits=1024, rng=None):
    rng = rng or random.Random()
    half = bits // 2
    p = _gen_prime(half, rng)
    q = _gen_prime(bits - half, rng)
    while q == p:
        q = _gen_prime(bits - half, rng)
    n = p * q
    lam = (p - 1) * (q - 1) // _gcd(p - 1, q - 1)
    mu = pow(lam % n, -1, n)
    return {"n": n}, {"n": n, "lam": lam, "mu": mu}


def _gcd(a, b):
    while b:
        a, b = b, a % b
    return a


def encrypt(pk, m, r=None):
    n = pk["n"]
    n2 = n * n
    if r is None:
        r = 1 + int.from_bytes(os.urandom((n.bit_length() + 7) // 8), "big") % (n - 1)
    return ((1 + (m % n) * n) % n2) * pow(r, n, n2) % n2


def decrypt(sk, c):
    n, lam, mu = sk["n"], sk["lam"], sk["mu"]
    n2 = n * n
    u = pow(c % n2, lam, n2)
    L = (u - 1) // n
    return (L * mu) % n
