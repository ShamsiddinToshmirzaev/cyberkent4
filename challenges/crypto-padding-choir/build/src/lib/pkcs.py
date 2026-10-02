"""PKCS#1 v1.5 (type 2, encryption) helpers + raw RSA, author-side.

The appliance (C++) has its own independent implementation; this Python copy is
used by the instance generator, the reference solver, and the tests.
"""
import os


def i2osp(x: int, length: int) -> bytes:
    return x.to_bytes(length, "big")


def os2ip(b: bytes) -> int:
    return int.from_bytes(b, "big")


def pkcs1v15_pad_type2(message: bytes, k: int, rng=os.urandom) -> bytes:
    """EM = 0x00 || 0x02 || PS(>=8 nonzero) || 0x00 || M , length k."""
    if len(message) > k - 11:
        raise ValueError("message too long for modulus")
    ps_len = k - 3 - len(message)
    ps = bytearray()
    while len(ps) < ps_len:                       # PS must be all-nonzero
        for b in rng(ps_len - len(ps)):
            if b != 0:
                ps.append(b)
    return b"\x00\x02" + bytes(ps[:ps_len]) + b"\x00" + message


def pkcs1v15_unpad_type2(em: bytes):
    """Return M, or None if not conforming. (Reference; the appliance re-checks
    this itself and the *timing* of that check is the oracle.)"""
    if len(em) < 11 or em[0] != 0x00 or em[1] != 0x02:
        return None
    try:
        sep = em.index(0x00, 2)
    except ValueError:
        return None
    if sep < 10:                                  # need >= 8 padding bytes
        return None
    return em[sep + 1:]


def rsa_pub(m: int, e: int, n: int) -> int:
    return pow(m, e, n)


def rsa_priv(c: int, d: int, n: int) -> int:
    return pow(c, d, n)


def encrypt(message: bytes, e: int, n: int, k: int, rng=os.urandom) -> bytes:
    """Standard PKCS#1 v1.5 public-key encryption. Anyone with (e, n) can do
    this — that is the point: the security was never in secrecy of encryption."""
    em = pkcs1v15_pad_type2(message, k, rng)
    return i2osp(rsa_pub(os2ip(em), e, n), k)
