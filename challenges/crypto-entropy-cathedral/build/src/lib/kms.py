"""Entropy Cathedral KMS key-derivation (shared by server, generator, solver).

Four "entropy sources" feed a SpongeMixer that derives a per-epoch rotation root:
  A, B : both derived from the same boot clock (a truncated source-ID collapses them,
         so together they contribute only the clock's bits — the correlation bug),
  C    : a small startup-biased value,
  D    : a full-width random source that a health check EXCLUDES on some epochs.
On an epoch where D is excluded, the seed depends only on (clock, C) — a space small
enough to enumerate against the published per-epoch root commitment.
"""
import hashlib
import hmac

CLOCK_BITS = 18      # boot-clock entropy (sources A and B collapse to this)
C_BITS = 4           # startup-biased source C


def _h(*parts):
    m = hashlib.sha256()
    for p in parts:
        m.update(p)
    return m.digest()


def derive_seed(salt, clock, c, D, epoch):
    """D is the 16-byte source-D sample, or None when the health check excluded it."""
    A = _h(salt, b"A", clock.to_bytes(3, "big"))
    B = _h(salt, b"B", clock.to_bytes(3, "big"))       # same clock as A -> correlated
    Cv = _h(salt, b"C", bytes([c & 0xFF]))
    parts = [A, B, Cv]
    if D is not None:
        parts.append(_h(salt, b"D", D))
    return _h(salt, b"".join(parts), epoch.to_bytes(2, "big"))


def derive_root(salt, clock, c, D, epoch):
    return _h(b"root", derive_seed(salt, clock, c, D, epoch))


def commitment(root, epoch):
    return _h(b"commit", root, epoch.to_bytes(2, "big"))[:10]


def ring_mac(root, epoch_bytes):
    return hmac.new(root, b"RING_THE_ENTROPY_BELL" + epoch_bytes, hashlib.sha256).digest()
