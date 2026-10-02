"""Minimal CBOR (RFC 8949 subset) with TWO deliberately-different map resolutions.

The whole challenge is that two "reasonable" CBOR decoders disagree on a map with
a duplicate key: the issuer's parser takes the FIRST occurrence, the customs
parser takes the LAST. RFC 8949 says duplicate keys make a map invalid, but real
decoders vary — so both accept, and disagree on the value. We hand-roll it so both
behaviours are fully under our control (exactly as C02 hand-rolls two DER parsers).

Supported major types: 0 (uint), 2 (byte string), 3 (text string), 4 (array),
5 (map). Enough for a COSE-style badge.
"""


# ---- encoder --------------------------------------------------------------
def _head(mt, n):
    if n < 24:
        return bytes([(mt << 5) | n])
    if n < 0x100:
        return bytes([(mt << 5) | 24, n])
    if n < 0x10000:
        return bytes([(mt << 5) | 25]) + n.to_bytes(2, "big")
    if n < 0x100000000:
        return bytes([(mt << 5) | 26]) + n.to_bytes(4, "big")
    return bytes([(mt << 5) | 27]) + n.to_bytes(8, "big")


def enc(value):
    """Encode an int / str / bytes / list / dict canonically."""
    if isinstance(value, bool):
        raise TypeError("bool unsupported")
    if isinstance(value, int):
        if value < 0:
            raise ValueError("negints unsupported")
        return _head(0, value)
    if isinstance(value, bytes):
        return _head(2, len(value)) + value
    if isinstance(value, str):
        b = value.encode()
        return _head(3, len(b)) + b
    if isinstance(value, list):
        return _head(4, len(value)) + b"".join(enc(v) for v in value)
    if isinstance(value, dict):
        return enc_map(list(value.items()))
    raise TypeError(f"unsupported {type(value)}")


def enc_map(pairs):
    """Encode a map from a list of (key, value) pairs — DUPLICATE KEYS ALLOWED
    (that is the point). Order is preserved exactly as given."""
    return _head(5, len(pairs)) + b"".join(enc(k) + enc(v) for k, v in pairs)


# ---- decoder --------------------------------------------------------------
def _read_head(d, i):
    first = d[i]
    mt, ai = first >> 5, first & 0x1F
    i += 1
    if ai < 24:
        return mt, ai, i
    if ai == 24:
        return mt, d[i], i + 1
    if ai == 25:
        return mt, int.from_bytes(d[i:i + 2], "big"), i + 2
    if ai == 26:
        return mt, int.from_bytes(d[i:i + 4], "big"), i + 4
    if ai == 27:
        return mt, int.from_bytes(d[i:i + 8], "big"), i + 8
    raise ValueError("unsupported additional info")


def _decode(d, i):
    mt, val, i = _read_head(d, i)
    if mt == 0:
        return val, i
    if mt == 2:
        return d[i:i + val], i + val
    if mt == 3:
        return d[i:i + val].decode("utf-8", "replace"), i + val
    if mt == 4:
        arr = []
        for _ in range(val):
            x, i = _decode(d, i)
            arr.append(x)
        return arr, i
    if mt == 5:
        pairs = []
        for _ in range(val):
            k, i = _decode(d, i)
            v, i = _decode(d, i)
            pairs.append((k, v))
        return pairs, i          # a map decodes to a LIST OF PAIRS (keeps duplicates)
    raise ValueError(f"unsupported major type {mt}")


def decode_pairs(data):
    """Top-level must be a map; returns its (key, value) pairs in order."""
    val, _ = _decode(data, 0)
    if not isinstance(val, list) or (val and not isinstance(val[0], tuple)):
        raise ValueError("top-level is not a map")
    return val


def first_wins(data):
    """Issuer semantics: first occurrence of each key wins."""
    d = {}
    for k, v in decode_pairs(data):
        if k not in d:
            d[k] = v
    return d


def last_wins(data):
    """Customs semantics: last occurrence of each key wins."""
    d = {}
    for k, v in decode_pairs(data):
        d[k] = v
    return d
