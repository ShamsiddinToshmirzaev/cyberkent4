"""Minimal DER/BER TLV kit for C02 (author-side).

Deliberately tiny so BOTH parser behaviours are fully under our control:
  * `session_first_wins`  == the C++ appliance's lenient importer semantics
  * `session_last_wins`   == the gateway policy canonicaliser semantics

The disagreement between "first occurrence wins" and "last occurrence wins" for a
duplicated context-tagged field IS the intended vulnerability (stage 2). Only the
handful of tags this challenge uses are supported.

Schema (IMPLICIT context tags so `role` and `seat` never collide):

    Session ::= SEQUENCE {
        version    INTEGER,            -- 0x02
        issuerTag  OCTET STRING,       -- 0x04   (per-instance secret, 16 bytes)
        role       [0] UTF8String,     -- 0x80   ("guest"|"subscriber"|"archivist")
        seat       [1] UTF8String      -- 0x81
    }
"""

INT, OCT, SEQ, CTX0, CTX1 = 0x02, 0x04, 0x30, 0x80, 0x81


def _enc_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = []
    while n:
        body.append(n & 0xFF)
        n >>= 8
    body.reverse()
    return bytes([0x80 | len(body)]) + bytes(body)


def tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _enc_len(len(value)) + value


def enc_int(n: int) -> bytes:
    if n == 0:
        return tlv(INT, b"\x00")
    body = []
    x = n
    while x:
        body.append(x & 0xFF)
        x >>= 8
    body.reverse()
    if body[0] & 0x80:          # keep it positive
        body = [0] + body
    return tlv(INT, bytes(body))


def enc_octet(b: bytes) -> bytes:
    return tlv(OCT, b)


def enc_ctx(tag: int, s) -> bytes:
    return tlv(tag, s.encode() if isinstance(s, str) else s)


def enc_seq(items) -> bytes:
    return tlv(SEQ, b"".join(items))


def build_session(version: int, issuer_tag: bytes, role, seat: str,
                  extra=()) -> bytes:
    """`role` may be a single string, or a list of strings to emit *duplicate*
    [0] role fields (the forgery). `extra` is a list of raw TLV byte-strings
    appended verbatim, for hand-crafted layouts."""
    roles = [role] if isinstance(role, str) else list(role)
    items = [enc_int(version), enc_octet(issuer_tag)]
    if roles:
        items.append(enc_ctx(CTX0, roles[0]))
    items.append(enc_ctx(CTX1, seat))
    for r in roles[1:]:
        items.append(enc_ctx(CTX0, r))
    items.extend(extra)
    return enc_seq(items)


def parse_tlvs(data: bytes):
    """Lenient TLV scan; returns [(tag, value), ...] in order. Tolerates trailing
    bytes and clamps over-long lengths rather than raising (this leniency is
    exactly what a sloppy production parser does)."""
    out = []
    i, n = 0, len(data)
    while i < n:
        tag = data[i]; i += 1
        if i >= n:
            break
        l = data[i]; i += 1
        if l & 0x80:
            k = l & 0x7F
            if k == 0 or i + k > n:
                break
            l = int.from_bytes(data[i:i + k], "big"); i += k
        if i + l > n:
            l = n - i
        out.append((tag, data[i:i + l])); i += l
    return out


def unwrap_sequence(payload: bytes):
    t = parse_tlvs(payload)
    if not t or t[0][0] != SEQ:
        return None
    return parse_tlvs(t[0][1])


def session_first_wins(payload: bytes):
    """Appliance importer: first occurrence of each field wins."""
    fields = unwrap_sequence(payload)
    if fields is None:
        return None
    d = {}
    for tag, val in fields:
        if tag == INT and "version" not in d:
            d["version"] = int.from_bytes(val, "big")
        elif tag == OCT and "issuer_tag" not in d:
            d["issuer_tag"] = val
        elif tag == CTX0 and "role" not in d:
            d["role"] = val.decode("utf-8", "replace")
        elif tag == CTX1 and "seat" not in d:
            d["seat"] = val.decode("utf-8", "replace")
    return d


def session_last_wins(payload: bytes):
    """Policy canonicaliser: naive dict build, last occurrence wins."""
    fields = unwrap_sequence(payload)
    if fields is None:
        return None
    d = {}
    for tag, val in fields:
        if tag == INT:
            d["version"] = int.from_bytes(val, "big")
        elif tag == OCT:
            d["issuer_tag"] = val
        elif tag == CTX0:
            d["role"] = val.decode("utf-8", "replace")
        elif tag == CTX1:
            d["seat"] = val.decode("utf-8", "replace")
    return d
