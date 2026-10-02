// Lenient DER/BER TLV parser for the appliance importer.
// Mirrors src/lib/der.py `session_first_wins`: first occurrence of each field
// wins. The disagreement with the gateway policy's last-wins canonicaliser is
// the intended stage-2 bug.
#pragma once
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace der {

struct TLV { uint8_t tag; const uint8_t* val; size_t len; };

inline std::vector<TLV> parse_tlvs(const uint8_t* d, size_t n) {
    std::vector<TLV> out;
    size_t i = 0;
    while (i < n) {
        uint8_t tag = d[i++];
        if (i >= n) break;
        size_t l = d[i++];
        if (l & 0x80) {
            size_t k = l & 0x7F;
            if (k == 0 || i + k > n) break;
            l = 0;
            for (size_t j = 0; j < k; j++) l = (l << 8) | d[i++];
        }
        if (i + l > n) l = n - i;          // lenient: clamp
        out.push_back({tag, d + i, l});
        i += l;
    }
    return out;
}

struct Session {
    long version = -1;
    std::vector<uint8_t> issuer;
    std::string role;
    bool have_issuer = false, have_role = false;
};

// returns false if payload is not a SEQUENCE
inline bool unwrap_first_wins(const uint8_t* p, size_t n, Session& s) {
    auto top = parse_tlvs(p, n);
    if (top.empty() || top[0].tag != 0x30) return false;
    auto f = parse_tlvs(top[0].val, top[0].len);
    for (auto& t : f) {
        if (t.tag == 0x02 && s.version < 0) {
            long v = 0;
            for (size_t j = 0; j < t.len; j++) v = (v << 8) | t.val[j];
            s.version = v;
        } else if (t.tag == 0x04 && !s.have_issuer) {
            s.issuer.assign(t.val, t.val + t.len);
            s.have_issuer = true;
        } else if (t.tag == 0x80 && !s.have_role) {   // [0] role, first wins
            s.role.assign(reinterpret_cast<const char*>(t.val), t.len);
            s.have_role = true;
        }
    }
    return true;
}

// Genuine canonicalisation cost paid on the slow (PKCS#1-conforming) path.
// It parses once (the realistic "canonicalise this structure" entry) and then
// folds the bytes in a tight, allocation-free, compute-bound loop `factor` times.
// Being compute-bound (not allocator-bound) makes the extra latency deterministic
// (min ~= median) instead of heavy-tailed, so the side channel is a fair, stable
// signal — and it is still real work, never a sleep() (design rule #4). The
// *noise* is added separately by the gateway (network model + queue contention).
inline uint64_t canonicalize_work(const uint8_t* p, size_t n, int factor) {
    auto tlvs = parse_tlvs(p, n);                       // single canonicalise pass
    uint64_t h = 1469598103934665603ULL;               // FNV-1a offset
    for (auto& t : tlvs) { h ^= t.tag; h *= 1099511628211ULL; }
    for (int r = 0; r < factor; r++) {
        for (size_t j = 0; j < n; j++) {
            h ^= p[j];
            h *= 1099511628211ULL;
            h ^= h >> 13;
        }
        h += (uint64_t)r * 2654435761ULL;
    }
    return h;
}

}  // namespace der
