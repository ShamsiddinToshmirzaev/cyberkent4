#!/usr/bin/env python3
"""Sanity-check a generated instance: RSA is consistent, the sample ticket
decrypts to a genuine guest session, and required fields are present."""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "src", "lib"))
import der    # noqa: E402
import pkcs   # noqa: E402


def validate(path):
    inst = json.load(open(path))
    errs = []
    for key in ("rsa", "issuer_tag", "flag", "allowlist_roles", "archive_role",
                "params", "net", "sample"):
        if key not in inst:
            errs.append(f"missing top-level key {key!r}")
    r = inst["rsa"]
    n, e, d, p, q, k = (int(r["n"], 16), r["e"], int(r["d"], 16),
                        int(r["p"], 16), int(r["q"], 16), r["k"])
    if p * q != n:
        errs.append("n != p*q")
    if (e * d) % ((p - 1) * (q - 1) // __import__("math").gcd(p - 1, q - 1)) != 1:
        errs.append("e*d != 1 mod lcm(p-1,q-1)")
    if (n.bit_length() + 7) // 8 != k:
        errs.append("k inconsistent with n")

    # sample ticket must decrypt to a genuine guest session
    c = int(inst["sample"]["ciphertext_hex"], 16)
    em = pkcs.i2osp(pow(c, d, n), k)
    m = pkcs.pkcs1v15_unpad_type2(em)
    if m is None:
        errs.append("sample ticket is not PKCS#1 conforming")
    else:
        s = der.session_first_wins(m)
        if not s or s.get("role") != "guest":
            errs.append("sample session role != guest")
        if not s or s.get("issuer_tag") != bytes.fromhex(inst["issuer_tag"]):
            errs.append("sample issuerTag mismatch")
    if inst["archive_role"] in inst["allowlist_roles"]:
        errs.append("archive_role must NOT be in the appliance allowlist "
                    "(else the differential is unnecessary)")
    if not inst["flag"].startswith("CTF4{"):
        errs.append("flag format")

    if errs:
        print("[validate] FAIL:")
        for e_ in errs:
            print("   -", e_)
        return False
    print(f"[validate] ok  (bits={r['bits']} k={k} profile={inst['profile']} seed={inst['seed']})")
    return True


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "instance", "state", "instance.json")
    sys.exit(0 if validate(path) else 1)
