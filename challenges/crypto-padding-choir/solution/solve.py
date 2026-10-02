#!/usr/bin/env python3
"""C02 full reference solver (author-side) — proves the challenge is solvable
using ONLY player-visible information (public key, sample ticket, the gateway).

Pipeline:
  1. calibrate a noisy padding oracle from the response-latency side channel,
     using min-of-K RTT (robust to the additive log-normal network jitter);
  2. Bleichenbacher-decrypt the sample ticket -> recover the secret issuerTag;
  3. forge a duplicate-[0]-role session (appliance sees "guest", policy's
     last-wins canonicaliser sees "archivist") -> import -> open archive -> flag.
"""
import argparse
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, "src", "lib"))
sys.path.insert(0, os.path.join(ROOT, "player", "client"))
sys.path.insert(0, HERE)
import der      # noqa: E402
import pkcs     # noqa: E402
from client import Client               # noqa: E402
from bleichenbacher import bleichenbacher  # noqa: E402


class TimingOracle:
    """min-of-K padding oracle over the latency channel. Conforming (00 02)
    blocks pay a fixed extra canonicalisation cost, so their min RTT sits above a
    threshold that fast (non-conforming) blocks fall below within a sample or two."""
    def __init__(self, cli, n, e, k, kmax=16):
        self.cli, self.n, self.e, self.k = cli, n, e, k
        self.kmax = kmax
        self.tau = None
        self.queries = 0

    def _measure(self, c_int):
        ct = pkcs.i2osp(c_int % self.n, self.k)
        _, rtt = self.cli.import_session(ct)
        self.queries += 1
        return rtt

    def _floor(self, xs, pct=0.01):
        xs = sorted(xs)
        return xs[max(0, int(len(xs) * pct))]

    def _validate(self, conf, nonc):
        good = sum(1 for c in conf if self(c) is True)
        good += sum(1 for c in nonc if self(c) is False)
        return good / (len(conf) + len(nonc))

    def calibrate(self, probes=80, rounds=5):
        import math
        conf = [pkcs.os2ip(pkcs.encrypt(os.urandom(8), self.e, self.n, self.k))
                for _ in range(probes)]
        nonc = [1 + (pkcs.os2ip(os.urandom(self.k)) % (self.n - 2)) for _ in range(probes)]
        cs, ns = [], []
        for _ in range(rounds):
            cs += [self._measure(c) for c in conf]   # conforming -> slow path
            ns += [self._measure(c) for c in nonc]   # non-conforming -> fast path
        fast_floor = self._floor(ns)                 # ~ base latency
        slow_floor = self._floor(cs)                 # ~ base + fixed work
        gap = slow_floor - fast_floor
        if gap <= 20e-6:
            raise RuntimeError(f"latency gap too small ({gap*1e3:.3f}ms) to build an oracle")

        # place tau inside the gap; size kmax so a non-conforming probe reliably
        # produces at least one sub-tau sample.
        best = None
        for frac_pos in (0.40, 0.32, 0.25):
            tau = fast_floor + frac_pos * gap
            below = sum(1 for x in ns if x < tau) / len(ns)
            below = min(max(below, 1e-3), 0.999)
            kmax = min(80, max(8, int(math.ceil(math.log(0.001) / math.log(1 - below))) + 3))
            self.tau, self.kmax = tau, kmax
            acc = self._validate(conf[:40], nonc[:40])
            if best is None or acc > best[0]:
                best = (acc, tau, kmax, fast_floor, slow_floor, gap)
            if acc >= 0.995:
                break
        acc, tau, kmax, ff, sf, gap = best
        self.tau, self.kmax = tau, kmax
        if acc < 0.98:
            raise RuntimeError(f"oracle accuracy only {acc:.3f} (gap={gap*1e3:.3f}ms)")
        return dict(kmax=kmax, tau_ms=tau * 1e3, fast_ms=ff * 1e3, slow_ms=sf * 1e3,
                    gap_ms=gap * 1e3, cal_acc=acc)

    def __call__(self, c_int):
        """True == conforming (00 02). Early-stops as soon as a fast sample proves
        non-conformance (min only decreases)."""
        m = None
        for _ in range(self.kmax):
            r = self._measure(c_int)
            m = r if m is None else min(m, r)
            if m < self.tau:
                return False
        return True


def solve_once(samples_dir, max_queries=4_000_000, verbose=True):
    """Run the whole attack against a live instance; return (flag, stats).
    Reusable by the CI test suite as well as the CLI."""
    def log(*a):
        if verbose:
            print(*a, flush=True)

    info = json.load(open(os.path.join(samples_dir, "instance_public.json")))
    n, e, k = int(info["n"], 16), info["e"], info["k"]
    host, port = info["gateway_host"], info["gateway_port"]
    c0 = int(open(os.path.join(samples_dir, "sample_ticket.hex")).read().strip(), 16)

    cli = Client(host, port)
    oracle = TimingOracle(cli, n, e, k)

    log("[*] calibrating latency oracle ...")
    cal = oracle.calibrate()
    log(f"    kmax={cal['kmax']} tau={cal['tau_ms']:.3f}ms fast={cal['fast_ms']:.3f}ms "
        f"slow={cal['slow_ms']:.3f}ms gap={cal['gap_ms']:.3f}ms cal_acc={cal['cal_acc']:.3f}")

    t0 = time.time()
    last = [0]

    def prog(q, M):
        if q - last[0] >= 2000:
            last[0] = q
            log(f"    ... {q} oracle decisions, {len(M)} interval(s)")

    log("[*] running Bleichenbacher on the sample ticket ...")
    m = bleichenbacher(n, e, k, c0, oracle, max_queries=max_queries, on_progress=prog)
    if pow(m, e, n) != c0:
        raise RuntimeError("BB result does not verify")
    payload = pkcs.pkcs1v15_unpad_type2(pkcs.i2osp(m, k))
    sess = der.session_first_wins(payload)
    issuer = sess["issuer_tag"]
    log(f"[+] recovered plaintext in {time.time()-t0:.1f}s, {oracle.queries} total queries")
    log(f"    role={sess['role']} seat={sess['seat']} issuerTag={issuer.hex()}")

    log("[*] forging duplicate-role archivist session ...")
    forged = der.build_session(1, issuer, ["guest", "archivist"], sess["seat"])
    line, _ = cli.import_session(pkcs.encrypt(forged, e, n, k))
    txt = line.decode(errors="replace")
    log(f"    import -> {txt}")
    if "SESSION" not in txt:
        raise RuntimeError("forgery rejected — differential failed")
    handle = txt.split("SESSION", 1)[1].split()[0]
    line, _ = cli.use_session(handle.encode(), b"OPEN_ARCHIVE")
    txt = line.decode(errors="replace")
    log(f"    open   -> {txt}")
    cli.close()
    if "flag{" in txt:
        flag = txt[txt.index("flag{"):txt.index("}", txt.index("flag{")) + 1]
        log(f"\n[+] FLAG: {flag}")
        return flag, {"queries": oracle.queries, "cal": cal}
    raise RuntimeError("archive did not return a flag")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--samples-dir", default=os.path.join(ROOT, "player", "samples"))
    ap.add_argument("--max-queries", type=int, default=4_000_000)
    args = ap.parse_args()
    try:
        solve_once(args.samples_dir, args.max_queries, verbose=True)
        return 0
    except Exception as ex:
        print(f"[-] solve failed: {ex}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
