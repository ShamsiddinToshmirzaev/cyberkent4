# Event runbook

## One-time VM setup (Ubuntu/Debian on ESXi)
1. Install Docker Engine + compose plugin: `curl -fsSL https://get.docker.com | sh`.
2. Put this repo at `/opt/ctf/ctf-2026` (matches `ops/reset.cron`).
3. `cp .env.global.example .env.global` and set `CTF_HOST` (public IP/DNS) and `ADMIN_CIDR`.
4. Generate all secrets in one shot: `./ctfctl secrets all` creates any missing `flags.env`/`db.env`
   with random values; `./ctfctl rotate all` regenerates them (do this once at setup —
   **it rotates every flag/password that was ever committed to the old repo**). Review any
   challenge-specific values (e.g. an intentionally-empty DB password) afterwards.
5. Put `/var/lib/docker` on a sized, monitored disk.
6. `python3 -m pip install -r ops/requirements-solver.txt` (for smoke tests).

## Pre-event (do this before players connect)
1. Pre-pull base images so event day doesn't depend on live registry:
   `xargs -a registry/images.txt -I{} docker pull {}`
2. `./ctfctl lint all`         # conformance gate — must be green before anything else
3. `./ctfctl ports`            # no dupes / no drift
4. `./ctfctl capacity`         # fleet memory/CPU limits vs host budget — resolve any warning first
5. `./ctfctl gen-cron`         # regenerate ops/reset.cron from challenge.yml (after all challenges added)
6. `./ctfctl build all -j4`    # parallel build (raise -j on a big host; ~50 images take a while)
7. `./ctfctl up all -j4`
9. `./ctfctl status all`       # all healthy; then verify only registry ports listen:
   `ss -ltnp` — only the published `host_port`s present; the internal MySQLs/7777 NOT host-reachable.
10. `./ctfctl test all -j4`     # every task PASS (flag capturable end-to-end)
11. Reset each stateful task then re-test twice to prove idempotent re-provision, e.g.
    `./ctfctl reset web-neon-auth && ./ctfctl test web-neon-auth`.
12. Firewall: `./ctfctl firewall > /tmp/fw.sh` — review, then `sudo bash /tmp/fw.sh`.
13. Install the reset cron: `crontab -u ctf ops/reset.cron` and `mkdir -p /var/log/ctf`.
14. **Take the "event-ready" ESXi snapshot now.** Take another right before opening.

## During the event
- Monitoring: cron `./ctfctl status all` for health; `./ctfctl test all` every 15–30 min as a
  canary (also catches "flag deleted, reset not yet run").
- One task wedged: `./ctfctl reset <slug>` (seconds; does not touch other tasks).
- Whole VM wedged/compromised: roll back to the event-ready ESXi snapshot.
- Give the scoreboard its endpoints + flags: `./ctfctl scoreboard`.

## After the event
- Consolidate ESXi snapshot chains (delta growth hurts perf if left).
- Rotate any exposed secrets before reuse.

## Notes / known deviations
- WordPress & Joomla tiers cannot run `read_only`/non-root/`cap_drop: ALL` (LAMP entrypoints
  need a writable rootfs and default caps). They keep `no-new-privileges`, limits, log rotation,
  and internal-only DB networks. Listed in each `challenge.yml` `hardening_exceptions`.
- web-docparser stays a single container on purpose: its exploit is XXE->SSRF to
  `127.0.0.1:7777`, so the internal service must share the app's localhost.
- web-silent-channel's full XXE->RCE solve needs an attacker-hosted DTD; the smoke test only
  checks liveness + provisioning. The full chain lives in its `solution/` scripts.
- web-jwtopia and web-token-ghost are near-duplicate challenges (JWT alg-confusion + SSTI).
  Decide whether to run both.
- Set each web app's public URL where it matters: `web-silent-channel/.env` `WP_SITE_URL`
  should be the real `http://<host>:10002` so WordPress redirects work.
