# Event runbook

## One-time VM setup (Ubuntu/Debian on ESXi)
1. Install Docker Engine + compose plugin: `curl -fsSL https://get.docker.com | sh`.
2. Put this repo at `/opt/ctf/ctf-2026` (matches `ops/reset.cron`).
3. `cp .env.global.example .env.global` and set `CTF_HOST` (public IP/DNS) and `ADMIN_CIDR`.
4. For each challenge: `cp <slug>/flags.env.example <slug>/flags.env` and set a real `CTF{...}` flag;
   for stateful tasks also `cp <slug>/db.env.example <slug>/db.env` and set strong creds.
   **Rotate every flag/password that was ever committed to the old repo.**
5. Put `/var/lib/docker` on a sized, monitored disk.
6. `python3 -m pip install -r ops/requirements-solver.txt` (for smoke tests).

## Pre-event (do this before players connect)
1. Pre-pull base images so event day doesn't depend on live registry:
   `xargs -a registry/images.txt -I{} docker pull {}`
2. `./ctfctl ports`            # no dupes / no drift
3. `./ctfctl build all`
4. `./ctfctl up all`
5. `./ctfctl status all`       # all healthy; then verify only registry ports listen:
   `ss -ltnp` — 10001–10005 present; 7777 and the MySQLs NOT host-reachable.
6. `./ctfctl test all`         # every task PASS (flag capturable end-to-end)
7. `./ctfctl reset web-silent-channel && ./ctfctl reset web-joombreaker`  # then re-test:
   `./ctfctl test web-silent-channel web-joombreaker`  (run twice to prove idempotent re-provision)
8. Firewall: `./ctfctl firewall > /tmp/fw.sh` — review, then `sudo bash /tmp/fw.sh`.
9. Install the reset cron: `crontab -u ctf ops/reset.cron` and `mkdir -p /var/log/ctf`.
10. **Take the "event-ready" ESXi snapshot now.** Take another right before opening.

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
