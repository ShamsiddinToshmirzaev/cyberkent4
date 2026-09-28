# CTF 2026 — challenge fleet

Standardized deployment for the CTF web challenges on a single Docker host (ESXi VM).
Every challenge is an independent `docker compose` project managed by `./ctfctl`.

## Layout
```
ctfctl              # fleet manager (up/down/reset/status/test/ports/firewall/scoreboard)
Makefile            # `make up`, `make T=<slug> up`, ...
ports.csv           # central port registry (single source of truth)
registry/images.txt # base images to pre-pull
_template/          # copy this to add a new challenge
challenges/<slug>/  # one folder per task
ops/                # reset cron, runbook, solver deps
```

## Quick start
```bash
cp .env.global.example .env.global      # set CTF_HOST, ADMIN_CIDR
# per task: create the real secrets (git-ignored)
for d in challenges/*/; do
  [ -f "$d/flags.env.example" ] && cp -n "$d/flags.env.example" "$d/flags.env"
  [ -f "$d/db.env.example" ]    && cp -n "$d/db.env.example"    "$d/db.env"
done
# ...edit each flags.env / db.env with real values...

./ctfctl ports          # validate registry
./ctfctl up all         # build + start everything
./ctfctl status all
./ctfctl test all       # end-to-end smoke tests
```

## Challenges & ports
| slug | port | category | stateful | vuln |
|------|------|----------|----------|------|
| web-jwtopia | 10001 | web | no | JWT alg-confusion + SSTI |
| web-silent-channel | 10002 | web | yes | WP 5.6 media XXE (CVE-2021-29447) → RCE |
| web-docparser | 10003 | web | no | XXE → SSRF (internal :7777) |
| web-token-ghost | 10004 | web | no | JWT alg-confusion + SSTI |
| web-joombreaker | 10005 | web | yes | Joomla CVE-2023-23752 unauth API leak |

## Rules of the road
- **Flags/creds never in git or images.** Real values live in `flags.env` / `db.env`
  (git-ignored); `.example` files document the shape. Flag format: `CTF{...}`.
- Add a task by copying `_template/` — see `_template/README.md`.
- Stateful tasks auto-reset on a cron (`ops/reset.cron`) because instances are shared.
- Full operational procedure: `ops/RUNBOOK.md`.

> The original task folders (`../1.web_jwtopia_web`, etc.) are left untouched as a backup.
