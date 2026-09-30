# CTF 2026 — challenge fleet (context for Claude)

This file is the durable context for this repo. It is intentionally portable: if the
folder is moved, a fresh Claude session started here should be able to continue without
losing anything. Keep it updated as the source of truth for *intent and state* (the code
is the source of truth for *implementation*).

Owner: o.ruzimatov@csec.uz. This repo was migrated out of a loose `SHAMS_TASKS/` folder
of one-off challenges into a standardized, operable fleet.

## Goal & target environment (decided with the owner)
- Run these CTF challenges so participants can capture flags.
- Host: **one Docker-host VM on ESXi** (Ubuntu/Debian). Generous resources. DNS available.
- Scale: **up to 1000 players**, internet available on the event network.
- Instancing: **shared** — everyone hits the same container per task (NOT per-team).
- Addressing: **raw host ports** per task (no reverse proxy required).
- Scoreboard: **in-house built**, treated as a black box — it only needs `host:port` + flags.
- More challenges are coming; adding one must be cheap (copy `_template/`).

## Layout
```
ctfctl              # fleet manager (bash). The operational entrypoint.
Makefile            # sugar: `make up`, `make T=<slug> up`, ...
ports.csv           # CENTRAL PORT REGISTRY — single source of truth
registry/images.txt # base images to pre-pull before the event
_template/          # copy this to add a new challenge (see _template/README.md)
challenges/<slug>/  # one independent compose project per task
ops/                # reset cron, RUNBOOK.md (full event procedure), solver deps
```
Each `challenges/<slug>/`: `challenge.yml` (metadata), `docker-compose.yml`, `.env`
(non-secret, committed), `flags.env` + `db.env` (real secrets, **git-ignored**),
`*.env.example` (committed placeholders), `build/` (Dockerfile + app source),
`solution/` (intended exploit + `smoke_test.py`).

## How to operate
Each task is its own compose project (`docker compose -p <slug>`), so everything is scoped
to one task. Run from the repo root:
```
./ctfctl ports              # validate ports.csv (no dupes / no drift vs each .env)
./ctfctl up   [slug|all]    # build + start
./ctfctl down [slug|all]    # stop, keep volumes
./ctfctl reset [slug|all]   # DESTRUCTIVE: down -v + up (wipe state + re-provision)
./ctfctl build [slug|all]
./ctfctl status [slug|all]  # containers + host-port reachability
./ctfctl test  [slug|all]   # run solution/smoke_test.py against the live host_port
./ctfctl firewall           # ufw rules from ports.csv
./ctfctl scoreboard         # slug,category,endpoint,flag manifest for the scoreboard
```
Accepts multiple slugs (e.g. `./ctfctl test web-silent-channel web-joombreaker`).
Smoke tests need `requests` + `cryptography` (`pip install -r ops/requirements-solver.txt`).

## Conventions — ENFORCE for every new task
- Flag format: `CTF{...}`.
- **Never** put flags/creds in Dockerfiles, source, or image layers. Real values live only in
  git-ignored `flags.env` / `db.env`; commit `*.env.example` placeholders. Apps read `FLAG`
  from the environment.
- Every service: `restart: unless-stopped`, CPU/mem/pids limits, json-file log rotation
  (`max-size:10m max-file:3`), `no-new-privileges`, a healthcheck, and `ctf.*` labels.
- Databases go on an `internal: true` network and are **never** host-published.
- Non-root + `read_only` rootfs + `tmpfs:/tmp` for apps that tolerate it (the Python/Flask
  tasks do). LAMP images (WordPress/Joomla) can NOT — list those in `challenge.yml`
  `hardening_exceptions` and keep the rest of the hardening.
- Port ranges: web `10000–10999`, pwn `11000–11999`, crypto `12000–12999`, misc/rev `13000+`.
  Add the row to `ports.csv` first; `./ctfctl ports` must stay green.

## Current challenges (all web)
| slug | port | stateful | vuln |
|------|------|----------|------|
| web-jwtopia | 10001 | no | JWT RS256→HS256 alg-confusion + Jinja2 SSTI |
| web-silent-channel | 10002 | yes | WordPress 5.6 media-upload XXE (CVE-2021-29447) → RCE |
| web-docparser | 10003 | no | XXE → SSRF to internal :7777 |
| web-token-ghost | 10004 | no | JWT alg-confusion + SSTI |
| web-joombreaker | 10005 | yes | Joomla 4.2.6 unauth API leak (CVE-2023-23752) |
| web-intranet | 10006 | no | hidden dir + X-Forwarded-For/cookie auth bypass → LFI |
| web-neon-auth | 10007 | yes | leaked vim .swp source → SQLi LOAD_FILE (in-container MariaDB) |
| web-sql-console | 10008 | yes | SQLi WAF-bypass → hidden SQL console → LOAD_FILE (in-container MariaDB) |

Per-task specifics worth knowing:
- **web-docparser** is a single container ON PURPOSE — its exploit is XXE→SSRF to
  `127.0.0.1:7777`, so the internal service must share the app's localhost. Do not split it.
- **web-joombreaker** replaced a host-side `start.sh` (which did global `docker rm -f` and
  host `docker exec`) with an **idempotent init container** (`build/` = php:8.1-cli image that
  runs `provision.sh`). It talks to MySQL with `--skip-ssl` because the Debian mariadb client
  rejects MySQL 8's self-signed TLS cert. `build/start.sh.orig` is the old script, kept for
  reference (git-ignored via `*.orig`).
- **web-silent-channel** writes the flag at container start from `$FLAG` (perms 640
  root:www-data) via `build/flag-entrypoint.sh`; WordPress auto-installs via the `wpcli`
  one-shot (idempotent). WP 5.6 uses plain permalinks, so REST is at `/?rest_route=/`.
  Set `WP_SITE_URL` in its `.env` to the real public `host:10002` so redirects work.
- Both LAMP `db` services set `--default-authentication-plugin=mysql_native_password`.
- **web-intranet / web-neon-auth / web-sql-console** were migrated from `raw_tasks/` (git-ignored
  third-party submissions) and refitted to the template. All three are `php:8.2-apache`. neon-auth
  and sql-console are **single-container LAMP by design** (Apache+PHP+MariaDB in one image): both
  exploits end in MySQL `LOAD_FILE` reading a flag file on the app's own filesystem, so the DB can't
  be split to a separate service. MariaDB binds localhost in-container, never host-published. Flags
  come from `flags.env`; DB config from `db.env` (init.sql is envsubst-templated in the entrypoint,
  idempotent DROP/CREATE). The deliberate vuln knobs — `secure_file_priv=""`, `GRANT FILE`, and
  sql-console's empty root password — are the intended bugs, listed in each `hardening_exceptions`.
  web-intranet writes the flag only into the hidden LFI directory (no site-root `/flag.txt`).
- Entrypoints set the flag default as `FLAG="${FLAG:-}"; [ -n "$FLAG" ] || FLAG='CTF{...}'` — an
  inline `${FLAG:-CTF{...}}` default mis-parses the nested brace and appends a stray `}`.

## Operations for 1000 shared players
- Stateful tasks (silent-channel, joombreaker) get trashed by shared players → **auto-reset on
  cron** (`ops/reset.cron`): `./ctfctl reset <slug>` wipes the volume + re-provisions. Stateless
  tasks self-heal via `restart: unless-stopped`.
- Full event procedure (pre-pull images, health/canary monitoring, ESXi snapshot strategy,
  firewall) is in `ops/RUNBOOK.md`.

## Verification status
- 2026-09-28: original 5 pass end-to-end via `./ctfctl test all`; stateful resets idempotent;
  only ports 10001–10005 exposed; 3306/33060/7777 not reachable. Committed on `master`.
- 2026-09-30: added **web-intranet (10006)**, **web-neon-auth (10007)**, **web-sql-console (10008)**
  from `raw_tasks/`. All three pass `./ctfctl test`; the two stateful ones reset-then-test twice
  (idempotent). Their MariaDB 3306 is not host-reachable; only 10006–10008 published. `./ctfctl
  ports` green. NOT re-run for the original 5 in this session (their folders were untouched), and
  NOT committed.

## Outstanding decisions / TODO for the owner
- [ ] **Rotate all flags + DB passwords** — the originals were committed in the old repo, so
      they're compromised. Values now live in `flags.env`/`db.env`; regenerate before the event.
- [ ] Decide whether to run BOTH **web-jwtopia** and **web-token-ghost** — they are near-duplicate
      challenges (JWT alg-confusion + SSTI).
- [ ] Set `WP_SITE_URL` (silent-channel) and `CTF_HOST`/`ADMIN_CIDR` (`.env.global`) to real values.
- [ ] On the ESXi VM: pre-pull base images, apply the firewall, install the reset cron, take the
      "event-ready" snapshot (see RUNBOOK).
- [ ] The `solution/` scripts (intended solves) reference flag values in comments — fine for an
      internal repo, but keep the repo private and rely on flag rotation.

## For Claude working here
- Prefer editing within a task folder; keep tasks independent (no cross-task coupling).
- After changing a task, verify with `./ctfctl up <slug> && ./ctfctl test <slug>` (and for
  stateful tasks, `./ctfctl reset <slug>` then test, to prove idempotency).
- Keep this file current when intent, ports, conventions, or status change.
