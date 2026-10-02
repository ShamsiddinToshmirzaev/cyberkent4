# CTF 2026 — challenge fleet

Operator handbook for the CTF web challenges. Every challenge is an independent
`docker compose` project on a single Docker host, managed by one script: `./ctfctl`.

- **Adding a challenge?** See the author handbook: [`docs/CREATING-A-CHALLENGE.md`](docs/CREATING-A-CHALLENGE.md).
- **Running the event?** See the runbook: [`ops/RUNBOOK.md`](ops/RUNBOOK.md).
- **Why things are the way they are?** See the durable intent doc: [`CLAUDE.md`](CLAUDE.md).

---

## What this is & why it's built this way

We run a handful of web CTF challenges for up to **~1000 players**. The deployment model was
chosen deliberately (see `CLAUDE.md` for the full rationale):

- **One Docker-host VM on ESXi** (Ubuntu/Debian). Generous resources, DNS available.
- **Shared instances** — everyone hits the *same* container per task. There is **no per-team
  copy**. This is the single most important fact about the fleet: a stateful task can be trashed
  by any player for everyone, so stateful tasks auto-reset on a cron (see below).
- **Raw host ports** per task — no reverse proxy. Task = `host:port`.
- **In-house scoreboard**, treated as a black box: it only needs `host:port` + flags, which
  `./ctfctl scoreboard` emits.
- **Cheap to extend** — adding a challenge is "copy a template, fill it in, submit".

## Repo layout

```
ctfctl               # fleet manager (bash) — the operational entrypoint
Makefile             # sugar over ctfctl: `make up`, `make T=<slug> up`, ...
ports.csv            # CENTRAL PORT REGISTRY — single source of truth for host ports
.env.global.example  # copy to .env.global: CTF_HOST + ADMIN_CIDR (sourced by ctfctl)
registry/images.txt  # base images to pre-pull before the event
_template/           # in-repo scaffold for a new challenge
challenges/<slug>/   # one independent compose project per task
docs/                # author-facing docs (handed to external challenge authors)
  CREATING-A-CHALLENGE.md   # the author handbook
  challenge-template/       # author-facing copy of the scaffold
  examples/web-pinger/      # a complete, runnable example challenge
ops/
  RUNBOOK.md               # full event procedure (VM setup → during → after)
  reset.cron               # auto-reset schedule for stateful tasks
  requirements-solver.txt  # Python deps for smoke tests (requests, cryptography)
```

> **Two scaffolds, on purpose.** `_template/` is the in-repo copy; `docs/challenge-template/` is
> the author-facing copy that ships inside the self-contained `docs/` folder we hand to external
> authors (who don't get the repo). They're equivalent — keep them in sync if you change one.

Each `challenges/<slug>/` folder:

```
challenge.yml        # metadata (name, category, host_port, stateful, reset policy, ...)
docker-compose.yml   # the service(s), fully hardened
.env                 # NON-secret runtime vars (slug, category, HOST_PORT, image tag) — committed
flags.env            # REAL flag — git-ignored, created on the host, never committed
flags.env.example    # committed placeholder
db.env / db.env.example   # DB creds (stateful tasks only); db.env git-ignored
build/               # Dockerfile + app source (COPY'd into the image; no secrets)
solution/            # smoke_test.py (the canary) + any exploit scripts
```

## Core concepts

**One compose project per task.** `ctfctl` runs `docker compose -p <slug>` from inside each
challenge folder, so everything — networks, volumes, containers — is scoped to that one task.
Resetting or rebuilding one task never touches another.

**Secrets never touch git or image layers.** The flag and any DB passwords live only in
git-ignored `flags.env` / `db.env`, injected into the container at *runtime* via `env_file`.
Committed `*.env.example` files document the shape. Apps read `FLAG` from the environment. The
`.gitignore` enforces this (`**/flags.env`, `**/db.env`, `*.pem`, `*.key`). Flag format:
`CTF4{...}` (lowercase, snake_case).

**`ports.csv` is the single source of truth for host ports.** A challenge's `.env` `HOST_PORT`
must equal its `ports.csv` row. `./ctfctl ports` fails on duplicates or drift.

**The hardening contract applies to every service** — non-root, read-only rootfs, dropped caps,
`no-new-privileges`, resource limits, log rotation, a healthcheck, `ctf.*` labels. Because
instances are shared, one popped or runaway container must not harm the host or the other tasks.
LAMP images (WordPress/Joomla) that physically can't comply declare a documented
`hardening_exceptions` list in `challenge.yml`. Full details:
[`docs/CREATING-A-CHALLENGE.md` §4](docs/CREATING-A-CHALLENGE.md).

**Stateless vs stateful.** Stateless tasks self-heal via `restart: unless-stopped`. Stateful
tasks (a DB or writable state players can trash) put their DB on an `internal: true` network
(never host-published) and auto-reset on a cron — `./ctfctl reset <slug>` wipes the volume and
re-provisions. Provisioning must be **idempotent** (one-shot init container that checks
"already installed?").

## Prerequisites & one-time setup

Local dev needs **Docker** (with the Compose v2 plugin) and **Python 3**. Full VM/event setup is
in [`ops/RUNBOOK.md`](ops/RUNBOOK.md); the essentials:

```bash
cp .env.global.example .env.global      # set CTF_HOST (public IP/DNS) and ADMIN_CIDR
# create the real, git-ignored secrets from the committed placeholders:
for d in challenges/*/; do
  [ -f "$d/flags.env.example" ] && cp -n "$d/flags.env.example" "$d/flags.env"
  [ -f "$d/db.env.example" ]    && cp -n "$d/db.env.example"    "$d/db.env"
done
# ...edit each flags.env / db.env with real values (ROTATE anything ever committed)...
python3 -m pip install -r ops/requirements-solver.txt   # deps for smoke tests
```

`.env.global` is sourced by `ctfctl`:

| Var | Default | Used by |
|-----|---------|---------|
| `CTF_HOST` | `127.0.0.1` | `ctfctl test` / `status` / `scoreboard` — the host players connect to. |
| `ADMIN_CIDR` | `10.0.0.0/24` | `ctfctl firewall` — the CIDR allowed to SSH. |

## `ctfctl` command reference

Run from the repo root. `[slug|all]` accepts one slug, several slugs, or `all` (the default when
omitted). `make` wraps each: `make <target>` or `make T=<slug> <target>`.

| Command | What it does |
|---------|--------------|
| `./ctfctl up [slug\|all] [-j N]` | Build + start detached (`compose up -d --build`). Warns if `flags.env` is missing. |
| `./ctfctl down [slug\|all]` | Stop, **keep** volumes (`compose down`). |
| `./ctfctl reset [slug\|all] [-j N]` | **DESTRUCTIVE:** `compose down -v` + `up` — wipes that task's volumes and re-provisions. Scoped to the one task. |
| `./ctfctl build [slug\|all] [-j N]` | Build images only. |
| `./ctfctl status [slug\|all]` | Table of `SLUG PORT PORTCHK CONTAINERS` — container states + host-port reachability. |
| `./ctfctl test [slug\|all] [-j N]` | Run each task's `solution/smoke_test.py` against the live host port. Any FAIL → non-zero exit. |
| `./ctfctl new <slug> [--archetype python\|lamp-php\|lamp-db] [--difficulty D] [--stateful]` | Scaffold a new challenge from a template, **auto-assigning a free port** and generating secrets. |
| `./ctfctl add <slug>` | **Register a conforming submission** already dropped in `challenges/<slug>/`: lint → assign port → `proposed_port`→`host_port` → `ports.csv` row → secrets. |
| `./ctfctl lint [slug\|all]` | Static conformance check (files, `challenge.yml` schema, coupling rules, compose invariants, secret hygiene). The submission gate. |
| `./ctfctl secrets [slug\|all]` | Create missing `flags.env`/`db.env` from `*.example` with random values (never overwrites). |
| `./ctfctl rotate [slug\|all]` | Regenerate `flags.env`/`db.env` (rotate secrets); `reset`/`up` after to apply new DB passwords. |
| `./ctfctl ports` | Validate `ports.csv`: no duplicate host ports, no `.env`↔registry drift. Must print `ports OK`. |
| `./ctfctl gen-cron` | Regenerate `ops/reset.cron` from each `challenge.yml reset.policy` (auto-staggered). Don't hand-edit the cron. |
| `./ctfctl index [--json]` | Fleet table from `challenge.yml` (name/port/category/difficulty/stateful). |
| `./ctfctl capacity` | Sum `deploy.resources.limits` across the fleet vs the host budget (`HOST_MEM_MB`/`HOST_CPUS` in `.env.global`). |
| `./ctfctl firewall` | **Print** (does not apply) `ufw` rules derived from `ports.csv` + `ADMIN_CIDR`. |
| `./ctfctl scoreboard` | Print the `slug,category,endpoint,flag` manifest for the scoreboard. |
| `./ctfctl install-hooks` | Point git at `ops/hooks` so the pre-commit hook runs `lint all` + blocks staged secrets. |

Multi-slug example: `./ctfctl test web-silent-channel web-joombreaker`. `-j N` runs
`build`/`up`/`reset`/`test` with up to N in parallel (important at fleet scale; default serial).

**Smoke-test environment.** `./ctfctl test` runs each test under `timeout 120 python3` with two
env vars — the same contract authors code against:

- `TARGET` — base URL, `http://$CTF_HOST:<host_port>`.
- `FLAGS_ENV` — path to that task's `flags.env`, so the test can read the expected flag.

## Ports & the registry

`ports.csv` columns: `slug,category,host_port,internal_ports,image,notes`. `host_port` is the
published host port; `internal_ports` are used only between/inside containers and never published
(document them, leave empty if none). Ranges by category:

| Category | Host-port range |
|----------|-----------------|
| web | 10000–10999 |
| pwn | 11000–11999 |
| crypto | 12000–12999 |
| misc / rev / forensics | 13000+ |

Add the row to `ports.csv` **before** wiring up the task, keep `.env` `HOST_PORT` in sync, and
keep `./ctfctl ports` green.

## Challenge fleet

| slug | port | category | stateful | vuln |
|------|------|----------|----------|------|
| web-jwtopia | 10001 | web | no | JWT RS256→HS256 alg-confusion + Jinja2 SSTI |
| web-silent-channel | 10002 | web | yes | WordPress 5.6 media-upload XXE (CVE-2021-29447) → RCE |
| web-docparser | 10003 | web | no | XXE → SSRF to internal `:7777` |
| web-token-ghost | 10004 | web | no | JWT alg-confusion + SSTI |
| web-joombreaker | 10005 | web | yes | Joomla 4.2.6 unauth API leak (CVE-2023-23752) |
| web-intranet | 10006 | web | no | hidden dir + `X-Forwarded-For`/cookie auth bypass → LFI |
| web-neon-auth | 10007 | web | yes | leaked vim `.swp` source → SQLi `LOAD_FILE` (in-container MariaDB) |
| web-sql-console | 10008 | web | yes | SQLi WAF-bypass → hidden SQL console → `LOAD_FILE` (in-container MariaDB) |

Per-task gotchas worth knowing:

- **web-docparser** is a single container **on purpose** — its exploit is XXE→SSRF to
  `127.0.0.1:7777`, so the internal service must share the app's localhost. Do not split it.
- **web-silent-channel** & **web-joombreaker** are stateful LAMP tasks: DB on an internal-only
  network, idempotent init container for provisioning, and on the auto-reset cron. They carry
  `hardening_exceptions` (LAMP entrypoints need a writable rootfs / default caps). silent-channel's
  full XXE→RCE needs an attacker-hosted DTD, so its smoke test checks liveness + provisioning and
  the full chain lives in `solution/`. Set its `.env` `WP_SITE_URL` to the real `http://<host>:10002`.
- **web-jwtopia** & **web-token-ghost** are near-duplicate (JWT alg-confusion + SSTI). Decide
  whether to run both.
- **web-neon-auth** & **web-sql-console** are **single-container LAMP by design** (Apache+PHP+MariaDB
  in one image): both exploits end in MySQL `LOAD_FILE` reading a flag file on the app's own
  filesystem, so the DB can't be split out. MariaDB binds localhost in-container and is never
  host-published. Both carry `hardening_exceptions` and are on the auto-reset cron. The deliberate
  `secure_file_priv=""` + `FILE`/empty-root-password weakenings are the intended vuln, documented in
  each `challenge.yml`. DB config lives in `db.env`.
- **web-intranet** is stateless (no DB). The flag is written from `flags.env` only into the hidden
  directory the intended LFI reads — there is deliberately no site-root `/flag.txt` to grab.
- These three were migrated from `raw_tasks/` (third-party submissions) and refitted to the template
  (compose, secrets externalised to `flags.env`/`db.env`, hardening, healthchecks, smoke tests).

## Adding challenges (at scale)

`challenge.yml` is the per-challenge source of truth; `ctfctl` reads it to lint, generate the
reset cron, index the fleet, and estimate capacity. Two entry points, both of which auto-assign a
free port and generate secrets so you never hand-edit `ports.csv` or copy `.example` files:

**Author a new one** (scaffolds a runnable placeholder from an archetype — see [`templates/`](templates/)):

```bash
./ctfctl new web-mytask --archetype lamp-db     # python | lamp-php | lamp-db
# edit build/ + solution/smoke_test.py to be the real challenge, then:
./ctfctl lint web-mytask && ./ctfctl up web-mytask && ./ctfctl test web-mytask
```

**Register a submission** from a task author (the common path — they send a conforming
`challenges/<slug>/` folder built per [`docs/CREATING-A-CHALLENGE.md`](docs/CREATING-A-CHALLENGE.md)):

```bash
# drop their folder into challenges/web-theirtask/ (with a proposed_port), then:
./ctfctl add web-theirtask          # lint -> assign real port -> ports.csv -> secrets -> re-lint
./ctfctl up web-theirtask && ./ctfctl test web-theirtask
```

**The gate.** `./ctfctl lint [slug|all]` statically checks the invariant contract (required files,
`challenge.yml` schema + coupling rules, compose hardening, secret hygiene). Run
`./ctfctl install-hooks` once so the pre-commit hook (`ops/hooks/pre-commit`) blocks any commit
that fails `lint all` or stages a `flags.env`/`db.env`. A complete runnable reference challenge
lives at [`docs/examples/web-pinger/`](docs/examples/web-pinger/).

**Capacity.** Before an event, `./ctfctl capacity` sums the fleet's memory/CPU limits against the
host budget (`HOST_MEM_MB`/`HOST_CPUS` in `.env.global`). This is the real ceiling at ~50 shared
challenges (many LAMP+MariaDB at ~1–1.5 GB each): if it warns, size up the VM or split across hosts.

## Operations

- **Stateful auto-reset.** `ops/reset.cron` periodically runs `./ctfctl reset <slug>` for the
  stateful tasks so shared-player damage self-heals. It is **generated** — run `./ctfctl gen-cron`
  after adding/removing challenges (it reads each `challenge.yml reset.policy`), then install with
  `crontab -u ctf ops/reset.cron`. Don't hand-edit it.
- **Monitoring / canary.** Run `./ctfctl status all` for health and `./ctfctl test all` every
  15–30 min as a canary — it catches "solvable path broke" and "flag deleted, reset not yet run".
- **Firewall.** `./ctfctl firewall > /tmp/fw.sh`, review, then `sudo bash /tmp/fw.sh`. Default
  deny in / allow out, SSH only from `ADMIN_CIDR`, one `allow <port>/tcp` per task.
- **Scoreboard.** `./ctfctl scoreboard` emits the `slug,category,endpoint,flag` manifest.
- **Recovery.** One task wedged → `./ctfctl reset <slug>` (seconds, isolated). Whole VM
  compromised → roll back to the event-ready ESXi snapshot (see `ops/RUNBOOK.md`).

## Troubleshooting

| Symptom | Likely cause / fix |
|---------|--------------------|
| `./ctfctl ports` fails | Duplicate `host_port` in `ports.csv`, or a `.env` `HOST_PORT` that doesn't match its registry row. Reconcile them. |
| Task won't start after edits | Check `docker compose -p <slug> logs`. A read-only rootfs breaks apps that write outside `/tmp` — point writes at the `/tmp` tmpfs, or (LAMP only) drop `read_only` and record it in `hardening_exceptions`. |
| Healthcheck stuck "starting"/unhealthy | The healthcheck URL/port doesn't match what the app serves. `./ctfctl status <slug>` shows container state; check the `healthcheck:` block. |
| `./ctfctl test` says missing flag / FAIL | `flags.env` absent or wrong. `up` only warns; create it from `flags.env.example`. |
| Reset leaves the task broken | Provisioning isn't idempotent — a setup step assumes a blank slate. Use a check-then-act one-shot init container. |
| A DB port is reachable from outside | A DB must be on an `internal: true` network and **not** published. Remove its host `ports:` mapping. |

## Security & outstanding TODO

Secret hygiene: real values live only in git-ignored `flags.env`/`db.env`; keep the repo private.
Open items before the event (also tracked in `CLAUDE.md`):

- [ ] **Rotate all flags + DB passwords** — the originals were committed in the old repo and are
      compromised.
- [ ] Set `WP_SITE_URL` (web-silent-channel) and `CTF_HOST` / `ADMIN_CIDR` (`.env.global`) to real
      values.
- [ ] Decide whether to run both **web-jwtopia** and **web-token-ghost** (near-duplicate).
- [ ] On the ESXi VM: pre-pull base images, apply the firewall, install the reset cron, take the
      "event-ready" snapshot.

## See also

- [`CLAUDE.md`](CLAUDE.md) — durable intent & decisions (the "why").
- [`ops/RUNBOOK.md`](ops/RUNBOOK.md) — full event procedure (VM setup → during → after).
- [`docs/CREATING-A-CHALLENGE.md`](docs/CREATING-A-CHALLENGE.md) — the challenge author handbook.
