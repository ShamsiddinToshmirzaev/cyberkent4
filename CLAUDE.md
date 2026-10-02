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
                    # cols: slug,category,host_port,internal_ports,image,author,notes
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
./ctfctl up/down/reset/build/status/test [slug|all] [-j N]   # lifecycle; -j runs in parallel
./ctfctl firewall           # ufw rules from ports.csv
./ctfctl scoreboard         # slug,category,endpoint,flag manifest for the scoreboard
```
Accepts multiple slugs (e.g. `./ctfctl test web-silent-channel web-joombreaker`).
Smoke tests need `requests` + `cryptography` (`pip install -r ops/requirements-solver.txt`).

Scaling/management commands (challenge.yml is the machine-read source of truth):
```
./ctfctl new <slug> [--archetype python|lamp-php|lamp-db] [--stateful]  # scaffold + auto-port + secrets
./ctfctl add <slug>         # register a conforming submission (lint -> port -> ports.csv -> secrets)
./ctfctl lint [slug|all]    # static conformance gate (also run by ops/hooks/pre-commit)
./ctfctl secrets|rotate [slug|all]   # generate / regenerate flags.env + db.env (random values)
./ctfctl gen-cron           # regenerate ops/reset.cron from challenge.yml reset.policy (don't hand-edit)
./ctfctl index [--json]     # fleet table from challenge.yml
./ctfctl capacity           # sum resource limits vs HOST_MEM_MB/HOST_CPUS (.env.global)
./ctfctl install-hooks      # git core.hooksPath -> ops/hooks
```
Archetype templates live in `templates/`; `docs/challenge-template/` is the author-facing copy of
the `python` archetype (keep in sync). The linter enforces the invariant contract, so `lint all`
must stay green.

## Conventions — ENFORCE for every new task
- Flag format: `CTF4{...}` (event-wide; changed from `CTF{...}` on 2026-10-02). The linter
  enforces `flag_format: "CTF4{...}"` and `gen_flag` emits `CTF4{<hex>}`.
- **Never** put flags/creds in Dockerfiles, source, or image layers. Real values live only in
  git-ignored `flags.env` / `db.env`; commit `*.env.example` placeholders. Apps read `FLAG`
  from the environment. (A flag-building idiom `CTF4{"+...` in source is allowed by the linter;
  a task that intentionally bakes **decoy** flags must declare `decoy_flags: true` in
  `challenge.yml` to downgrade the build/ baked-flag check to a warning.)
- Every service: `restart: unless-stopped`, CPU/mem/pids limits, json-file log rotation
  (`max-size:10m max-file:3`), `no-new-privileges`, a healthcheck, and `ctf.*` labels.
- Databases go on an `internal: true` network and are **never** host-published.
- Non-root + `read_only` rootfs + `tmpfs:/tmp` for apps that tolerate it (the Python/Flask
  tasks do). LAMP images (WordPress/Joomla) can NOT — list those in `challenge.yml`
  `hardening_exceptions` and keep the rest of the hardening.
- Port ranges: web `10000–10999`, pwn `11000–11999`, crypto `12000–12999`, misc/rev `13000+`.
  Add the row to `ports.csv` first; `./ctfctl ports` must stay green.
- Every `challenge.yml` carries an `author:` (the incident contact who can fix it live). `ctfctl
  add`/`new` copy it into the `author` column of `ports.csv`, and `./ctfctl index` shows it.

## Current challenges

### web
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
| web-metaguard | 10000 | no | SSRF chain → cloud IMDS creds → admin unlock |

### crypto (all stateless; TCP line-protocol gateways on :5000)
| slug | port | vuln |
|------|------|------|
| crypto-bls-orchestra | 12000 | BLS rogue-key aggregate-signature forgery (Rust service) |
| crypto-cbor-time-machine | 12001 | CBOR canonicalization / replay |
| crypto-chain-of-misfortune | 12002 | hash/commitment chain break |
| crypto-dilithium-drift | 12003 | Dilithium signature nonce/drift |
| crypto-entropy-cathedral | 12004 | weak entropy / PRNG recovery |
| crypto-fever-dream | 12005 | signature forgery |
| crypto-frostbite-coordinator | 12006 | FROST threshold-signing flaw |
| crypto-minerva-fm | 12007 | Minerva ECDSA timing lattice (multi-service: init+signer+gateway) |
| crypto-neon-em-oracle | 12008 | EM/side-channel oracle |
| crypto-nonce-funeral | 12009 | ECDSA nonce reuse |
| crypto-padding-choir | 12010 | padding-oracle (multi-service: init+appliance+gateway) |
| crypto-passkey-doppelganger | 12011 | WebAuthn/passkey RP-binding confusion |
| crypto-rsa-museum | 12012 | RSA misuse |
| crypto-threshold-theatre | 12013 | threshold-signature flaw |

### pwn (all stateless; binaries served on :5000)
| slug | port | vuln |
|------|------|------|
| pwn-appleseed | 11000 | house-of-apple2 _IO_FILE (FSOP) overflow |
| pwn-blindfmt | 11001 | blind format-string oracle |
| pwn-coldcache | 11002 | safe-linking shift-xor leak |
| pwn-jitterbug | 11003 | JIT spray via unblinded immediates |
| pwn-nine-lives | 11004 | fastbin dup + realloc trick |
| pwn-phantom | 11005 | sigreturn-oriented programming (SROP) |
| pwn-ring-master | 11006 | io_uring I/O-race UAF |
| pwn-singularity | 11007 | seccomp filter missing arch check |
| pwn-verifier-ex | 11008 | verifier state-merge logic bug |

### misc
| slug | port | vuln |
|------|------|------|
| misc-honeypot | 13000 | AEAD handshake beats prompt-injection decoys/banner |

Per-task specifics worth knowing:
- **_sort1 batch (24 crypto/pwn/misc + web-metaguard), added 2026-10-02** from
  `raw_tasks/_sort1/` zips. Authored against this template; two fleet fixups on intake:
  (1) their shared external `ctffleet` network was rewritten to the repo's per-task
  `frontend: driver: bridge` (the two multi-service crypto keep an `internal: true` net —
  only the gateway publishes `${HOST_PORT}:5000`); (2) ports auto-assigned via `ctfctl add`
  (NOT the submissions' `proposed_port` / `FLAGS-AND-PORTS.csv`) and flags freshly randomized
  via `ctfctl secrets` — scoreboard must re-import from `./ctfctl scoreboard`.
- Every app reads the real flag from `FLAG` env; the `CTF4{"+hmac(...)` lines in crypto
  `generate.py` are only a dev fallback (env wins). **misc-honeypot** and **web-metaguard**
  bake intentional *decoy* flags, declared via a new `decoy_flags: true` key in `challenge.yml`
  that the linter honors (downgrades the build/ baked-flag check to a warning for that task).
- Smoke tests that can't self-solve in a plain CI env (deploy fine, serve the correct flag):
  **crypto-bls-orchestra** (needs a native AVX-512/x86-64-v4 Rust helper) and
  **crypto-passkey-doppelganger** (needs the per-player credential handout, not exposed by the
  live `/info`). pwn smoke tests need `pwntools` (absent locally). Verify these on the event host.
- **web-docparser** is a single container ON PURPOSE — its exploit is XXE→SSRF to
  `127.0.0.1:7777`, so the internal service must share the app's localhost. Do not split it.
- **web-joombreaker** replaced a host-side `start.sh` (which did global `docker rm -f` and
  host `docker exec`) with an **idempotent init container** (`build/` = php:8.1-cli image that
  runs `provision.sh`). It talks to MySQL with `--skip-ssl` because the Debian mariadb client
  rejects MySQL 8's self-signed TLS cert. (The old `build/start.sh.orig` reference script was
  **deleted** — it contained a compromised real flag that `ctfctl lint` flagged.)
- **web-silent-channel** writes the flag at container start from `$FLAG` (perms 640
  root:www-data) via `build/flag-entrypoint.sh`; WordPress auto-installs via the `wpcli`
  one-shot (idempotent). WP 5.6 uses plain permalinks, so REST is at `/?rest_route=/`.
  Set `WP_SITE_URL` in its `.env` to the real public `host:10002` so redirects work.
- Both LAMP `db` services set `--default-authentication-plugin=mysql_native_password`.
- **Coupled DB creds + rotate/reset:** some `db.env` fields must hold the SAME value (silent-channel
  `MYSQL_PASSWORD`==`WORDPRESS_DB_PASSWORD`; joombreaker `MYSQL_PASSWORD`==`JOOMLA_DB_PASSWORD`==
  `CTF_DB_PASSWORD`). The example files encode this by repeating one placeholder, and `gen_dbenv`
  gives identical placeholder values the SAME generated password (so `rotate`/`secrets` keep them
  in sync). MySQL bakes its user password into the data VOLUME at first init, so after any
  `rotate`/`db.env` change a stateful DB task must be **`./ctfctl reset <slug>`** (down -v wipes the
  volume) — a plain `up` fails with `Access denied for user ...` and, because the WP/Joomla
  healthcheck then never passes, the install one-shot never runs and `up` hangs.
- **web-intranet / web-neon-auth / web-sql-console** were migrated from `raw_tasks/` (git-ignored
  third-party submissions) and refitted to the template. All three are `php:8.2-apache`. neon-auth
  and sql-console are **single-container LAMP by design** (Apache+PHP+MariaDB in one image): both
  exploits end in MySQL `LOAD_FILE` reading a flag file on the app's own filesystem, so the DB can't
  be split to a separate service. MariaDB binds localhost in-container, never host-published. Flags
  come from `flags.env`; DB config from `db.env` (init.sql is envsubst-templated in the entrypoint,
  idempotent DROP/CREATE). The deliberate vuln knobs — `secure_file_priv=""`, `GRANT FILE`, and
  sql-console's empty root password — are the intended bugs, listed in each `hardening_exceptions`.
  web-intranet writes the flag only into the hidden LFI directory (no site-root `/flag.txt`).
- Entrypoints set the flag default as `FLAG="${FLAG:-}"; [ -n "$FLAG" ] || FLAG='CTF4{...}'` — an
  inline `${FLAG:-CTF4{...}}` default mis-parses the nested brace and appends a stray `}`.

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
- 2026-09-30 (scaling): extended `ctfctl` with `new`/`add`/`lint`/`secrets`/`rotate`/`gen-cron`/
  `index`/`capacity`/`install-hooks` + `-j` parallelism; added `templates/` archetypes,
  `ops/hooks/pre-commit`, Makefile targets. `./ctfctl lint all` green on all 8 (fixed joombreaker
  image mismatch, removed the compromised `start.sh.orig`). Verified `new` (python/lamp-php/lamp-db)
  and `add` round-trips build+lint+test PASS. Not committed.

- 2026-10-02 (_sort1 batch): added 25 challenges — 14 crypto (12000–12013), 9 pwn
  (11000–11008), misc-honeypot (13000), web-metaguard (10000). `./ctfctl ports` green;
  `./ctfctl lint all` green on all 33. Patched the lint secrets-gate: allow the `CTF4{"`
  flag-building idiom + a declared `decoy_flags: true` opt-in. Networks conformed to
  `frontend` bridge. Representative python tasks verified end-to-end (healthy + correct
  flag): crypto-rsa-museum, crypto-nonce-funeral, misc-honeypot, web-metaguard PASS smoke;
  crypto-passkey-doppelganger deploys healthy (smoke needs out-of-band handout). All 25
  images built. Full build/up/smoke across rust/go/pwn deferred to the ESXi host. Not committed.

- 2026-10-02 (flag format -> CTF4): switched the whole fleet (all 33) from `CTF{...}` to
  `CTF4{...}`. `gen_flag`, the lint `flag_format` gate, and the secrets-scan regex (`CTF4?\{`)
  updated in `ctfctl`; swept `CTF{`->`CTF4{` (and regex `CTF\{`->`CTF4\{`) across all
  build/ + solution/ source, `challenge.yml`, and `flags.env.example` (150 literal + 30 regex
  sites, incl. crypto `validate.py` prefix guards, honeypot decoys + the `0x43 0x54 0x46 7B`
  byte literal -> `...0x34 0x7B`, and all solver/smoke regexes). Re-ran `ctfctl rotate all`
  (flags.env now `CTF4{...}`). `lint all` + `ports` green; rebuilt+smoked rsa-museum,
  nonce-funeral, honeypot, web-metaguard, web-jwtopia -> all PASS. Not committed.

- 2026-10-02 (authorship): recorded per-challenge authors for incident contact — Shams (first
  5 web: jwtopia, silent-channel, docparser, token-ghost, joombreaker), Falcon (intranet,
  neon-auth, sql-console), Giyosiddin (the 25 _sort1 tasks). Stored in each `challenge.yml`
  `author:` (source of truth), surfaced as a new `author` column in `ports.csv` (col 6, before
  notes — cols 1–5 unchanged so all `field()` reads still valid) and in `./ctfctl index`
  (table + `--json`). `ctfctl add`/`new` now populate the column. Not committed.

- 2026-10-02 (db-cred desync fix): `./ctfctl rotate all` (run during the CTF4 switch) had
  desynced coupled DB passwords because `gen_dbenv` randomized each `*PASSWORD` field
  independently — WordPress/Joomla then got a different password than their MySQL user, so
  `web-silent-channel` hung on `up` (wp healthcheck stuck at 500 -> wpcli installer never ran).
  Fixed `gen_dbenv` to map identical example placeholders to one shared password; regenerated
  silent-channel + joombreaker `db.env`; `reset` both (down -v to clear the stale MySQL volume).
  Both now PASS smoke. Also added the `default-address-pools` host-prep (see RUNBOOK) that this
  surfaced alongside. Not committed.

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
