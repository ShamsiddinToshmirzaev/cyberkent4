# Adding a new challenge

1. Copy this folder: `cp -r _template challenges/<category>-<slug>`
2. Add a row to `ports.csv` with a unique `host_port` (web 10000–10999, pwn 11000–11999,
   crypto 12000–12999, misc/rev 13000+).
3. Edit `challenge.yml`, `.env` (copy from `.env.example`), and put the app in `build/`.
4. Create the real flag: `cp flags.env.example flags.env` and set `FLAG=CTF4{...}`.
   `flags.env` is git-ignored — never commit it.
5. Implement `solution/smoke_test.py` so it captures the flag via the intended path.
6. Validate: `./ctfctl ports && ./ctfctl up <slug> && ./ctfctl test <slug>`.

## Conventions
- Flag format: `CTF4{...}` (lowercase inner text, snake_case).
- Never bake flags/creds into Dockerfiles, source, or images — inject via `flags.env` / `db.env`.
- Every service gets: `restart: unless-stopped`, resource limits, log rotation,
  `no-new-privileges`, `cap_drop: ALL`, a healthcheck, and `ctf.*` labels.
- Put any database on an `internal: true` network; never publish its port.
- Stateful tasks (`stateful: true`, `reset.policy: scheduled`) go on the reset cron in ops/.
