# Challenge archetype templates

These are the parameterized skeletons `./ctfctl new <slug> --archetype <name>` copies from.
Each is a **complete, runnable placeholder** (the flag is disclosed trivially so a fresh scaffold
builds and `ctfctl test`-passes out of the box); the author then replaces the placeholder app +
`solution/smoke_test.py` with the real challenge.

| archetype | stack | when to use |
|-----------|-------|-------------|
| `python` | hardened `python:3.12-slim` Flask, `read_only`+non-root+`cap_drop:ALL`, port 5000 | any self-written app challenge (default) |
| `lamp-php` | `php:8.2-apache`, LAMP hardening exceptions, port 80, no DB | PHP/Apache challenge without a database |
| `lamp-db` | `php:8.2-apache` + in-container MariaDB, port 80, DB never host-published | PHP challenge that needs a database (SQLi, etc.) |

Multi-service challenges (a stock CMS + separate DB + one-shot installer, e.g. WordPress or
Joomla) are bespoke — copy `challenges/web-joombreaker/` or `challenges/web-silent-channel/` as a
reference rather than scaffolding from a template.

## Placeholders substituted by `ctfctl new`
`__SLUG__`, `__CATEGORY__`, `__PORT__`, `__IMAGE__`, `__DIFFICULTY__` — filled in across
`challenge.yml`, `.env`, `.env.example`, and the source files. The `docker-compose.yml` uses the
runtime `${...}` vars from `.env` and needs no substitution.

## Invariants every template keeps (enforced by `ctfctl lint`)
- `name: ${CTF_SLUG}`, the `json-file` logging anchor, `no-new-privileges`, `restart: unless-stopped`,
  `ctf.task/category/port` labels, a healthcheck, `deploy.resources.limits`, host-side `"${HOST_PORT}:..."`.
- Flag is **never baked** — injected from `flags.env` at runtime; the LAMP templates write it to a
  non-web-served file the app reads (robust regardless of mod_php `getenv`). DB creds come from `db.env`.
- `stateful ⟺ reset.policy: scheduled`; fully-hardened ⟺ `hardening_exceptions: []`; LAMP ⟺ the
  `["read_only","user","cap_drop"]` exceptions.

> `docs/challenge-template/` is the author-facing copy of the `python` archetype (what external
> authors receive). Keep the two in sync when the python skeleton changes.
