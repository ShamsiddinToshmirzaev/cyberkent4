# Challenge starter template

This folder is a complete, runnable challenge skeleton. Copy it, rename it to your slug,
and build your challenge inside the copy. Full instructions are in
`../CREATING-A-CHALLENGE.md` — read that first.

Quick version:

```bash
cp -r challenge-template web-mytask       # slug = <category>-<name>, kebab-case
cd web-mytask
cp .env.example .env                      # then edit HOST_PORT + slug/image
cp flags.env.example flags.env            # then set the REAL flag; do NOT share this file
# ... build your app in build/, write the exploit in solution/smoke_test.py ...

docker compose up --build                 # starts on http://127.0.0.1:<HOST_PORT>
# in another shell:
TARGET=http://127.0.0.1:<HOST_PORT> FLAGS_ENV="$PWD/flags.env" python3 solution/smoke_test.py
```

When `smoke_test.py` prints `PASS`, zip the folder **without `flags.env`** (send the real
flag separately) and hand it back. We assign the final port and wire it into the fleet.

Files:

| File | Share it? | What it is |
|------|-----------|------------|
| `challenge.yml` | yes | Metadata for humans + the scoreboard. |
| `docker-compose.yml` | yes | How the service runs (ports, limits, hardening). |
| `.env` / `.env.example` | yes | Non-secret runtime vars. |
| `flags.env` | **no** | The real flag. Send it to us out of band. |
| `flags.env.example` | yes | Placeholder showing the shape. |
| `build/**` | yes | Your app + Dockerfile. Must contain no secrets. |
| `solution/**` | yes | The intended solve / smoke test. |
