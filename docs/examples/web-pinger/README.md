# Example challenge — `web-pinger` (OS command injection)

This is a **complete, runnable, compliant** challenge. It's the same task the handbook walks
through step by step in `../../CREATING-A-CHALLENGE.md`, Section 8 — here it's on disk so you can
build it, solve it, and copy it as the starting point for your own challenge.

**The vuln:** a network-diagnostics page shells out to `ping -c 1 <host>` with the `host`
parameter concatenated straight into the command. Injecting `; printenv FLAG` prints the flag,
which the app reads from the environment (never baked into the image). The intended flag is
`CTF4{n3ver_sh3ll_out_with_user_1nput}`.

## Run it

```bash
# 1. Create the real flag (flags.env is never shared/committed).
cp flags.env.example flags.env
echo 'FLAG=CTF4{n3ver_sh3ll_out_with_user_1nput}' > flags.env

# 2. Build + start (serves on http://127.0.0.1:10010).
docker compose up --build -d

# 3. Run the intended solve (needs `pip install requests`).
TARGET=http://127.0.0.1:10010 FLAGS_ENV="$PWD/flags.env" python3 solution/smoke_test.py
#   -> [captured] 'CTF4{n3ver_sh3ll_out_with_user_1nput}'
#   -> PASS

# 4. Stop it, and don't leave a real flag lying around.
docker compose down
rm -f flags.env
```

## Use it as a starting point

```bash
cp -r examples/web-pinger web-mytask     # from the docs/ root
```

Then replace `build/app.py` with your own vulnerability, rewrite `solution/smoke_test.py` to
solve *your* bug, and update `challenge.yml` / `.env`. Everything else (the hardened
`docker-compose.yml`, the Dockerfile shape, the secret handling) is already correct — keep it.

See `../../CREATING-A-CHALLENGE.md` for the full handbook and the submission checklist.
