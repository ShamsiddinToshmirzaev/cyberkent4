# Fever Dream — API

HTTP + JSON. Address in `samples/instance_public.json`.

## Scheme

ECDSA over **secp128r1** (a real standardized 128-bit curve; `n ≈ 2^128`). A command
string `m` is signed as ordinary ECDSA with `z = int(sha256(m)[:16]) mod n`. Nonces are
deterministic (RFC6979-style over the key and `z`), so signing the same command twice
returns the same `(r, s)` — and the same underlying power draw, up to measurement noise.

## The module

The device has a temperature `T` (persistent across requests, starts at ambient). Each
signature raises `T`; the device cools toward ambient only while idle. A DVFS governor
scales the clock from `T`, which multiplies the reported power once `T` passes a knee. The
reported `power_uj` is therefore `work · throttle(T) · noise`, where `noise` is multiplicative
and re-drawn every call. What `work` depends on is for you to discover.

## Endpoints

### `GET /info`
`{ id, curve{name,p,a,b,n,G}, pubkey{x,y}, hash_rule, forbidden_command, note }`

### `POST /sign`  `{ "command": "<str>", "cool": <int> }`
Signs the command (deterministically) unless it is interlocked (then `{status:"refused"}`).
`cool` = idle ticks to wait before signing (lets the module cool). Returns:
`{ status:"signed", command, r:"<hex>", s:"<hex>", power_uj:<float> }`

### `POST /sign-batch`  `{ "commands": ["<str>", ...], "cool": <int> }`
A telemetry sweep: applies `cool` before each element and returns one result object per
command (`{command, r, s, power_uj}`, or `{status:"refused"}` for the interlocked one).

### `POST /command`  `{ "command", "r", "s" }`
Verifies the ECDSA signature over the command under the public key. If it verifies **and**
the command is interlocked, returns `{status:"executed", flag}`; a valid non-interlocked
command returns `{status:"executed"}` without a flag; anything else is `rejected`.
