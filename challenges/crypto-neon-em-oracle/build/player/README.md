# Neon EM Oracle

> The arcade's prize booth mints tokens by running AES-128 over a challenge block under its
> secret booth key. A cracked shielding can means the booth leaks: every mint hands you back
> the **EM trace** of the operation "for calibration". Tokens for restricted commands (see
> `/info`) are never issued — but a token is just an AES-CMAC tag under the booth key.
>
> The traces are noisy and never quite line up. One clean trace tells you nothing.

## Goal

Get `POST /redeem` to accept a **valid AES-CMAC token over the forbidden command** and
return the flag. The booth will never mint that token, so you must recover the booth key
from the EM side channel and forge it.

## What you have

| file | what it is |
|------|-----------|
| `protocol.md` | the API + the leak/tag description |
| `client/client.py` | a client (`info`, `mint`, `redeem`) |
| `samples/instance_public.json` | where to connect |

## House rules

- `/mint {plaintext}` (16-byte hex) returns the EM `trace` of that AES operation — and
  nothing else (no ciphertext). `/mint-batch` sweeps many at once.
- Every trace starts with a trigger spike, but each is shifted by a little timing jitter.
- `/redeem {command, tag}` spends a token; `tag = AES-CMAC(booth_key, command)`. The
  forbidden command with a valid tag -> flag.
- The booth key and flag never leave the server; the flag is the token **capability**.

A single trace is mostly noise. Think about what the trace amplitude correlates with in the
*first round* of AES, and how many aligned traces you need to see it.
