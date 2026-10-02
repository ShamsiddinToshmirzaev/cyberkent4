# Fever Dream

> The satellite's command-authentication module signs uplinked commands with ECDSA on a
> lightweight 128-bit curve. The signing core was audited constant-time. But the bird runs
> hot: a DVFS governor scales the clock from a live power estimate, and the module only
> sheds heat while it's idle. Every `/sign` hands you back the module's **power reading**
> for that operation — "for telemetry."
>
> Interlocked commands (see `/info`) are refused outright. You want one anyway.

## Goal

Get `POST /command` to accept a **valid ECDSA signature over the forbidden command** and
return the flag. The module will never sign it for you, so you must recover the signing key
and forge.

## What you have

| file | what it is |
|------|-----------|
| `protocol.md` | the API + the scheme |
| `client/client.py` | a client (`info`, `sign`, `command`) |
| `samples/instance_public.json` | where to connect |

## House rules

- The public key and curve are in `/info`. Nonces are deterministic (a command re-signs
  identically), so you can measure the same command many times.
- `/sign {command, cool}` returns `(r, s, power)`. `cool` is the number of idle ticks to
  wait before signing. `/sign-batch {commands, cool}` sweeps many at once.
- `/command {command, r, s}` executes; the forbidden command with a valid signature -> flag.
- The private key and the module's thermal constants never leave the server; the flag is
  the command **capability**.

The power reading is noisy, and it moves with the module's temperature as much as with
anything else. A constant-time core should leak nothing — so why does the reading drift?
Ask what the number depends on once the module is *cold and quiet*.
