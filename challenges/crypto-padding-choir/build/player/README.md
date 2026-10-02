# Padding Choir

> Vienna, some years from now. Nobody can switch off the old opera-house signing
> appliance — the *"Maria Callas 2047 season"* keys live on it and nowhere else.
> So the ops team did the sensible thing and bolted a shiny API gateway in front
> of the 20-year-old box. The gateway is very careful to give the same polite
> refusal to everyone.
>
> Somewhere in the archive is a sealed record of a performance that, officially,
> never happened. You'd like the backstage token that opens it.

You are given a client that can talk to the gateway, the appliance's **public**
RSA key, and one ordinary **guest** ticket (an encrypted session blob). Every
rejected request comes back as an identical `403 AUTH FAILED`.

## Goal

Get the gateway to hand you the sealed **"Phantom Performance"** archive record.
Concretely: obtain a `200 ARCHIVE …` response containing the flag.

## What you have

| file | what it is |
|------|-----------|
| `protocol.md` | the wire protocol |
| `client/client.py` | a reference client (measures round-trip time, too) |
| `samples/public_key.pem` | the appliance's public RSA key |
| `samples/instance_public.json` | `n`, `e`, `k`, gateway address, query budget |
| `samples/sample_ticket.hex` | one legitimately-issued **guest** session, encrypted |

## Rules of the house

- All failures are one uniform `403`. The gateway will not tell you *why*.
- There is a generous but finite global query budget (`STATS` shows it).
- The RSA private key never leaves the appliance. You are not meant to factor
  anything — `n` is a real modulus.
- The flag is a capability the archive hands out, not a key you print.

Good luck. Listen closely.
