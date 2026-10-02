# Frostbite Coordinator

> Five frozen kings jointly sign every withdrawal from the ice-castle treasury —
> a 3-of-5 FROST threshold. You get to play the coordinator: you drive the signing
> rounds. One of the kings keeps forgetting whether he already signed, and the
> binding ritual isn't quite as binding as it should be.
>
> Behind the last door is the treasury. The wall reads: **OPEN_ICE_VAULT**. The kings
> flatly refuse to sign those words.

You get a client and the group's **public** key. The shares never leave the kings;
the flag is the vault-open capability.

## Goal

Get `POST /open` to accept a valid group Schnorr signature over `OPEN_ICE_VAULT` and
return the flag. No honest signing session will produce it.

## What you have

| file | what it is |
|------|-----------|
| `protocol.md` | the FROST-style protocol + the Schnorr/hash definitions |
| `client/client.py` | a client (`info`, `round1`, `round2`, `commit`, `open`) |
| `samples/instance_public.json` | where to connect (public data at `/info`) |

## Rules of the house

- P-256 Schnorr; `(R, z)` verifies iff `z·G == R + c·Y`, `c = H(R, Y, msg)`.
- `round1` commits a nonce for a signer; `round2` returns that signer's partial
  response; `commit` finalises; `open` checks a full signature.
- The kings refuse to sign `OPEN_ICE_VAULT`; the shares and flag never leave the server.

Two things reward a close read: when a committed nonce stops being usable, and what the
binding factor actually commits to versus what the challenge does.
