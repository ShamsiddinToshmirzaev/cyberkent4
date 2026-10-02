# Dilithium Drift

> The bootloader signing authority migrated to post-quantum **ML-DSA (Dilithium)** after
> the last scare. It signs firmware manifests on request and flatly refuses the ones on
> the deny list. To satisfy the auditors, every signature now ships with a **QA
> "nonce-drift report"** — a few live readings that prove the masking RNG isn't stuck.
>
> The lattice maths is textbook-solid. The telemetry, on the other hand, was bolted on by
> a different team.

You want the authority's signature on the forbidden manifest (see `/info`) — the one the
signer will never produce for you.

## Goal

Get `POST /publish` to accept a **valid ML-DSA signature over the forbidden manifest** and
return the flag. There is no honest way to have it signed, so you must recover the signing
key and forge.

## What you have

| file | what it is |
|------|-----------|
| `protocol.md` | the API + the scheme (textbook ML-DSA) |
| `client/client.py` | a client (`info`, `sign`, `publish`) |
| `samples/instance_public.json` | where to connect |

## House rules

- The public key `(rho, t)` is in `/info`; `A = ExpandA(rho)` and `t = A·s1 + s2`.
- `/sign {firmware}` returns `(cseed, z)` and a `qa_drift` report; the signer refuses the
  forbidden manifest.
- `/publish {firmware, cseed, z}` verifies and, for the forbidden manifest, returns the flag.
- The secret key never leaves the server; the flag is the signing **capability**.

Dilithium's security rests on the masking vector `y` staying secret. Read the drift report
carefully, and remember `z = y + c·s1`.
