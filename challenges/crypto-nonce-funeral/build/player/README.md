# Nonce Funeral

> The record label signs every track manifest with ECDSA. Their engineers are proud
> of it — "randomness is dead, long live deterministic nonces" — and the pipeline
> never repeats a nonce. Unfortunately the nonce is also *half*-dead: every
> maintenance reboot restores the signing context from a checkpoint that was, let's
> say, cut a little short.
>
> The label refuses to sign the unreleased album **`0xDEADBEAT`**. You want it out.

You get a client, the label's **public** key, and a note on the checkpoint format.

## Goal

Get `POST /release` to accept a valid signature over track `0xDEADBEAT` and return
the flag. The signer will never sign it for you.

## What you have

| file | what it is |
|------|-----------|
| `protocol.md` | the API + signing/message format |
| `client/client.py` | a client (`info`, `sign`, `maintenance`, `release`) |
| `samples/checkpoint_format.md` | partial source: the NonceContext checkpoint layout |
| `samples/instance_public.json` | where to connect (public data at `/info`) |

## Rules of the house

- Nonces are never repeated — the classic "same r twice" attack does not exist here.
- `/maintenance` reboots the signer, but only once every so many signatures (`/info`).
- The private key never leaves the signer; `n` is a real P-256 order (no brute force).
- The flag is the release capability, not the key.

Deterministic isn't the same as *correctly serialized*. Look at what a reboot does
to the next few signatures.
