# Threshold Theatre

> Every big purchase at the studio needs two directors: the signing server and the
> director's tablet jointly authorise it with a two-party ECDSA. The maths uses
> Paillier-encrypted rehearsals and careful abort handling — except one director keeps
> reacting differently depending on whether your encrypted rehearsal was *almost* valid,
> and the studio never quite tears down a failed rehearsal.
>
> You want to greenlight the $13.37M vanity project **THE LAST NONCE**.

You are the tablet: you hold your own key share `d1` and can talk to the server. The
group key is `Y = (d1 + d2)·G`; the server's share `d2` is secret.

## Goal

Get `POST /authorize` to accept a valid ECDSA signature over `THE LAST NONCE` and return
the flag. There is no honest way to co-sign it.

## What you have

| file | what it is |
|------|-----------|
| `protocol.md` | the API + the scheme (Paillier + two-party ECDSA) |
| `client/client.py` | a client (`info`, `sign_round`, `authorize`) |
| `samples/my_share.json` | your tablet share `d1` |
| `samples/instance_public.json` | where to connect |

## Rules of the house

- `/sign-round` takes a **Paillier ciphertext** (encrypt under `paillier_n` from `/info`).
- The Paillier modulus is a real ~1024-bit modulus — factoring it is not the path.
- The server's share and Paillier secret never leave the server; the flag is the
  purchase capability.

An abort is not nothing. Ask what the range check reveals, and what survives a failed round.
