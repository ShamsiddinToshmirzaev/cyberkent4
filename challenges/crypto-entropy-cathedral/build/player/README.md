# Entropy Cathedral

> The data centre keeps a cathedral to entropy. Four "randomness bells" ring at boot
> and feed a SpongeMixer that derives each epoch's key-rotation root; three signing
> appliances hold the shares. A dashboard proudly shows the entropy health. Two of the
> bells, it turns out, are wired to the same clock — and the mixer is a little careless
> about which source is which.
>
> Ring the great bell — **RING_THE_ENTROPY_BELL** — for the *current* epoch, and the
> vault sings.

You get a client, the public per-epoch root commitments and mixer parameters
(`/info`), the source-health dashboard (`/telemetry`), and a leaked mixer source note.

## Goal

Get `POST /ring` to authorize `RING_THE_ENTROPY_BELL` for the current epoch and return
the flag.

## What you have

| file | what it is |
|------|-----------|
| `protocol.md` | the API + the derivation / commitment / MAC definitions |
| `client/client.py` | a client (`info`, `telemetry`, `ring`) |
| `samples/mixer_source.md` | partial source: the SpongeMixer + epoch versioning |
| `samples/instance_public.json` | where to connect |

## Rules of the house

- The current epoch's root is not recoverable — its entropy is full.
- Root commitments are public; the salt and derivation are public; the boot clock,
  the C source and each epoch's source-D sample are not.
- The three appliances never reveal a share; the flag is the bell capability.

Two independent sources are not four. The dashboard decides which sources reach the
mixer. And two services do not agree on how an epoch number is written down.
