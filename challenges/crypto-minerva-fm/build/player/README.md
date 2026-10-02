# Minerva FM

> Radio Minerva 13.37 FM signs every track manifest with its DRM key before the
> stream goes out. The signer is careful — constant-time scalar math, the works —
> and it flatly refuses to sign anything for the pirate "ghost-dj" midnight slot.
> But the old normalization code in front of the signer was never quite so careful
> about *how long* it takes.

You can ask the signer to sign ordinary manifests as much as you like, and the
client tells you exactly how long each one took. You have the DRM **public** key.

## Goal

Get the station to accept a signed **ghost-dj** broadcast manifest:

```
{"station":"13.37","role":"ghost-dj"}
```

i.e. `SUBMIT` a valid signature over that exact manifest and receive the flag.
The honest signer will never sign it for you.

## What you have

| file | what it is |
|------|-----------|
| `protocol.md` | the wire protocol |
| `client/client.py` | a client that returns `(r, s, round_trip_time)` per signature |
| `samples/instance_public.json` | DRM public key, curve order `n`, the target manifest, gateway address |

## Rules of the house

- The signer refuses any manifest containing the privileged tokens.
- Signing times are noisy; a single measurement barely tells you anything.
- The DRM private key never leaves the signer, and `n` is a real 256-bit order —
  you are not meant to brute-force or rho the key.
- The flag is the broadcast capability, not a key you print.

Listen to the timing. Some signatures are faster than others for a reason.
