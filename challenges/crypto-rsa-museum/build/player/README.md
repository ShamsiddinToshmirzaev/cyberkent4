# RSA Museum

> The museum's provenance HSM certifies artifacts with RSA-2048 (CRT) and EMSA-PSS. It
> refuses to certify interlocked artifacts (see `/info`). It also exposes a maintenance
> "supply-voltage glitch" knob — auditors were told it's harmless.
>
> It isn't. Push the voltage into the wrong band and the CRT recombination sometimes slips.

## Goal

Get `POST /issue` to accept a **valid PSS certificate over the interlocked artifact** and
return the flag. The HSM will never sign it, so you must recover the private key and forge.

## What you have

| file | what it is |
|------|-----------|
| `protocol.md` | the API + the signature scheme |
| `client/client.py` | a client (`info`, `sign`, `issue`) |
| `samples/instance_public.json` | where to connect |

## House rules

- `/sign {artifact, glitch}` signs `CERT|artifact` (deterministically). `glitch` is a
  supply-voltage offset (0 = nominal). Interlocked artifacts are refused.
- `/issue {artifact, signature}` registers a certificate; the interlocked artifact with a
  valid PSS signature -> flag.
- The private key and flag never leave the HSM; the flag is the certificate **capability**.

Too little glitch and nothing changes; too much and the HSM latches off. Somewhere in between,
a signature comes back that doesn't verify. What can two signatures of the *same* certificate
tell you when one of them is subtly wrong?
