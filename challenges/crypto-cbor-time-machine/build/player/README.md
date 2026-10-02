# CBOR Time Machine

> Spaceport customs runs on COSE-signed CBOR cargo badges. The **issuer** signs a
> badge only after checking your declared cargo against the permitted list. At the
> gate, **customs** verifies the issuer's signature and reads the cargo to decide
> what to admit. Same signed bytes, two offices — and, it turns out, two slightly
> different CBOR parsers.
>
> You'd like to bring in one gram of impossible **`<forbidden cargo>`** (see `/info`).

You get a client and the issuer's **public** key. The private key stays with the
issuer; the flag is the customs master token.

## Goal

Make `POST /customs` admit the forbidden target cargo and return the flag — with a
badge the issuer actually signed.

## What you have

| file | what it is |
|------|-----------|
| `protocol.md` | the API + the badge/CBOR/signature format |
| `client/client.py` | a thin client (`info`, `issue`, `customs`) |
| `samples/instance_public.json` | where to connect (public data is at `/info`) |

## Rules of the house

- The issuer refuses to sign a forbidden cargo, and signs the exact bytes you submit.
- Customs verifies a real Ed25519 signature — you cannot forge one, and you cannot
  edit the bytes after they are signed.
- Badges are CBOR maps: `{1: version, 2: holder, 3: cargo, 4: nonce}`.
- The flag is the customs capability, not a key.

Bring your own CBOR encoder. Stare at how a *map* is decoded on each side.
