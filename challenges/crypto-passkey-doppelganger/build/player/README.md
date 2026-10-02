# Passkey Doppelganger

> The festival runs one WebAuthn kiosk for everything: general punters sign in at
> `festival.example`, and crew sign in at `staff.festival.example`. Marketing's promise
> was "one passkey for every stage." The security team should have been more precise.
>
> You hold a **guest** passkey. You'd like to walk on as the **stage manager** and
> start the forbidden afterparty stage.

You get a client, your own passkey (its private key — you are the authenticator), and
the public registration at `GET /info`.

## Goal

Get `POST /authenticate` to resolve you to the **privileged profile** (see `/info`)
and return the flag.

## What you have

| file | what it is |
|------|-----------|
| `protocol.md` | the API + the assertion / authData / signature format |
| `client/client.py` | a client (`info`, `challenge`, `authenticate`) |
| `samples/my_credential.json` | YOUR credential: id, rpId, and private key |
| `samples/instance_public.json` | where to connect |

## Rules of the house

- You can only sign for your own credential; forging others is out (real ES256).
- The kiosk checks `authData.rpIdHash` against your credential's registered rpId, that
  the challenge is fresh, that the origin is under your rpId, and the signature.
- The private key you hold is your own authenticator — the flag is a capability, not a key.

Two questions repay attention: which relying party does the *verifier* think you are,
and which does the *account mapper* think you are?
