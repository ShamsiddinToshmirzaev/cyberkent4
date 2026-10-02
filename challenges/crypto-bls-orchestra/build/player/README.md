# BLS Orchestra

> The Orchestra DAO approves each concert setlist with a BLS aggregate signature
> from its committee. Every member key is registered with a **weight** and an
> **instrument section**; an approval passes when the tallied weight of a valid
> aggregate reaches the threshold. There are two ways in: the modern `/enroll`
> (which demands a proof of possession) and a dusty `/legacy/import` left over from
> the "v1 migration" (which… doesn't).
>
> You'd like to approve an encore that no founder would ever sign:
> **`THE ROGUE SYMPHONY`**.

You get a client, and the full public registry is served at `GET /info` (member
public keys, sections, weights, the threshold, the hash-to-curve domain tags, and
the target encore).

## Goal

Make `POST /approve` return the flag: a valid aggregate signature over
`THE ROGUE SYMPHONY` whose tallied weight meets the threshold.

## What you have

| file | what it is |
|------|-----------|
| `protocol.md` | the HTTP API + the exact signature/hash scheme |
| `client/client.py` | a thin client (`info`, `legacy_import`, `enroll`, `approve`) |
| `samples/instance_public.json` | where to connect (everything public is at `/info`) |

## Rules of the house

- BLS12-381, minimal-pubkey-size: public keys in G1 (48-byte compressed), signatures
  in G2 (96-byte compressed). Same-message aggregate: `apk = Σ pk_i`, `asig = Σ sig_i`,
  verify `e(apk, H(m)) == e(G1, asig)`.
- The server hashes the encore **title** itself; you never supply `H(m)`.
- Every registered point is subgroup-checked and the identity is rejected; encodings
  must be canonical.
- The private keys never leave the members (and the honest ones were discarded after
  setup) — the flag is the approval capability, not a key.

Bring your own BLS12-381 library. Two things are worth staring at: how a key gets
*registered*, and how a vote gets *weighed*.
