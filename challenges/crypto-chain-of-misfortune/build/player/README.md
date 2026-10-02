# Chain of Misfortune

> NovaFest runs its ticketing on two chains: **MainStage** (the real one) and
> **TestStage** (a sandbox that hands out free tickets). Same code, same signer,
> "deployed at the same address on both chains." The `BACKSTAGE_ZERO` operator
> pass is minted to anyone who racks up enough **MainStage** loyalty credits — and
> MainStage tickets, of course, cost real money. You only have the free TestStage
> ones.

Tickets are EIP-712-style typed-data signatures. You get a client, the signer's
**public** key, and the public chain/domain parameters.

## Goal

Mint the `BACKSTAGE_ZERO` capability: get `POST /mint` to return the flag. That
needs `mint_threshold` **MainStage** loyalty credits for your holder address.

## What you have

| file | what it is |
|------|-----------|
| `protocol.md` | the HTTP API |
| `client/client.py` | a reference client |
| `samples/instance_public.json` | signer public key, domain, chain ids, curve order `n`, params |

## Rules of the house

- Free tickets are issued on **TestStage** only, and only a few per holder.
- MainStage tickets are not free — yet the mint only counts MainStage credits.
- The signer's private key never leaves the service; you cannot forge tickets.
- The flag is the operator capability the mint returns, not a key.

`GET /info` tells you the signer, both chains, the curve order, the type
definitions, and the credit/threshold parameters. Everything you need to
understand why a ticket is (or isn't) accepted is public.
