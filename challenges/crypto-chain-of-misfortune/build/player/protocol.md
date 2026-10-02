# Chain of Misfortune — API

HTTP + JSON. Base URL from `samples/instance_public.json`
(`gateway_host`, `gateway_port`).

## Endpoints

### `GET /info`
Public parameters: signer public key `{x,y,address}`, `domain {name,version,
verifying_contract}`, `chains {mainstage,teststage}` with their `chain_id`, the
curve `{name:"P-256", n:<hex order>}`, the EIP-712 `types` (legacy domain, modern
domain, ticket), and `params {free_budget, mint_threshold, credit_per_ticket}`.

### `POST /freeticket`  `{ "holder": "<20-byte hex address>" }`
Issues a free **TestStage** ticket to `holder` (up to `free_budget` per holder).
Returns:
```json
{ "status":"issued", "chain":"teststage",
  "ticket":{"ticket_id":1,"holder":"...","action":"ADMIT","tier":1},
  "signature":{"r":"<hex>","s":"<hex>"} }
```

### `POST /submit`  `{ "chain":"mainstage|teststage", "ticket":{...}, "signature":{"r","s"} }`
Verifies the signature for that chain and, if valid and not already seen, credits
the ticket's holder on that chain. Returns `status` ∈
`credited` (+`credits`) · `duplicate` · `rejected` · `error`.

### `GET /credits?chain=<>&holder=<>`
Current loyalty credits for a holder on a chain.

### `POST /mint`  `{ "holder": "<hex address>" }`
If the holder has `>= mint_threshold` **MainStage** credits, returns
`{ "status":"minted", "credential":"BACKSTAGE_ZERO", "flag":"flag{...}" }`;
otherwise `{ "status":"insufficient", "have":.., "need":.. }`.

## Typed-data digest (EIP-712 style, using SHA-256)

```
domainSeparator = H( H(domainType) | H(name) | H(version) | [chainId] | contract )
hashStruct      = H( H(ticketType) | ticketId | holder | H(action) | tier )   # 32-byte words
digest          = H( 0x19 0x01 | domainSeparator | hashStruct )
```
`domainType` / `ticketType` strings are in `/info`. Words are 32-byte big-endian;
addresses are left-padded to 32 bytes. The signature is ECDSA over `digest`.
