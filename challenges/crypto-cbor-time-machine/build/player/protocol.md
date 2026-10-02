# CBOR Time Machine — API

HTTP + JSON. Address in `samples/instance_public.json`.

## Badge format

A badge is a **CBOR map** (RFC 8949, major type 5) with integer keys:

| key | field | type |
|-----|-------|------|
| 1 | version | uint |
| 2 | holder  | text |
| 3 | cargo   | text |
| 4 | nonce   | text |

The issuer signs the **raw CBOR bytes** with **Ed25519** (COSE-style detached
signature). Customs verifies that signature over the same raw bytes.

## Endpoints

### `GET /info`
`{ issuer_pubkey (32-byte hex Ed25519), allowed_cargo:[...], forbidden_target_cargo,
   badge_schema }`

### `POST /issue`  `{ "badge_hex": "<hex CBOR map>" }`
Decodes the badge, checks the cargo is permitted, and (if so) returns
`{ status:"signed", cargo_seen, signature:"<hex>" }`. A forbidden cargo is
`{ status:"rejected" }`. The signature is over the exact bytes you submitted.

### `POST /customs`  `{ "badge_hex": "<hex CBOR map>", "signature": "<hex>" }`
Verifies the Ed25519 signature over `badge_hex`; on failure `{ status:"denied" }`.
On success it reads the cargo and returns `{ status:"cleared", cargo }` — unless the
cargo is the forbidden target, in which case it returns
`{ status:"impossible_cargo_admitted", credential:"CUSTOMS_MASTER", flag }`.

## Note

Both offices accept CBOR maps that a strict encoder would never emit. RFC 8949 calls
a map with a duplicate key invalid, but decoders in the wild resolve it differently.
