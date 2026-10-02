# Neon EM Oracle — API

HTTP + JSON. Address in `samples/instance_public.json`.

## Scheme

The booth runs **AES-128** over a caller-supplied 16-byte challenge block under a fixed
secret key. A **token** for a command is `tag = AES-CMAC(booth_key, command_utf8)`
(RFC 4493). Restricted commands are never tokenised by the booth.

## The side channel

Each `/mint` returns an **EM trace**: a short vector of samples. The trace amplitude at a
fixed (per-booth) offset carries the leakage of the AES **round-1 S-box** outputs — one
contribution per key byte, `∝ HammingWeight(SBox(plaintext[i] ⊕ key[i]))` — buried under
additive noise. Each trace also starts with a large **trigger spike**, but is shifted by a
small random timing **jitter**, so traces must be aligned on the trigger before they can be
compared. Nothing about the offset, jitter, or noise level is disclosed.

## Endpoints

### `GET /info`
`{ id, cipher, trace_len, leak_hint, tag_scheme, forbidden_command, note }`

### `POST /mint`  `{ "plaintext": "<32 hex chars>" }`
Returns `{ status:"minted", trace:[<float>, ...] }` of length `trace_len`. No ciphertext.

### `POST /mint-batch`  `{ "plaintexts": ["<hex16>", ...] }`
Returns `{ status:"minted", traces:[[...], ...] }`, one trace per plaintext.

### `POST /redeem`  `{ "command", "tag" }`
Verifies `tag == AES-CMAC(booth_key, command)`. If valid **and** the command is restricted,
returns `{ status:"redeemed", flag }`; a valid normal command returns `{ status:"redeemed" }`
without a flag; anything else is `rejected`.
