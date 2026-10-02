# Passkey Doppelganger — API

HTTP + JSON. Address in `samples/instance_public.json`.

## Assertion format (CTAP-style, CBOR)

A CBOR map with integer keys:

| key | field | type |
|-----|-------|------|
| 1 | credentialId | byte string |
| 2 | authenticatorData | byte string |
| 3 | signature | byte string — raw `r‖s`, 64 bytes (ES256/P-256) |
| 4 | clientDataJSON | byte string |

`authenticatorData = rpIdHash(32) ‖ flags(1) ‖ signCount(4 BE)`, `flags` with the
user-presence bit `0x01` set.
`clientDataJSON = {"type":"webauthn.get","challenge":"<b64url>","origin":"https://<host>"}`.
The signed message is `authenticatorData ‖ SHA256(clientDataJSON)`; the ES256
signature is ECDSA/P-256 over its SHA-256, encoded as raw `r‖s`.

## Endpoints

### `GET /info`
`{ rp_id, privileged_profile, credentials:[{cred_id, rp_id, account, profile}],
   assertion_format, authData }`

### `GET /challenge`
`{ challenge }` — a fresh, single-use base64url nonce to place in `clientDataJSON`.

### `POST /authenticate`  `{ "assertion_hex": "<hex CBOR>" }`
Verifies the assertion (rpIdHash matches the credential's rpId, fresh challenge,
origin is a registrable-suffix of the rpId, valid signature) and resolves a profile
from the origin. Returns `{status:"authenticated", account, profile}` — or, for the
privileged profile, `{status:"authenticated", credential:"STAGE_MANAGER", flag}`.
