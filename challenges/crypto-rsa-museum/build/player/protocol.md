# RSA Museum — API

HTTP + JSON. Address in `samples/instance_public.json`.

## Scheme

RSA-2048 signatures using **CRT** signing and **EMSA-PSS** (SHA-256, salt length 32). The
signed message for an artifact is `CERT|<artifact>`. Verification is standard PSS under the
public `(n, e)` from `/info`.

## The glitch

`/sign` takes a `glitch` integer — a supply-voltage offset. At `glitch = 0` the HSM signs
correctly. In a certain (undisclosed) band the CRT recombination occasionally faults; above a
brown-out threshold the HSM halts and returns no signature.

## Endpoints

### `GET /info`
`{ id, rsa{n,e,bits}, signature_scheme, cert_rule, forbidden_artifact, note }`

### `POST /sign`  `{ "artifact": "<str>", "glitch": <int> }`
Returns `{ status:"signed", artifact, signature:"<hex>" }`, or `{status:"refused"}` for the
interlocked artifact, or `{status:"halted"}` if the glitch trips the brown-out latch.

### `POST /issue`  `{ "artifact", "signature" }`
Verifies the PSS signature over `CERT|artifact`. If valid **and** the artifact is interlocked,
returns `{status:"issued", flag}`; a valid normal artifact returns `{status:"issued"}` without
a flag; anything else is `rejected`.
