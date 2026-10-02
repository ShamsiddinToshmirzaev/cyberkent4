# Dilithium Drift — API

HTTP + JSON. Address in `samples/instance_public.json`.

## Scheme (textbook ML-DSA / Dilithium)

Fiat-Shamir with aborts over Module-LWE, ML-DSA-44-style parameters
(`n=256`, `q=8380417`, `k=l=4`, `eta=2`, `tau=39`, `gamma1=2^17`, `gamma2=(q-1)/88`,
`beta=tau*eta`). Ring `R_q = Z_q[X]/(X^256+1)`.

- **Public key**: `rho` (seed for the matrix `A = ExpandA(rho)`, shape `k×l`) and `t`
  (`k` polynomials). Uncompressed: `t = A·s1 + s2`.
- **Secret key**: short vectors `s1` (`l` polys) and `s2` (`k` polys), coefficients in
  `[-eta, eta]`.
- **Sign(mu)**: sample masking `y` (coeffs in `(-gamma1, gamma1]`); `w = A·y`;
  `c = SampleInBall(H(mu ‖ HighBits(w)))` (sparse ±1, `tau` nonzero); `z = y + c·s1`;
  rejection-sample on the norms of `z` and `LowBits(w - c·s2)`. Signature `= (cseed, z)`
  where `cseed = H(mu ‖ HighBits(w))`.
- **Verify(mu, cseed, z)**: recompute `c = SampleInBall(cseed)`, check `‖z‖∞` is small, and
  accept iff `H(mu ‖ HighBits(A·z - c·t)) == cseed`. (Works because
  `A·z - c·t = A·y - c·s2 = w - c·s2`, whose HighBits equal HighBits(w).)

Signed message for a firmware manifest: `mu = b"C12-firmware|" + firmware_name`.

## Endpoints

### `GET /info`
`{ id, scheme, params, rho, t, forbidden_firmware, message_rule }`

### `POST /sign`  `{ "firmware": "<name>" }`
Signs the manifest (deterministically) unless it is the forbidden one (then
`{status:"refused"}`). On success:
```
{ "status":"signed", "firmware", "cseed":"<hex>", "z":[[...],...],
  "qa_drift": { "lanes":[i0,i1,...], "lane_levels":[[...],[...],[...],[...]] } }
```
`qa_drift.lane_levels[j]` are the per-component QA readings on the monitored `lanes`.

### `POST /publish`  `{ "firmware", "cseed", "z" }`
Verifies the signature over `mu = "C12-firmware|"+firmware`. If it verifies **and** the
manifest is the forbidden one, returns `{status:"published", flag}`; a valid non-target
signature returns `{status:"published"}` without a flag; anything else is `rejected`.
