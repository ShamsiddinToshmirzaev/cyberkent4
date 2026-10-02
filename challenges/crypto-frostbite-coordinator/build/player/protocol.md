# Frostbite Coordinator — API

HTTP + JSON. Address in `samples/instance_public.json`. Points are `{x,y}` hex; scalars
are hex. Curve is P-256 (order `n` in `/info`).

## Scheme

Group public key `Y = x·G`. A Schnorr signature `(R, z)` over `msg` verifies iff
`z·G == R + c·Y` with `c = H(R, Y, msg)`. The secret `x` is Shamir-shared 3-of-5; a
signing set `S` combines partial responses:

```
rho_i = H("FROST-rho" | i | msg | sorted(S))          # binding factor
r_i   = d_i + rho_i·e_i                                # d_i,e_i are the signer's nonce
R     = Σ_{(j,D,E) in B} (D + rho_j·E)                 # group commitment from B
c     = H("FROST-chal" | R | Y | msg)
z_i   = r_i + c·lambda_i(S)·x_i                        # lambda_i = Lagrange coeff at 0
```
(`H(...)` is SHA-256 of the length-prefixed parts, reduced mod n.)

## Endpoints

### `GET /info`
`{ group_pubkey, signers, threshold, curve, forbidden_message, protocol, hashes }`

### `POST /round1`  `{ session_id, target }`
Commits a fresh nonce for signer `target`; returns its commitment `{ D, E }`.

### `POST /round2`  `{ session_id, target, set, msg, B }`
`B` is the commitment list `[{j, D, E}, ...]` (coordinator-supplied). Returns the
target's partial response `{ z, c, R }`. The forbidden message is refused.

### `POST /commit`  `{ session_id }`
Finalises the session (consumes its nonces).

### `POST /open`  `{ R, z }`
If `(R, z)` is a valid signature over the forbidden message, returns the flag.
