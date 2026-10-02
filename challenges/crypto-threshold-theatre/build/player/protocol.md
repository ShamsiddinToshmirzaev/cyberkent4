# Threshold Theatre — API

HTTP + JSON. Address in `samples/instance_public.json`.

## Scheme

Two-party ECDSA over P-256. The group key is `Y = (d1 + d2)·G`; you hold `d1`, the
server holds `d2`. Signatures over a movie title `m` verify as ordinary ECDSA under `Y`
with hash `z = SHA256(m) mod n`.

Paillier (additively homomorphic) carries the tablet's online input: encrypt a value `t`
under the server's public key `paillier_n` (from `/info`) as
`Enc(t) = (1 + t·N)·r^N mod N²`.

## Endpoints

### `GET /info`
`{ paillier_n, group_pubkey:{x,y}, curve:{name,n}, forbidden_movie, protocol }`

### `POST /sign-round`  `{ "ciphertext": "<hex Paillier ciphertext>" }`
The server decrypts your input `t`, computes `(d2 - t) mod N`, and runs the online range
check. Returns `{status:"continue"}` or `{status:"abort", reason:...}`. The preprocessing
is reused across aborted rounds.

### `POST /authorize`  `{ "movie", "r", "s" }`
If `movie` is the forbidden title and `(r, s)` is a valid ECDSA signature over it under
`Y`, returns `{status:"authorized", flag}`; otherwise `{status:"denied"}`.
