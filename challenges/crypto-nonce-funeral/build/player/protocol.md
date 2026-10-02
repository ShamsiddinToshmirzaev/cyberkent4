# Nonce Funeral — API

HTTP + JSON. Address in `samples/instance_public.json`.

## Signing

ECDSA over **P-256** (curve order `n` in `/info`). A track is signed over
`z = SHA256("release-v1|track:" + track_id)  (mod n)`, returning `(r, s)` as hex.

## Endpoints

### `GET /info`
`{ pubkey:{x,y}, curve:{name,n}, target_track, message_format,
   maintenance:{ reboot_window, reboot_cooldown, checkpoint } }`

### `POST /sign`  `{ "track": "<id>" }`
Signs the track and returns `{ status:"signed", r, s }`. The unreleased
`target_track` is refused (`status:"rejected"`).

### `POST /maintenance`  `{}`
Reboots the signer if at least `reboot_cooldown` signatures have been made since the
last reboot; returns `{ status:"rebooted" }` or `{ status:"cooldown", ... }`.

### `POST /release`  `{ "track": "<id>", "r": "<hex>", "s": "<hex>" }`
If the track is the target and the signature verifies under the public key, returns
`{ status:"released", credential:"MASTER_RELEASE", flag }`; otherwise `{status:"denied"}`.

## Checkpoint note

See `samples/checkpoint_format.md`. After a reboot, the signing context is restored
from its checkpoint before the next `reboot_window` signatures are produced.
