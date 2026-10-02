# Entropy Cathedral — API

HTTP + JSON. Address in `samples/instance_public.json`.

## Derivation (all public; SHA-256 throughout)

```
A = SHA256(salt | 'A' | clock:3B)          # clock is an 18-bit boot value
B = SHA256(salt | 'B' | clock:3B)          # SAME clock as A
C = SHA256(salt | 'C' | c:1B)              # c is a 4-bit startup source
D = SHA256(salt | 'D' | sample)            # excluded on unhealthy epochs
seed  = SHA256(salt | A|B|C[|D] | epoch:2B)
root  = SHA256('root' | seed)
commitment = SHA256('commit' | root | epoch:2B)[:10]      # published per epoch
ring_mac   = HMAC-SHA256(root, 'RING_THE_ENTROPY_BELL' | epoch_bytes)
```

## Endpoints

### `GET /info`
`{ salt, current_epoch, clock_bits, c_source_bits, root_commitments:{epoch: hex},
   derivation, ... }`

### `GET /telemetry`
`{ epochs:{epoch: {source_D_healthy: bool, mixer_lanes: 3|4, ...}} }` — the health
dashboard; an unhealthy epoch excluded source D (3 lanes).

### `POST /ring`  `{ "epoch": "<2-byte hex>", "mac": "<hex>" }`
The authoriser reads `epoch` **little-endian** and requires it to equal the current
epoch; the root lookup reads `epoch` **big-endian**. If the MAC matches that root's
`ring_mac`, returns `{status:"bell_rung", flag}`.
