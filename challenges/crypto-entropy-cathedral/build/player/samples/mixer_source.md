# SpongeMixer + epoch versioning (partial source, leaked)

Reconstructed from a config-repo commit. Two things are worth noting.

## 1. Source IDs are truncated in the mixer

```python
def absorb(state, source_id, sample):
    lane = source_id & 0x01           # <-- only the low BIT of the source id
    state[lane] ^= H(sample)
    return state
```

The boot-clock sources are registered as `id=0` ("A") and `id=2` ("B"). With
`source_id & 0x01` both map to lane 0, and both samples are derived from the same boot
clock — so A and B together contribute only the clock's bits. The startup source C is
`id=1` (lane 1); source D is `id=3` (lane 1) and is dropped when the health check
excludes it.

Boot clock is 18 bits; C is 4 bits.

## 2. Epoch numbers are versioned inconsistently

```python
# rotation store (root lookup)
epoch = int.from_bytes(epoch_bytes, "big")
...
# quorum authoriser (current-epoch gate)
if int.from_bytes(epoch_bytes, "little") != CURRENT_EPOCH:
    reject()
```

The rotation store keys roots big-endian; the authoriser compares little-endian.
