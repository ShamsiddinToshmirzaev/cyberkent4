# NonceContext checkpoint format (partial source, leaked from a support ticket)

The signer serialises its nonce state to a checkpoint on every maintenance reboot
and restores it on start-up. Reconstructed struct (little-endian on disk):

```c
struct NonceCheckpoint {
    uint8_t  magic[4];      // "NCP1"
    uint64_t counter;       // monotonic signature counter
    uint8_t  pool[30];      // <-- "entropy pool" restored into the 256-bit nonce state
    uint16_t crc;
};
```

Restore path (paraphrased):

```c
// nonce_state is 256 bits; the checkpoint only carries 30 bytes of pool.
memset(nonce_state, 0, 32);
memcpy(nonce_state, ckpt.pool, sizeof(ckpt.pool));   // top bytes stay zero
// ... the next `reboot_window` signatures derive their nonce from nonce_state ...
```

Ops note: "after a reboot the first few signatures come out of the restored context;
it re-widens once the pool re-fills. Harmless — the signatures still verify."
