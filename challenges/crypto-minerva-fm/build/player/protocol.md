# Minerva FM — protocol

Length-framed TCP. Address in `samples/instance_public.json`
(`gateway_host`, `gateway_port`).

```
frame = uint32_be length | payload[length]
payload = op(1 byte) | body
```

## Requests

| op   | name   | body                                                    |
|------|--------|---------------------------------------------------------|
| 0x01 | SIGN   | `manifest` bytes (a UTF-8 string)                       |
| 0x02 | SUBMIT | `uint16_be msglen | manifest | r(32 bytes) | s(32 bytes)` |
| 0x03 | STATS  | *(empty)*                                               |

## Responses (ASCII line, ending ` req=<id>`)

| line                         | meaning                                          |
|------------------------------|--------------------------------------------------|
| `200 SIG <r_hex> <s_hex> …`  | ECDSA signature over `SHA256(manifest)`          |
| `403 FORBIDDEN …`            | the manifest contains a privileged token         |
| `429 BUDGET …`               | the query budget is exhausted                    |
| `200 FLAG <flag> …`          | SUBMIT accepted a valid signature over the target |
| `403 DENIED …`               | SUBMIT rejected (wrong manifest or bad signature) |
| `200 STATS used=<u> budget=<b> …` | query-budget usage                          |

## Signature scheme

ECDSA over **P-256** (curve order `n` in `instance_public.json`). The signed
message hash is `z = SHA256(manifest)` (as a big-endian integer). Signatures are
standard `(r, s)`.

The reference client returns the **round-trip time** of every `SIGN`:

```python
from client import Client
c = Client(host, port)
r, s, rtt = c.sign(b'{"station":"88.5","title":"...","mix":"..."}')   # rtt in seconds
line = c.submit(target_bytes, r, s)
```
