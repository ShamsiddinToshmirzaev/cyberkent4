# Padding Choir — protocol

The gateway speaks a length-framed binary protocol over TCP.

```
frame  = uint32_be length | payload[length]
```

Connection details are in `samples/instance_public.json`
(`gateway_host`, `gateway_port`).

## Requests

`payload = op(1 byte) | body`

| op   | name           | body                                             |
|------|----------------|--------------------------------------------------|
| 0x01 | IMPORT_SESSION | `ciphertext` — a raw RSA-encrypted session blob, exactly `k` bytes (`k` = modulus size in bytes, see `instance_public.json`) |
| 0x02 | USE_SESSION    | `uint16_be handle_len | handle | command`        |
| 0x03 | STATS          | *(empty)*                                        |

Sessions are wrapped with **RSA PKCS#1 v1.5 encryption**. The public key is in
`samples/public_key.pem` (and `n`,`e`,`k` in `samples/instance_public.json`), so
you can construct session ciphertexts yourself.

## Responses

`payload` is an ASCII line, always ending in ` req=<id> ts=<ms>`
(`ts` is a coarse server millisecond clock).

| line                          | meaning                                        |
|-------------------------------|------------------------------------------------|
| `403 AUTH FAILED …`           | the request was not accepted (all failures look identical) |
| `200 SESSION <handle> …`      | a privileged session was imported; use the handle |
| `200 ARCHIVE <data> …`        | a `USE_SESSION` command succeeded               |
| `200 STATS used=<u> budget=<b> …` | how much of the global query budget is spent |
| `429 BUDGET EXCEEDED …`       | the global query budget is exhausted            |
| `400 BAD OP …`                | unknown opcode                                  |

## Notes

- Failures are intentionally indistinguishable at the application layer: the
  gateway returns the same `403 AUTH FAILED` regardless of *why* a session was
  rejected.
- There is a global query budget and a rate limit; `STATS` shows your budget use.
- A reference client is in `client/client.py`:
  ```bash
  python3 client/client.py stats
  python3 client/client.py import <hex-ciphertext>
  python3 client/client.py use <handle> OPEN_ARCHIVE
  ```
  `Client.import_session()` returns `(response_line, round_trip_seconds)`.
