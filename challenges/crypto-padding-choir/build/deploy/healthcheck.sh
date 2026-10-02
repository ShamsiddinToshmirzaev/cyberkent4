#!/usr/bin/env bash
# Liveness: send a STATS frame to the gateway and require a 200 STATS reply.
exec python3 - "$@" <<'PY'
import socket, struct, sys
try:
    s = socket.create_connection(("127.0.0.1", 9020), 3)
    s.sendall(struct.pack(">I", 1) + bytes([0x03]))          # op 0x03 = STATS
    (ln,) = struct.unpack(">I", s.recv(4))
    resp = s.recv(ln)
    sys.exit(0 if resp.startswith(b"200 STATS") else 1)
except Exception:
    sys.exit(1)
PY
