#!/bin/sh
# Generate a fresh random instance into tmpfs, then run the Rust server.
set -e
: "${PORT:=9150}"
: "${SEED:=$(od -An -N4 -tu4 </dev/urandom | tr -d ' ')}"
python3 instance/generate.py --seed "$SEED" --port "$PORT" --out /tmp/instance.json --player-dir /tmp
exec env INSTANCE=/tmp/instance.json GATEWAY_BIND=0.0.0.0 ./orchestra
