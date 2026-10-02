#!/usr/bin/env bash
# Liveness: GET /info and require the expected id.
exec python3 - <<'PY'
import json, sys, urllib.request
try:
    with urllib.request.urlopen("http://127.0.0.1:9170/info", timeout=3) as r:
        sys.exit(0 if json.load(r).get("id") == "C17-cbor-time-machine" else 1)
except Exception:
    sys.exit(1)
PY
