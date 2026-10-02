#!/usr/bin/env bash
# Liveness: GET /info and require a 200 with the expected id.
exec python3 - <<'PY'
import json, sys, urllib.request
try:
    with urllib.request.urlopen("http://127.0.0.1:9160/info", timeout=3) as r:
        info = json.load(r)
    sys.exit(0 if info.get("id") == "C16-chain-of-misfortune" else 1)
except Exception:
    sys.exit(1)
PY
