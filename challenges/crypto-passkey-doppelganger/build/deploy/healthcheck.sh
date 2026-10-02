#!/usr/bin/env bash
exec python3 - <<'PY'
import json, sys, urllib.request
try:
    with urllib.request.urlopen("http://127.0.0.1:9100/info", timeout=3) as r:
        sys.exit(0 if json.load(r).get("id") == "C10-passkey-doppelganger" else 1)
except Exception:
    sys.exit(1)
PY
