#!/bin/sh
# ROOT PID1: place a read-only root-owned flag (popped uid-1000 shells in sticky
# /tmp can READ but never delete/modify), keep a watchdog that restores it, then
# serve via socat. run.sh drops each connection to uid 1000 before exec'ing vuln.
set -u
FLAG_FILE=/tmp/flag.txt
: "${FLAG:=CTF4{local_dev_flag}}"
write_flag() {
  printf '%s' "$FLAG" > "${FLAG_FILE}.tmp" 2>/dev/null || return 0
  chmod 0444 "${FLAG_FILE}.tmp" 2>/dev/null || true
  chown 0:0 "${FLAG_FILE}.tmp" 2>/dev/null || true
  mv -f "${FLAG_FILE}.tmp" "$FLAG_FILE" 2>/dev/null || true
}
write_flag
( while true; do
    if [ ! -e "$FLAG_FILE" ] || [ "$(cat "$FLAG_FILE" 2>/dev/null || true)" != "$FLAG" ]; then write_flag; fi
    sleep 2
  done ) &
exec socat -T120 TCP-LISTEN:5000,reuseaddr,fork "EXEC:/chal/run.sh,stderr"
