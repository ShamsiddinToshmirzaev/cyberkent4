#!/bin/sh
# Runs as ROOT (PID1): place a read-only, root-owned flag that popped shells
# (uid 1000, sticky /tmp) can READ but never delete or modify; keep a watchdog
# that restores it if it ever disappears; then drop to uid 1000 for the vuln.
set -u
FLAG_FILE=/tmp/flag
: "${FLAG:=CTF4{local_dev_flag}}"

write_flag() {
  printf '%s' "$FLAG" > "${FLAG_FILE}.tmp" 2>/dev/null || return 0
  chmod 0444 "${FLAG_FILE}.tmp" 2>/dev/null || true
  chown 0:0 "${FLAG_FILE}.tmp" 2>/dev/null || true
  mv -f "${FLAG_FILE}.tmp" "$FLAG_FILE" 2>/dev/null || true
}
write_flag

# self-healing watchdog (root): restore flag if deleted/emptied/altered
(
  while true; do
    if [ ! -e "$FLAG_FILE" ] || [ "$(cat "$FLAG_FILE" 2>/dev/null || true)" != "$FLAG" ]; then
      write_flag
    fi
    sleep 2
  done
) &

export FLAG_PATH="$FLAG_FILE"
exec setpriv --reuid=1000 --regid=1000 --clear-groups /chall 5000
