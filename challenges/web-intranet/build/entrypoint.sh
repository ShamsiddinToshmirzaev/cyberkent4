#!/bin/bash
set -e

# Flag is injected from flags.env (env_file) at runtime. Fallback only for local dev.
# (Avoid an inline ${FLAG:-CTF4{...}} default: the nested brace mis-parses and appends a '}'.)
FLAG="${FLAG:-}"
[ -n "$FLAG" ] || FLAG='CTF4{local_dev_flag}'

# Write the flag ONLY where the intended LFI reads it:
#   GET /e7fa32cb05ba9ddc8d5f75bdf1694790/?lang=flag.txt  ->  include('flag.txt')
# It is deliberately NOT placed at the docroot root, so there is no zero-effort
# /flag.txt grab that bypasses the discovery -> auth-bypass -> LFI chain.
HASHDIR="/var/www/html/e7fa32cb05ba9ddc8d5f75bdf1694790"
printf '%s\n' "$FLAG" > "$HASHDIR/flag.txt"
chmod 644 "$HASHDIR/flag.txt"

exec apache2-foreground
