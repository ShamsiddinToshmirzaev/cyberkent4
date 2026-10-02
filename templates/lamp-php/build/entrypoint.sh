#!/bin/bash
set -e

# Flag injected from flags.env at runtime. Fallback only for local dev.
# (Avoid an inline ${FLAG:-CTF4{...}} default: the nested brace mis-parses and appends a '}'.)
FLAG="${FLAG:-}"
[ -n "$FLAG" ] || FLAG='CTF4{local_dev_flag}'

# Written OUTSIDE the docroot (/var/www/html) so it is not directly web-served; PHP reads it.
printf '%s' "$FLAG" > /var/www/flag.txt
chmod 644 /var/www/flag.txt

exec apache2-foreground
