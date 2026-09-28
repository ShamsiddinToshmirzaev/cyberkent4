#!/bin/bash
# Write the flag from the environment (never baked into the image), then hand off
# to the stock WordPress entrypoint. Intended path: XXE -> wp-config creds ->
# webshell (runs as www-data) -> read /flag.txt.
set -e

if [ -n "${FLAG:-}" ]; then
  printf '%s\n' "$FLAG" > /flag.txt
  chown root:www-data /flag.txt
  chmod 640 /flag.txt
fi

exec docker-entrypoint.sh "$@"
