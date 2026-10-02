#!/bin/bash
set -e

# Flag injected from flags.env at runtime. Fallback only for local dev.
# (Avoid an inline ${FLAG:-CTF4{...}} default: the nested brace mis-parses and appends a '}'.)
FLAG="${FLAG:-}"
[ -n "$FLAG" ] || FLAG='CTF4{local_dev_flag}'
# Written OUTSIDE the docroot so it is not directly web-served; PHP reads it.
printf '%s' "$FLAG" > /var/www/flag.txt
chmod 644 /var/www/flag.txt

# DB config from db.env (env_file); defaults keep a bare run working.
export DB_USER="${DB_USER:-ctfuser}"
export DB_PASS="${DB_PASS:-ctfpass}"
export DB_NAME="${DB_NAME:-ctfdb}"

mysql_install_db --user=mysql --datadir=/var/lib/mysql > /dev/null 2>&1
mysqld_safe --user=mysql &
for i in $(seq 1 30); do
    if mysqladmin ping --silent 2>/dev/null; then break; fi
    sleep 1
done

# Provision DB. Idempotent: init.sql DROPs then recreates. Name/creds injected from env.
envsubst < /init.sql > /tmp/init.sql
mysql < /tmp/init.sql

exec apache2-foreground
