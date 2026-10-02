#!/bin/bash
set -e

# Flag injected from flags.env at runtime. Fallback only for local dev.
# (Avoid an inline ${FLAG:-CTF4{...}} default: the nested brace mis-parses and appends a '}'.)
FLAG="${FLAG:-}"
[ -n "$FLAG" ] || FLAG='CTF4{local_dev_flag}'
printf '%s\n' "$FLAG" > /tmp/flag.txt
chmod 644 /tmp/flag.txt

# DB config from db.env. `${DB_PASS-}` keeps an intentionally-EMPTY password empty
# (only defaults when the var is entirely unset).
export DB_PASS="${DB_PASS-}"
export DB_NAME="${DB_NAME:-ctf_db}"

# Initialise the MySQL data dir.
mysql_install_db --user=mysql --datadir=/var/lib/mysql > /dev/null 2>&1

# Disable secure_file_priv so the intended LOAD_FILE exploit works (DELIBERATE weakening).
mkdir -p /etc/mysql/conf.d
printf '[mysqld]\nsecure_file_priv = ""\n' > /etc/mysql/conf.d/ctf.cnf

mysqld_safe --user=mysql --secure-file-priv="" &

# Wait until MySQL is ready.
for i in $(seq 1 30); do
    if mysqladmin ping --silent 2>/dev/null; then break; fi
    sleep 1
done

# Provision DB. Idempotent: init.sql DROPs then recreates. Name/password injected from env.
envsubst < /init.sql > /tmp/init.sql
mysql < /tmp/init.sql

exec apache2-foreground
