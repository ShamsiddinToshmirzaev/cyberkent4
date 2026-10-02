#!/bin/bash
set -e

# Flag injected from flags.env at runtime. Fallback only for local dev.
# (Avoid an inline ${FLAG:-CTF4{...}} default: the nested brace mis-parses and appends a '}'.)
FLAG="${FLAG:-}"
[ -n "$FLAG" ] || FLAG='CTF4{local_dev_flag}'
printf '%s\n' "$FLAG" > /tmp/office.txt
chmod 644 /tmp/office.txt

# DB creds from db.env (env_file); defaults keep a bare `docker run` working.
export DB_USER="${DB_USER:-ctfuser}"
export DB_PASS="${DB_PASS:-ctfpass}"
export DB_NAME="${DB_NAME:-ctfdb}"

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

# Provision DB. Idempotent: init.sql DROPs then recreates. Creds injected from env.
envsubst < /init.sql > /tmp/init.sql
mysql < /tmp/init.sql

exec apache2-foreground
