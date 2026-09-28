# Init image: provisions the Joomla DB + files once, idempotently, then exits.
# php-cli for password_hash(), mysql client for schema/user, gettext for envsubst.
FROM php:8.1-cli

RUN apt-get update \
    && apt-get install -y --no-install-recommends default-mysql-client gettext-base \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/ctf
COPY provision.sh /opt/ctf/provision.sh
COPY configuration.php.tmpl /opt/ctf/configuration.php.tmpl
RUN chmod 0755 /opt/ctf/provision.sh

ENTRYPOINT ["/opt/ctf/provision.sh"]
