FROM php:8.2-apache

# MariaDB in-container + mysqli. gettext-base gives envsubst (DB name/password templating).
RUN apt-get update \
    && apt-get install -y --no-install-recommends default-mysql-server gettext-base \
    && docker-php-ext-install mysqli \
    && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /entrypoint.sh
COPY init.sql /init.sql
COPY html/ /var/www/html/

RUN chmod +x /entrypoint.sh \
    && sed -i 's/AllowOverride None/AllowOverride All/' /etc/apache2/sites-available/000-default.conf

# NOTE: no flag/creds baked in. Flag from flags.env at runtime; DB name from db.env.
# The Node files (index.html base64 + `p`) are intentional decoy hints, not a runtime.
EXPOSE 80
ENTRYPOINT ["/entrypoint.sh"]
