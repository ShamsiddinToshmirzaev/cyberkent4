FROM php:8.2-apache

# MariaDB in-container + mysqli. gettext-base gives envsubst (creds templating);
# python3 is used at BUILD time only to generate the leaked vim swap file.
RUN apt-get update \
    && apt-get install -y --no-install-recommends default-mysql-server python3 gettext-base \
    && docker-php-ext-install mysqli \
    && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /entrypoint.sh
COPY init.sql /init.sql
COPY make_swp.py /make_swp.py
COPY html/ /var/www/html/

RUN chmod +x /entrypoint.sh \
    && sed -i 's/AllowOverride None/AllowOverride All/' /etc/apache2/sites-available/000-default.conf \
    && python3 /make_swp.py

# NOTE: no flag/creds baked in. The flag comes from flags.env at runtime; DB creds from db.env.
EXPOSE 80
ENTRYPOINT ["/entrypoint.sh"]
