FROM php:8.2-apache

# Only the .htaccess DirectoryIndex is used; enable overrides so Apache honors it.
RUN sed -i 's/AllowOverride None/AllowOverride All/' /etc/apache2/sites-available/000-default.conf

COPY entrypoint.sh /entrypoint.sh
COPY html/ /var/www/html/

RUN chmod +x /entrypoint.sh

# NOTE: no flag is baked in. entrypoint.sh writes $FLAG (from flags.env) at runtime,
# only into the hidden directory where the intended LFI reads it.
EXPOSE 80
ENTRYPOINT ["/entrypoint.sh"]
