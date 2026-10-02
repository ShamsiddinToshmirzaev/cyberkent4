FROM php:8.2-apache

# Enable .htaccess overrides (common for PHP challenges).
RUN sed -i 's/AllowOverride None/AllowOverride All/' /etc/apache2/sites-available/000-default.conf

COPY entrypoint.sh /entrypoint.sh
COPY html/ /var/www/html/
RUN chmod +x /entrypoint.sh

# NOTE: no flag baked in — entrypoint writes $FLAG (from flags.env) at runtime.
EXPOSE 80
ENTRYPOINT ["/entrypoint.sh"]
