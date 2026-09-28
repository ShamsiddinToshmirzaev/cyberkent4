FROM wordpress:5.6-php8.0-apache

# NOTE: this image is Debian buster (EOL) — apt repos are gone, so we install nothing.
# The healthcheck uses the bundled php CLI instead of curl.

# Uploads dir with correct ownership (media-upload XXE is the intended entry point).
RUN mkdir -p /var/www/html/wp-content/uploads \
    && chown -R www-data:www-data /var/www/html/wp-content/

# Hide the WordPress/Apache version banner (fingerprinting still possible).
RUN echo "ServerTokens Prod"  >> /etc/apache2/conf-enabled/security.conf \
    && echo "ServerSignature Off" >> /etc/apache2/conf-enabled/security.conf

# The flag is NOT baked into the image. It is written at container start from $FLAG
# with the intended perms (640 root:www-data) so it never enters an image layer or git.
COPY flag-entrypoint.sh /usr/local/bin/flag-entrypoint.sh
RUN chmod 0755 /usr/local/bin/flag-entrypoint.sh

ENTRYPOINT ["/usr/local/bin/flag-entrypoint.sh"]
CMD ["apache2-foreground"]
