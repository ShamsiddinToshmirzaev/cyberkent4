FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# RSA-2048 keypair generated at build time. The public key is served on purpose
# (the challenge is RS256->HS256 algorithm confusion); the private key signs tokens.
RUN mkdir -p /app/keys \
    && openssl genrsa -out /app/keys/private.pem 2048 \
    && openssl rsa -in /app/keys/private.pem -pubout -out /app/keys/public.pem

COPY app.py .

# Non-root. Make keys/app readable by uid 1000 so a read-only rootfs still works.
RUN useradd -u 1000 -m app \
    && chown -R 1000:1000 /app \
    && chmod 640 /app/keys/private.pem
USER 1000

# NOTE: no `ENV FLAG=...` here — the flag is injected at runtime via flags.env.
EXPOSE 5000
CMD ["python", "app.py"]
