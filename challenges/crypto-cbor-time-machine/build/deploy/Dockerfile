# Pure-Python service; only dependency is `cryptography` (Ed25519).
# Build context is the challenge root:  docker build -f deploy/Dockerfile -t c17 .
FROM python:3.12-slim@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f
RUN pip install --no-cache-dir cryptography
WORKDIR /app
COPY src ./src
COPY instance ./instance
COPY player ./player
COPY deploy/entrypoint.sh deploy/healthcheck.sh ./deploy/
RUN chmod +x deploy/entrypoint.sh deploy/healthcheck.sh \
 && useradd -m -u 10001 customs && chown -R customs:customs /app
USER customs
ENTRYPOINT ["deploy/entrypoint.sh"]
