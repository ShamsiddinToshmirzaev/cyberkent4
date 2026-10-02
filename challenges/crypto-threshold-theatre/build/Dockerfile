# Pure-stdlib Python service (no external dependencies).
# Build context is the challenge root:  docker build -f deploy/Dockerfile -t c08 .
FROM python:3.12-slim@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f
WORKDIR /app
COPY src ./src
COPY instance ./instance
COPY player ./player
COPY deploy/entrypoint.sh deploy/healthcheck.sh ./deploy/
RUN chmod +x deploy/entrypoint.sh deploy/healthcheck.sh \
 && useradd -m -u 10001 studio && chown -R studio:studio /app
USER studio
ENTRYPOINT ["deploy/entrypoint.sh"]
