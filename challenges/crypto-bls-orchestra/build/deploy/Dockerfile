# Build the Rust server, then a slim Python runtime (generate.py is stdlib-only).
# Build context is the challenge root:  docker build -f deploy/Dockerfile -t c15 .
FROM rust:1-slim@sha256:4cd829461bd5c4d511c32e269da9cb8929223b666519d8004e35fc8d1d771ab7 AS build
WORKDIR /app
COPY src/orchestra ./src/orchestra
RUN cd src/orchestra && cargo build --release

FROM python:3.12-slim@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f AS runtime
WORKDIR /app
COPY --from=build /app/src/orchestra/target/release/orchestra ./orchestra
COPY instance ./instance
COPY player ./player
COPY deploy/entrypoint.sh deploy/healthcheck.sh ./deploy/
RUN chmod +x deploy/entrypoint.sh deploy/healthcheck.sh \
 && useradd -m -u 10001 dao && chown -R dao:dao /app
USER dao
ENTRYPOINT ["deploy/entrypoint.sh"]
