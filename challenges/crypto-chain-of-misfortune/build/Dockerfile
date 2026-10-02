# Build the Go service, then a slim Python runtime (generate.py needs cryptography).
# Build context is the challenge root:  docker build -f deploy/Dockerfile -t c16 .
FROM golang:1.23-bookworm@sha256:167053a2bb901972bf2c1611f8f52c44d5fe7e762e5cab213708d82c421614db AS build
WORKDIR /src
COPY src/ ./
RUN CGO_ENABLED=0 go build -o /c16-gateway .

FROM python:3.12-slim@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f AS runtime
RUN pip install --no-cache-dir cryptography
WORKDIR /app
COPY --from=build /c16-gateway ./c16-gateway
COPY instance ./instance
COPY player ./player
COPY deploy/entrypoint.sh deploy/healthcheck.sh ./deploy/
RUN chmod +x deploy/entrypoint.sh deploy/healthcheck.sh \
 && useradd -m -u 10001 nova && chown -R nova:nova /app
USER nova
ENTRYPOINT ["deploy/entrypoint.sh"]
