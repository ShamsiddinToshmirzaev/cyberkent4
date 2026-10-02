# Build the C signer, then a slim Python runtime (gateway + generate.py + p256).
# Build context is the challenge root:  docker build -f deploy/Dockerfile -t c03 .
FROM debian:stable-slim@sha256:5bc3287b25407c965a30f38e32603dc253a3869e1b12a21ac09bfc27fd8b13ce AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential cmake libssl-dev ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY src/signer ./src/signer
RUN cmake -S src/signer -B build/signer -DCMAKE_BUILD_TYPE=Release \
 && cmake --build build/signer -j

FROM python:3.12-slim@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f AS runtime
RUN pip install --no-cache-dir cryptography
WORKDIR /app
COPY --from=build /app/build/signer/signer ./build/signer/signer
COPY src ./src
COPY instance ./instance
COPY player ./player
COPY deploy/signer_entry.py deploy/healthcheck.sh ./deploy/
RUN chmod +x deploy/healthcheck.sh \
 && useradd -m -u 10001 minerva && chown -R minerva:minerva /app
USER minerva
