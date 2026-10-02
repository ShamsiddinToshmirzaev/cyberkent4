# Build the C++ appliance, then assemble a slim Python runtime that carries both
# the binary and the Python services. Build context is the challenge root:
#   docker build -f deploy/Dockerfile -t c02 .
FROM debian:stable-slim@sha256:5bc3287b25407c965a30f38e32603dc253a3869e1b12a21ac09bfc27fd8b13ce AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential cmake libssl-dev ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY src/appliance ./src/appliance
RUN cmake -S src/appliance -B build/appliance -DCMAKE_BUILD_TYPE=Release \
 && cmake --build build/appliance -j

FROM python:3.12-slim@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f AS runtime
RUN pip install --no-cache-dir cryptography
WORKDIR /app
COPY --from=build /app/build/appliance/appliance ./build/appliance/appliance
COPY src ./src
COPY instance ./instance
COPY player ./player
COPY deploy/appliance_entry.py ./deploy/appliance_entry.py
COPY deploy/healthcheck.sh ./deploy/healthcheck.sh
RUN useradd -m -u 10001 choir && chown -R choir:choir /app
USER choir
