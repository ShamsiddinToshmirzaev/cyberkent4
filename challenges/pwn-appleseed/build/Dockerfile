FROM ubuntu:22.04@sha256:4f838adc7181d9039ac795a7d0aba05a9bd9ecd480d294483169c5def983b64d AS builder
RUN apt-get update && apt-get install -y --no-install-recommends gcc make libc6-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY src/ src/
COPY Makefile .
RUN make chall

FROM ubuntu:22.04@sha256:4f838adc7181d9039ac795a7d0aba05a9bd9ecd480d294483169c5def983b64d
RUN apt-get update && apt-get install -y --no-install-recommends python3-minimal \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/chall /chall
COPY entrypoint.sh /entrypoint.sh
RUN chmod 0555 /chall && chmod 0555 /entrypoint.sh
EXPOSE 5000
ENTRYPOINT ["/entrypoint.sh"]
