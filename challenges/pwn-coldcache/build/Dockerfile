FROM ubuntu:22.04@sha256:4f838adc7181d9039ac795a7d0aba05a9bd9ecd480d294483169c5def983b64d AS builder
RUN apt-get update && apt-get install -y gcc make && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY src/ src/
COPY Makefile .
RUN make chall

FROM ubuntu:22.04@sha256:4f838adc7181d9039ac795a7d0aba05a9bd9ecd480d294483169c5def983b64d
COPY --from=builder /build/chall /chall
COPY entrypoint.sh /entrypoint.sh
RUN chmod 555 /chall && chmod +x /entrypoint.sh
EXPOSE 5000
ENTRYPOINT ["/entrypoint.sh"]
