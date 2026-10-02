FROM ubuntu:16.04@sha256:1f1a2d56de1d604801a9671f301190704c25d604a416f59e03c04f5c6ffee0d6 AS builder
RUN apt-get update && apt-get install -y --no-install-recommends gcc make libc6-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY src/ src/
COPY Makefile .
COPY drop.c .
RUN make chall && gcc -O2 -o /drop drop.c

FROM ubuntu:16.04@sha256:1f1a2d56de1d604801a9671f301190704c25d604a416f59e03c04f5c6ffee0d6
COPY --from=builder /build/chall /chall
COPY --from=builder /drop /drop
COPY entrypoint.sh /entrypoint.sh
RUN chmod 555 /chall /drop && chmod +x /entrypoint.sh
EXPOSE 5000
ENTRYPOINT ["/entrypoint.sh"]
