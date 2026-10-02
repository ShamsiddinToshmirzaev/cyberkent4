# Remote pwn service. Runs the prebuilt vuln behind socat, using the SHIPPED
# glibc loader + libc so player-side offsets match the live target.
FROM debian:bookworm-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251
RUN apt-get update && apt-get install -y --no-install-recommends socat util-linux \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /chal
COPY vuln libc.so.6 ld-linux-x86-64.so.2 run.sh entrypoint.sh ./
# World-readable/executable so the non-root runtime user (1000) can run them.
RUN chmod 0755 vuln ld-linux-x86-64.so.2 libc.so.6 run.sh entrypoint.sh
# Non-root at runtime (matches user: 1000:1000 in compose).
# NOTE: no flag baked in — entrypoint reads $FLAG (flags.env) at runtime.
EXPOSE 5000
ENTRYPOINT ["/chal/entrypoint.sh"]
