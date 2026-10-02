# misc-honeypot — blind-oracle handshake + prompt-injection banner. Pure stdlib.
FROM python:3.12-slim@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f
WORKDIR /app
COPY server.py .
RUN useradd -u 1000 -m app || true
USER 1000
# server binds 0.0.0.0:5000; NO flag baked in — reads $FLAG (flags.env) at runtime.
ENV HOST=0.0.0.0 PORT=5000
EXPOSE 5000
CMD ["python3", "server.py", "--host", "0.0.0.0", "--port", "5000"]
