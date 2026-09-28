FROM python:3.12-slim

WORKDIR /app

# lxml needs libxml2/libxslt at runtime; slim image builds the wheel or pulls binary wheel.
RUN pip install --no-cache-dir flask==3.1.0 lxml

COPY main_app.py internal_service.py ./

# The SSRF target lives at 127.0.0.1:7777 *inside this container* on purpose:
# the intended exploit is XXE->SSRF to localhost, so both processes share one container.
ENV INTERNAL_URL=http://127.0.0.1:7777

RUN useradd -u 1000 -m app && chown -R 1000:1000 /app
USER 1000

# NOTE: no baked FLAG — injected at runtime via flags.env.
EXPOSE 5000
CMD ["sh", "-c", "python internal_service.py & exec python main_app.py"]
