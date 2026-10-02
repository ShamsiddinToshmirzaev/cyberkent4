FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

# Run as non-root (matches user: 1000:1000 in compose).
RUN useradd -u 1000 -m app || true
USER 1000

# NOTE: no ENV FLAG — the flag is injected at runtime from flags.env.
EXPOSE 5000
CMD ["python3", "app.py"]
