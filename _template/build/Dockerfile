FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

# Run as non-root (matches `user: 1000:1000` in compose).
RUN useradd -u 1000 -m app || true
USER 1000

EXPOSE 5000
# App must read the flag from the environment: FLAG = os.environ.get("FLAG")
CMD ["python3", "app.py"]
