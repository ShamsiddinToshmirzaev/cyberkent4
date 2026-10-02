FROM python:3.12-slim@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
RUN useradd -u 1000 -m app || true
USER 1000
# app listens on 0.0.0.0:5000 (PORT env); NO ENV FLAG — injected at runtime via flags.env
ENV HOST=0.0.0.0 PORT=5000
EXPOSE 5000
CMD ["python3", "app.py"]
