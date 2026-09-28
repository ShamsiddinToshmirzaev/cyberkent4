FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

RUN useradd -u 1000 -m app && chown -R 1000:1000 /app
USER 1000

# App reads FLAG from env and drops it to /tmp/flag.txt for the SSTI path (tmpfs at runtime).
EXPOSE 5555
CMD ["python3", "app.py"]
