FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    gcc \
    libssl-dev \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir requests cryptography urllib3

COPY ct_monitor.py .
COPY domains.txt .

RUN mkdir -p /app/data

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD pgrep -f ct_monitor.py || exit 1

CMD ["python3", "-u", "ct_monitor.py"]
