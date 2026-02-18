FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    gcc \
    libssl-dev \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir requests cryptography urllib3

# Script principal
COPY ct_monitor.py .

# Fichiers de configuration — copiés dans l'image au build
# Pour modifier : éditer dans le repo et pousser → Railway rebuild automatiquement
COPY domains.txt .
COPY subdomains.txt .
COPY paths.txt .

RUN mkdir -p /app/data

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD pgrep -f ct_monitor.py || exit 1

CMD ["python3", "-u", "ct_monitor.py"]
