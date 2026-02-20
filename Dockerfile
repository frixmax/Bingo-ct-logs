FROM python:3.11-slim
WORKDIR /app
# ── Dépendances système ──────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y \
    curl \
    gcc \
    libssl-dev \
    libffi-dev \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*
# ── Dépendances Python : wheels pré-compilés en priorité (évite OOM au build) ─
COPY requirements.txt .
RUN pip install --upgrade pip --no-cache-dir \
 && pip install --no-cache-dir --prefer-binary -r requirements.txt
# ── Fichiers applicatifs ─────────────────────────────────────────────────────
COPY ct_monitor.py .
COPY domains.txt .
# Fichiers optionnels (créés vides s'ils n'existent pas)
RUN touch /app/subdomains.txt /app/paths.txt
# Répertoire de données persistant
RUN mkdir -p /app/data
EXPOSE 10000
HEALTHCHECK --interval=60s --timeout=10s --start-period=30s --retries=3 \
    CMD python3 -c "import os,time; f='/tmp/ct_monitor.heartbeat'; \
        age=time.time()-os.path.getmtime(f) if os.path.exists(f) else 999; \
        exit(0 if age < 120 else 1)" || exit 1
CMD ["python3", "-u", "ct_monitor.py"]
