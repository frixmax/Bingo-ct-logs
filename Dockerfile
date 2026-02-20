FROM python:3.11-slim
WORKDIR /app
RUN apt-get update && apt-get install -y \
    curl gcc libssl-dev libffi-dev libpq-dev \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --upgrade pip --no-cache-dir \
 && pip install --no-cache-dir --prefer-binary -r requirements.txt
COPY ct_monitor.py .
COPY domains.txt .
COPY subdomains.txt /app/data/subdomains.txt
RUN touch /app/paths.txt
RUN mkdir -p /app/data
EXPOSE 10000
HEALTHCHECK --interval=60s --timeout=10s --start-period=30s --retries=3 \
    CMD python3 -c "import os,time; f='/tmp/ct_monitor.heartbeat'; \
        age=time.time()-os.path.getmtime(f) if os.path.exists(f) else 999; \
        exit(0 if age < 120 else 1)" || exit 1
CMD ["python3", "-u", "ct_monitor.py"]
