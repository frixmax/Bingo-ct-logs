FROM python:3.11-slim

# Security: Run as non-root user
RUN useradd -m -u 1000 monitor

WORKDIR /app

# Install dependencies from requirements.txt
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application and configuration files
COPY ct_monitor.py .
COPY domains.txt .
COPY paths.txt .
COPY subdomains.txt .

# Create data directory with correct ownership
RUN mkdir -p /app/data && chown -R monitor:monitor /app

# Switch to non-root user
USER monitor

# Healthcheck: Monitor heartbeat file
HEALTHCHECK --interval=60s --timeout=10s --start-period=30s --retries=3 \
    CMD python3 -c "import os, time; f='/tmp/ct_monitor.heartbeat'; exit(0 if os.path.exists(f) and (time.time() - os.path.getmtime(f)) < 120 else 1)"

# Start monitoring
CMD ["python3", "ct_monitor.py"]
