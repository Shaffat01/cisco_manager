# ============================================================
# NetScan Pro — Cisco Switch Manager
# Python 3.11 (pysnmp 4.x requires asyncore — removed in 3.12)
# ============================================================
FROM python:3.11-slim

# ------------------------------------------------------------
# Environment
# ------------------------------------------------------------
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    TZ=Asia/Dhaka \
    DB_FILE=/app/data/switches.db \
    SNMP_INTERVAL=5 \
    SNMP_WORKERS=20 \
    SNMP_CACHE_TTL=300

# ------------------------------------------------------------
# System dependencies
# ------------------------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
        ca-certificates \
        tzdata \
        iputils-ping \
        snmp \
    && rm -rf /var/lib/apt/lists/*

# ------------------------------------------------------------
# Working directory
# ------------------------------------------------------------
WORKDIR /app

# ------------------------------------------------------------
# Python dependencies (cached layer)
# ------------------------------------------------------------
COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip install -r requirements.txt

# ------------------------------------------------------------
# Application code
# ------------------------------------------------------------
COPY . .

# ------------------------------------------------------------
# Persistent data directory
# ------------------------------------------------------------
RUN mkdir -p /app/data

# ------------------------------------------------------------
# Network
# ------------------------------------------------------------
EXPOSE 5000

# ------------------------------------------------------------
# Health check
# ------------------------------------------------------------
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/').read()" || exit 1

# ------------------------------------------------------------
# Start
# ------------------------------------------------------------
CMD ["python", "app.py"]
