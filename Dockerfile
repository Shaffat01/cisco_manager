FROM python:3.12-slim

# Locale & timezone
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    TZ=Asia/Dhaka

WORKDIR /app

# System dependencies (gcc for building any C-extensions)
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
        ca-certificates \
        tzdata \
    && rm -rf /var/lib/apt/lists/*

# Python dependencies — cache layer
COPY requirements.txt .
RUN pip install -r requirements.txt

# Application code
COPY . .

# Persistent data directory
RUN mkdir -p /app/data

# Default DB location (overridable via env)
ENV DB_FILE=/app/data/switches.db

EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/').read()" || exit 1

CMD ["python", "app.py"]
