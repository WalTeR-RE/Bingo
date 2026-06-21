# ============================================================
# Bingo AI-Agent runtime image (Linux / Python 3.12)
# ============================================================
# Provides the Python environment + the CLI security tools the
# offensive ReAct agents shell out to. The agent source is
# mounted at /app at run time (see docker-compose), so code
# edits do NOT require an image rebuild.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    DEBIAN_FRONTEND=noninteractive

# ---- System packages: CLI tools used by recon/exploit agents ----
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
        ca-certificates \
        nmap \
        sqlmap \
        iputils-ping \
        dnsutils \
        git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# ---- Python dependencies (cached layer) ----
COPY requirements.txt /tmp/requirements.txt
RUN pip install --upgrade pip && \
    pip install -r /tmp/requirements.txt

# ---- Playwright Chromium + its system libraries ----
RUN playwright install --with-deps chromium

# Source is bind-mounted at /app at runtime.
CMD ["bash"]
