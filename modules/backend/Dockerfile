FROM python:3.11-slim

WORKDIR /app

# Install Docker CLI, compose plugin, and Pango/Cairo system libraries
# (the latter are required by WeasyPrint for engagement-report PDF
# rendering — the customer-facing IR deliverable).
# apt-get with retries — a transient network blip mid-install used to
# kill the whole build (2026-06-16: a fresh install died here with
# "curl: (56) Recv failure: Connection reset by peer", exit 56, while
# pulling docker-compose; the operator had to re-run install.sh). The
# apt::Retries option + the curl --retry flags below make this step
# ride out short network interruptions instead of aborting the install.
RUN apt-get -o Acquire::Retries=5 update && \
    apt-get -o Acquire::Retries=5 install -y \
        docker.io curl ca-certificates \
        libpango-1.0-0 libpangoft2-1.0-0 libcairo2 libffi8 \
        shared-mime-info fonts-dejavu && \
    mkdir -p /usr/local/lib/docker/cli-plugins && \
    curl -fSL --retry 5 --retry-delay 5 --retry-max-time 600 \
        --connect-timeout 30 --retry-connrefused \
        https://github.com/docker/compose/releases/download/v2.27.0/docker-compose-linux-x86_64 \
        -o /usr/local/lib/docker/cli-plugins/docker-compose && \
    chmod +x /usr/local/lib/docker/cli-plugins/docker-compose && \
    rm -rf /var/lib/apt/lists/*

# Upgrade pip and wheel first to fix security vulnerabilities (CVE-2025-8869, CVE-2026-1703, CVE-2026-24049)
RUN pip install --no-cache-dir --upgrade pip>=26.0 wheel>=0.46.2

# Copy config.yaml early so we can conditionally install module dependencies
COPY config.yaml /app/config.yaml

# Copy all requirements files and install script
COPY modules/backend/requirements*.txt /app/
COPY modules/backend/install_deps.py /app/

# Install core dependencies, then conditionally install module dependencies
RUN pip install --no-cache-dir -r /app/requirements.txt && \
    python3 /app/install_deps.py /app/config.yaml /app

# Copy application files
COPY modules/backend/config.py /app/
COPY modules/backend/app.py /app/
COPY modules/backend/services/ /app/services/
COPY modules/backend/routes/ /app/routes/
COPY modules/backend/scripts/ /app/scripts/

# Copy bundled config files (default blueprints, etc.)
# These are NOT volume-mounted, so they persist in the container image
COPY modules/backend/config/ /app/config/

# Copy config.yaml to /app/
COPY config.yaml /app/config.yaml

# Create logs directory
RUN mkdir -p /app/logs

# Expose port
EXPOSE 5001

# Run the application
CMD ["python", "app.py"]
