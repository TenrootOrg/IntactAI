FROM python:3.11-slim

WORKDIR /app

# Install Docker CLI, compose plugin, and Pango/Cairo system libraries
# (the latter are required by WeasyPrint for engagement-report PDF
# rendering — the customer-facing IR deliverable).
# Pinned docker-compose release + its published checksum. Kept together so a
# version bump that forgets the hash fails the build loudly instead of silently
# verifying the wrong artifact. From the official
# docker-compose-linux-x86_64.sha256 asset for this tag.
ARG DOCKER_COMPOSE_SHA256=f3ba3bf1e4ab18e96c2d36526a075a02a78fb5f8e80d3e3ca9c5bf256d81d0a0

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
    # Verify before making it executable. This binary is fetched over the
    # network and then run by a container that holds the Docker socket, so a
    # compromised release or a broken TLS path would be root on the host. The
    # URL is already version-pinned, which makes the artifact immutable and the
    # checksum meaningful — keep the two on adjacent lines so they are updated
    # together. Value is the published .sha256 asset for v2.27.0, confirmed
    # against the binary in the current image.
    echo "${DOCKER_COMPOSE_SHA256}  /usr/local/lib/docker/cli-plugins/docker-compose" \
        | sha256sum -c - && \
    chmod +x /usr/local/lib/docker/cli-plugins/docker-compose && \
    rm -rf /var/lib/apt/lists/*

# Upgrade pip and wheel first to fix security vulnerabilities (CVE-2025-8869, CVE-2026-1703, CVE-2026-24049)
RUN pip install --no-cache-dir --upgrade pip>=26.0 wheel>=0.46.2

# Copy the TEMPLATE, never the operator's live config.yaml.
#
# This used to be `COPY config.yaml`, which baked whatever the build host had
# into an image layer. On a real install that file holds the operator's GitHub
# PAT (options.github_token) and every module password in plaintext — verified
# recoverable with a plain `docker run --entrypoint sh <image> -c 'cat
# /app/config.yaml'`. Image layers get saved, pushed and shared, so that is a
# credential leak with no audit trail. Nothing is lost by using the template:
# at runtime modules/backend/docker-compose.yaml bind-mounts the operator's real
# config.yaml over this exact path, so the baked copy is only ever a build-time
# input and a fallback for contexts with no mount (CI test runs).
#
# install_deps.py below reads it to decide which module dependencies to install.
# The template ships every module `enabled: true`, so this installs a superset —
# which also makes the image reproducible instead of varying by build host.
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

# THE HOST-SIDE UPGRADE ENGINE, carried as a bootstrap copy.
#
# Not for this container to run against itself -- upgrades normally execute
# the appliance's own /scripts/upgrade.sh, mounted into the helper container.
# This copy exists for the one box that has not got that file yet.
#
# An intact-20260726 appliance has no scripts/upgrade.sh and no lib/upgrade/ at
# all. Its only way to take a new release is its own Import Package UI, whose
# Phase 1 swaps in THIS image and then hands over to a Phase 2 that no longer
# exists. The box comes back running new backend code, showing the upgrade UI,
# with nothing on disk for that UI to call -- so it would sit there
# half-upgraded and unable to finish itself.
#
# scripts/upgrade.sh already separates _CODE_DIR (where the engine lives) from
# --root (the appliance it acts on); that is the same split the in-package
# stage-0 hop uses. So the helper can run THIS copy against the host and the
# first thing it does is mirror lib/ and scripts/ onto the appliance, after
# which the box is self-sufficient and this copy is never used again.
#
# Deliberately at /app/host-engine, not /app/lib + /app/scripts:
# /app/scripts is already the backend's own, and shadowing it would be a
# genuinely confusing way to break the backend.
COPY lib/ /app/host-engine/lib/
COPY scripts/upgrade.sh /app/host-engine/scripts/upgrade.sh

# Re-copy the template after the source layers (see the note above — the
# operator's real config.yaml is bind-mounted over this at runtime).
COPY config.yaml /app/config.yaml

# Create logs directory
RUN mkdir -p /app/logs

# Expose port
EXPOSE 5001

# Run the application
CMD ["python", "app.py"]
