FROM ubuntu:22.04

# VELOCIRAPTOR_TAG = release tag (e.g., 0.75)
# VELOCIRAPTOR_VERSION = binary version (e.g., 0.75.6)
ARG VELOCIRAPTOR_TAG
ARG VELOCIRAPTOR_VERSION

LABEL description="Velociraptor server"
LABEL version="Velociraptor ${VELOCIRAPTOR_VERSION}"

# Binaries are staged into the build context by the install/upgrade
# orchestrator BEFORE invoking `docker compose build`. Both modes
# (fresh install + online upgrade) download from GitHub on the host
# side; offline upgrade copies them out of the upgrade package. Either
# way the Dockerfile sees them as plain files and just COPYs — no
# network at build time.
#
# Earlier versions of this Dockerfile curled directly from
# github.com/Velocidex during build, which made every build network-
# dependent and outright impossible during offline upgrade. See
# services/upgrade/velociraptor.py:_stage_velociraptor_binaries for
# the staging contract.
# ca-certificates is the ONLY runtime dep we need: the Velociraptor
# server's `Server.Utils.GetDependency` fetches tools on-demand from
# HTTPS endpoints (GitHub releases, etc.) and Ubuntu 22.04 base ships
# with no CA bundle — without this every fetch fails with
# "x509: certificate signed by unknown authority". apt-get needs
# network at BUILD time only; the resulting image runs fully offline.
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    mkdir -p /opt/velociraptor/linux \
             /opt/velociraptor/mac \
             /opt/velociraptor/windows

COPY clients/linux/velociraptor                /opt/velociraptor/linux/velociraptor
COPY clients/mac/velociraptor_client           /opt/velociraptor/mac/velociraptor_client
COPY clients/windows/velociraptor_client.exe   /opt/velociraptor/windows/velociraptor_client.exe
COPY clients/windows/velociraptor_client.msi   /opt/velociraptor/windows/velociraptor_client.msi

RUN chmod +x /opt/velociraptor/linux/velociraptor \
             /opt/velociraptor/mac/velociraptor_client \
             /opt/velociraptor/windows/velociraptor_client.exe

# Curated artifact-definition bundle (ArtifactExchange / DetectRaptor /
# Sigma / Rapid7 / TenRoot, pre-exported as plain YAMLs). Baked into the
# image so the server loads them on boot via `--definitions` (see
# entrypoint.sh) — one pass at startup instead of importing each artifact
# over the API one-by-one (which is O(N^2) and took ~37 min on a fresh
# air-gap install). Works identically for fresh install, online upgrade,
# and offline package apply because the artifacts ride inside this image.
COPY bundled_artifacts /opt/velociraptor_artifacts

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

WORKDIR /velociraptor

CMD ["/entrypoint.sh"]
