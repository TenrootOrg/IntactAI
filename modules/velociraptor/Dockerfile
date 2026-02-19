FROM ubuntu:22.04

# VELOCIRAPTOR_TAG = release tag (e.g., 0.75)
# VELOCIRAPTOR_VERSION = binary version (e.g., 0.75.6)
ARG VELOCIRAPTOR_TAG=0.75
ARG VELOCIRAPTOR_VERSION=0.75.6

LABEL description="Velociraptor server"
LABEL version="Velociraptor ${VELOCIRAPTOR_VERSION}"

# Install dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      rsync curl ca-certificates && \
    mkdir -p /opt/velociraptor/linux && \
    mkdir -p /opt/velociraptor/mac && \
    mkdir -p /opt/velociraptor/windows && \
    # Download Velociraptor binaries using direct URLs (no API rate limits)
    curl -s -L -o /opt/velociraptor/linux/velociraptor \
      "https://github.com/Velocidex/velociraptor/releases/download/v${VELOCIRAPTOR_TAG}/velociraptor-v${VELOCIRAPTOR_VERSION}-linux-amd64" && \
    chmod +x /opt/velociraptor/linux/velociraptor && \
    curl -s -L -o /opt/velociraptor/mac/velociraptor_client \
      "https://github.com/Velocidex/velociraptor/releases/download/v${VELOCIRAPTOR_TAG}/velociraptor-v${VELOCIRAPTOR_VERSION}-darwin-amd64" && \
    curl -s -L -o /opt/velociraptor/windows/velociraptor_client.exe \
      "https://github.com/Velocidex/velociraptor/releases/download/v${VELOCIRAPTOR_TAG}/velociraptor-v${VELOCIRAPTOR_VERSION}-windows-amd64.exe" && \
    curl -s -L -o /opt/velociraptor/windows/velociraptor_client.msi \
      "https://github.com/Velocidex/velociraptor/releases/download/v${VELOCIRAPTOR_TAG}/velociraptor-v${VELOCIRAPTOR_VERSION}-windows-amd64.msi" && \
    # Cleanup
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

WORKDIR /velociraptor

CMD ["/entrypoint.sh"]
