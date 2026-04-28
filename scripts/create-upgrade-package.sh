#!/bin/bash
# Create Intact.AI Offline Upgrade Package
# Run this script on a machine WITH internet to create an upgrade package
# that can be transferred to an air-gapped Intact.AI installation.
#
# Usage: ./create-upgrade-package.sh [OPTIONS]
#
# By default, all versions are read from ../config.yaml (the single source of
# truth). Set any of these env vars to override on the command line:
#
#   ELK_VERSION, TS_VERSION, PLASO_VERSION, IRIS_VERSION, VELO_VERSION,
#   INCLUDE_SOURCE (default: true), CONFIG_YAML (default: ../config.yaml)
#
# Examples:
#   ./create-upgrade-package.sh                   # use config.yaml versions
#   VELO_VERSION=0.77.0 ./create-upgrade-package.sh   # override one

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_YAML="${CONFIG_YAML:-${SCRIPT_DIR}/../config.yaml}"

# Read a versions.* value from config.yaml. Same python3+yaml pattern as lib/config.sh.
read_config_version() {
    local key="$1"
    if [[ ! -f "$CONFIG_YAML" ]]; then
        echo ""
        return 1
    fi
    python3 -c "import yaml; v = yaml.safe_load(open('${CONFIG_YAML}'))['versions'].get('${key}', ''); print(v if v is not None else '')" 2>/dev/null || echo ""
}

# Defaults come from config.yaml; env vars still override.
ELK_VERSION="${ELK_VERSION:-$(read_config_version elk)}"
TS_VERSION="${TS_VERSION:-$(read_config_version timesketch)}"
PLASO_VERSION="${PLASO_VERSION:-$(read_config_version plaso)}"
IRIS_VERSION="${IRIS_VERSION:-$(read_config_version iris)}"
VELO_VERSION="${VELO_VERSION:-$(read_config_version velociraptor)}"
INCLUDE_SOURCE="${INCLUDE_SOURCE:-true}"

# Fail fast if any version is empty — that means config.yaml is missing,
# unparseable, or the key is absent. We never want to package an empty version.
for v in ELK_VERSION TS_VERSION PLASO_VERSION IRIS_VERSION VELO_VERSION; do
    if [[ -z "${!v}" ]]; then
        echo "ERROR: $v is empty. Set it via env var or fix ${CONFIG_YAML}." >&2
        exit 1
    fi
done

# Package directory
DATE_STAMP=$(date +%Y%m%d_%H%M%S)
PACKAGE_NAME="intact-upgrade-${DATE_STAMP}"
PACKAGE_DIR="/tmp/${PACKAGE_NAME}"
OUTPUT_FILE="${PWD}/${PACKAGE_NAME}.tar.gz"

echo "=============================================="
echo "  Intact.AI Offline Upgrade Package Creator"
echo "=============================================="
echo ""
echo "Target versions:"
echo "  ELK (Elasticsearch/Kibana/Logstash): ${ELK_VERSION}"
echo "  Timesketch: ${TS_VERSION}"
echo "  Plaso: ${PLASO_VERSION}"
echo "  IRIS: ${IRIS_VERSION}"
echo "  Velociraptor: ${VELO_VERSION}"
echo "  Include source: ${INCLUDE_SOURCE}"
echo ""
echo "Output: ${OUTPUT_FILE}"
echo ""

# Create directory structure
echo "Creating package directory structure..."
mkdir -p "${PACKAGE_DIR}"/{images,binaries,source/backend,source/frontend}

# Function to pull and save docker image
save_docker_image() {
    local image_name="$1"
    local output_name="$2"

    echo "  Pulling ${image_name}..."
    docker pull "${image_name}" || { echo "ERROR: Failed to pull ${image_name}"; return 1; }

    echo "  Saving to ${output_name}..."
    docker save -o "${PACKAGE_DIR}/images/${output_name}" "${image_name}" || { echo "ERROR: Failed to save ${image_name}"; return 1; }

    local size=$(du -h "${PACKAGE_DIR}/images/${output_name}" | cut -f1)
    echo "  Done (${size})"
}

# ===========================================
# 1. Pull and save Docker images
# ===========================================
echo ""
echo "=== Downloading Docker Images ==="

# ELK Stack
echo ""
echo "ELK Stack (${ELK_VERSION}):"
save_docker_image "docker.elastic.co/elasticsearch/elasticsearch:${ELK_VERSION}" "elasticsearch-${ELK_VERSION}.tar"
save_docker_image "docker.elastic.co/kibana/kibana:${ELK_VERSION}" "kibana-${ELK_VERSION}.tar"
save_docker_image "docker.elastic.co/logstash/logstash:${ELK_VERSION}" "logstash-${ELK_VERSION}.tar"

# Timesketch
echo ""
echo "Timesketch (${TS_VERSION}):"
save_docker_image "us-docker.pkg.dev/osdfir-registry/timesketch/timesketch:${TS_VERSION}" "timesketch-${TS_VERSION}.tar"

# Plaso
echo ""
echo "Plaso (${PLASO_VERSION}):"
save_docker_image "log2timeline/plaso:${PLASO_VERSION}" "plaso-${PLASO_VERSION}.tar"

# IRIS
echo ""
echo "IRIS (${IRIS_VERSION}):"
save_docker_image "ghcr.io/dfir-iris/iriswebapp_app:${IRIS_VERSION}" "iris-app-${IRIS_VERSION}.tar"
save_docker_image "ghcr.io/dfir-iris/iriswebapp_worker:${IRIS_VERSION}" "iris-worker-${IRIS_VERSION}.tar"
save_docker_image "ghcr.io/dfir-iris/iriswebapp_nginx:${IRIS_VERSION}" "iris-nginx-${IRIS_VERSION}.tar"

# ===========================================
# 2. Download Velociraptor binary
# ===========================================
echo ""
echo "=== Downloading Velociraptor Binary ==="

# Build URL directly from version (no GitHub API needed)
# Requires full version like 0.75.6, not partial like 0.75
VELO_CLEAN_VERSION="${VELO_VERSION#v}"  # Strip 'v' prefix if present
VELO_PARTS=(${VELO_CLEAN_VERSION//./ })  # Split by dot

if [ ${#VELO_PARTS[@]} -lt 3 ]; then
    echo "ERROR: Full version required (e.g., 0.75.6), got: ${VELO_VERSION}"
    echo "Check https://github.com/Velocidex/velociraptor/releases for available versions"
    exit 1
fi

VELO_RELEASE_TAG="v${VELO_PARTS[0]}.${VELO_PARTS[1]}"
VELO_BINARY="velociraptor-v${VELO_CLEAN_VERSION}-linux-amd64"
VELO_URL="https://github.com/Velocidex/velociraptor/releases/download/${VELO_RELEASE_TAG}/${VELO_BINARY}"

echo "  Version: ${VELO_CLEAN_VERSION}"
echo "  Release tag: ${VELO_RELEASE_TAG}"
echo "  Binary: ${VELO_BINARY}"
echo "  Downloading from: ${VELO_URL}"

curl -fL --retry 5 --retry-delay 5 --retry-max-time 120 -o "${PACKAGE_DIR}/binaries/${VELO_BINARY}" "${VELO_URL}" || {
    echo "ERROR: Failed to download Velociraptor binary"
    echo "URL: ${VELO_URL}"
    echo "Make sure version ${VELO_VERSION} exists at https://github.com/Velocidex/velociraptor/releases"
    exit 1
}
chmod +x "${PACKAGE_DIR}/binaries/${VELO_BINARY}"
ls -lh "${PACKAGE_DIR}/binaries/${VELO_BINARY}"

# Use clean version for manifest
VELO_ACTUAL_VERSION="${VELO_CLEAN_VERSION}"
echo "  Actual version: ${VELO_ACTUAL_VERSION}"

# ===========================================
# 3. Copy source files (optional)
# ===========================================
if [ "${INCLUDE_SOURCE}" = "true" ]; then
    echo ""
    echo "=== Copying Source Files ==="

    # Find the Intact.AI repo directory
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    REPO_DIR="$(dirname "${SCRIPT_DIR}")"

    if [ -d "${REPO_DIR}/modules/backend" ]; then
        echo "  Copying backend source..."
        cp -r "${REPO_DIR}/modules/backend/." "${PACKAGE_DIR}/source/backend/"
        # Remove __pycache__ and .pyc files
        find "${PACKAGE_DIR}/source/backend" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
        find "${PACKAGE_DIR}/source/backend" -name "*.pyc" -delete 2>/dev/null || true
    else
        echo "  WARNING: Backend source not found at ${REPO_DIR}/modules/backend"
    fi

    if [ -d "${REPO_DIR}/modules/nginx/html" ]; then
        echo "  Copying frontend source..."
        cp -r "${REPO_DIR}/modules/nginx/html/." "${PACKAGE_DIR}/source/frontend/"
    else
        echo "  WARNING: Frontend source not found at ${REPO_DIR}/modules/nginx/html"
    fi
fi

# ===========================================
# 4. Generate checksums
# ===========================================
echo ""
echo "=== Generating Checksums ==="
cd "${PACKAGE_DIR}"
find . -type f ! -name "checksums.sha256" ! -name "manifest.json" -exec sha256sum {} \; > checksums.sha256
echo "  Generated checksums for $(wc -l < checksums.sha256) files"

# ===========================================
# 5. Create manifest
# ===========================================
echo ""
echo "=== Creating Manifest ==="

# Get image sizes for manifest
ELK_SIZE=$(du -sb "${PACKAGE_DIR}/images/elasticsearch-${ELK_VERSION}.tar" 2>/dev/null | cut -f1 || echo "0")
KIBANA_SIZE=$(du -sb "${PACKAGE_DIR}/images/kibana-${ELK_VERSION}.tar" 2>/dev/null | cut -f1 || echo "0")

cat > "${PACKAGE_DIR}/manifest.json" << EOF
{
  "package_version": "1.0",
  "created": "$(date -Iseconds)",
  "created_by": "create-upgrade-package.sh",
  "versions": {
    "elk": "${ELK_VERSION}",
    "timesketch": "${TS_VERSION}",
    "plaso": "${PLASO_VERSION}",
    "iris": "${IRIS_VERSION}",
    "velociraptor": "${VELO_ACTUAL_VERSION}"
  },
  "contents": {
    "images": [
      "elasticsearch-${ELK_VERSION}.tar",
      "kibana-${ELK_VERSION}.tar",
      "logstash-${ELK_VERSION}.tar",
      "timesketch-${TS_VERSION}.tar",
      "plaso-${PLASO_VERSION}.tar",
      "iris-app-${IRIS_VERSION}.tar",
      "iris-worker-${IRIS_VERSION}.tar",
      "iris-nginx-${IRIS_VERSION}.tar"
    ],
    "binaries": [
      "${VELO_BINARY}"
    ],
    "include_source": ${INCLUDE_SOURCE}
  }
}
EOF

echo "  Created manifest.json"

# ===========================================
# 6. Create tar.gz package
# ===========================================
echo ""
echo "=== Creating Package Archive ==="
cd /tmp
tar -czvf "${OUTPUT_FILE}" "${PACKAGE_NAME}"

# Get final size
PACKAGE_SIZE=$(du -h "${OUTPUT_FILE}" | cut -f1)

# ===========================================
# 7. Cleanup
# ===========================================
echo ""
echo "=== Cleanup ==="
rm -rf "${PACKAGE_DIR}"
echo "  Removed temporary directory"

# ===========================================
# Summary
# ===========================================
echo ""
echo "=============================================="
echo "  Package Created Successfully!"
echo "=============================================="
echo ""
echo "Output file: ${OUTPUT_FILE}"
echo "Size: ${PACKAGE_SIZE}"
echo ""
echo "Contents:"
echo "  - Docker images for ELK ${ELK_VERSION}, Timesketch ${TS_VERSION}, IRIS ${IRIS_VERSION}"
echo "  - Plaso ${PLASO_VERSION}"
echo "  - Velociraptor binary v${VELO_ACTUAL_VERSION}"
if [ "${INCLUDE_SOURCE}" = "true" ]; then
    echo "  - Backend and frontend source files"
fi
echo ""
echo "To use this package:"
echo "  1. Transfer ${OUTPUT_FILE} to the air-gapped machine"
echo "  2. Go to Settings > General > Upgrade (Offline)"
echo "  3. Upload the package file"
echo "  4. Review the versions and click Start Upgrade"
echo ""
