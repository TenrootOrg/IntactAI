#!/bin/bash
# Build a synthetic upgrade package for testing upgrade.sh.
#
#   scripts/dev/make_test_package.sh <tag> <out.tar> module=version [module=version ...]
#
# Produces a real, fully-formed package -- correct manifest, correct per-file
# sha256 map, a source/intact tree -- carrying whatever pins you name. That is
# the only way to make every module actually swap: the real releases barely
# move any pins (20260726 -> 20260809 changes 2 of 9), so an upgrade between
# two of them skips seven modules as "already at target" and proves nothing.
#
# By default the package carries NO image tars, because upgrade.sh's
# _u_ensure_image checks the local docker store first and both the baseline
# and target images are already on a test box. Pass --with-images to docker
# save them in, which additionally exercises the tar-loading path.
#
# DEV ONLY. This fabricates a release; never point a real appliance at one.
set -euo pipefail

usage() { sed -n '2,20p' "$0" | sed 's/^# \?//'; exit "${1:-0}"; }

WITH_IMAGES=0
ARGS=()
for a in "$@"; do
    case "$a" in
        --with-images) WITH_IMAGES=1 ;;
        --help|-h) usage 0 ;;
        *) ARGS+=("$a") ;;
    esac
done
set -- "${ARGS[@]}"
(( $# >= 3 )) || usage 2

TAG="$1"; OUT="$2"; shift 2
PINS=("$@")

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
ROOT="${WORK}/intact-upgrade-${TAG}"
mkdir -p "${ROOT}/images" "${ROOT}/source/intact"

echo "[make-test-package] tag=${TAG}"

# The source tree the intact module mirrors in, and that the stage-0 re-exec
# hands over to. Excludes the things that must never travel in a package:
# the operator's config.yaml and .env files, live data, git history, logs.
if [[ -d "${REPO}/lib" ]]; then
    tar -C "$REPO" -cf - \
        --exclude='.git' --exclude='data' --exclude='backups' \
        --exclude='*.log' --exclude='config.yaml' --exclude='*/.env' \
        --exclude='__pycache__' --exclude='node_modules' \
        install.sh upgrade.sh lib scripts modules 2>/dev/null \
      | tar -C "${ROOT}/source/intact" -xf - 2>/dev/null || true
    echo "[make-test-package] staged source/intact"
fi

# Optional: docker save the target images so the tar-loading path runs too.
if (( WITH_IMAGES )); then
    for pin in "${PINS[@]}"; do
        mod="${pin%%=*}"; ver="${pin#*=}"
        case "$mod" in
            portainer)
                docker save -o "${ROOT}/images/portainer-ce-${ver}.tar"    "portainer/portainer-ce:${ver}"
                docker save -o "${ROOT}/images/portainer-agent-${ver}.tar" "portainer/agent:${ver}" ;;
            elk)
                docker save -o "${ROOT}/images/elasticsearch-${ver}.tar" "docker.elastic.co/elasticsearch/elasticsearch:${ver}"
                docker save -o "${ROOT}/images/kibana-${ver}.tar"        "docker.elastic.co/kibana/kibana:${ver}"
                docker save -o "${ROOT}/images/logstash-${ver}.tar"      "docker.elastic.co/logstash/logstash:${ver}" ;;
            iris)
                docker save -o "${ROOT}/images/iris-app-${ver}.tar"   "ghcr.io/dfir-iris/iriswebapp_app:${ver}"
                docker save -o "${ROOT}/images/iris-db-${ver}.tar"    "ghcr.io/dfir-iris/iriswebapp_db:${ver}"
                docker save -o "${ROOT}/images/iris-nginx-${ver}.tar" "ghcr.io/dfir-iris/iriswebapp_nginx:${ver}" ;;
            volweb)
                docker save -o "${ROOT}/images/volweb-backend-${ver}.tar"  "forensicxlab/volweb-backend:${ver}"
                docker save -o "${ROOT}/images/volweb-frontend-${ver}.tar" "forensicxlab/volweb-frontend:${ver}" ;;
            timesketch)
                docker save -o "${ROOT}/images/timesketch-${ver}.tar" "us-docker.pkg.dev/osdfir-registry/timesketch/timesketch:${ver}" ;;
            plaso)
                docker save -o "${ROOT}/images/plaso-${ver}.tar" "log2timeline/plaso:${ver}" ;;
        esac
        echo "[make-test-package] saved images for ${mod}=${ver}"
    done
fi

# Manifest last: the sha256 map must describe the tree as it finally is, and
# it is computed rather than copied. Merging manifests unions these maps and
# errors on a conflict; recomputing one would verify nothing.
python3 - "$ROOT" "$TAG" "${PINS[@]}" <<'PY'
import hashlib, json, os, sys
root, tag, pins = sys.argv[1], sys.argv[2], sys.argv[3:]
def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for c in iter(lambda: fh.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()
shas = {}
for r, _, files in os.walk(root):
    for f in files:
        full = os.path.join(r, f)
        rel = os.path.relpath(full, root)
        if rel == "manifest.json" or os.path.islink(full):
            continue
        shas[rel] = sha(full)
versions = dict(p.split("=", 1) for p in pins)
versions.setdefault("intact", tag)
json.dump({
    "package_version": "1.0",
    "created": "1970-01-01T00:00:00Z",
    "created_by": "make_test_package.sh",
    "versions": versions,
    "contents": {
        "release_tag": tag,
        "pins_source": "target-release",
        "sha256": shas,
    },
}, open(os.path.join(root, "manifest.json"), "w"), indent=2)
print("[make-test-package] manifest: %d pins, %d checksummed files"
      % (len(versions), len(shas)))
PY

mkdir -p "$(dirname "$OUT")"
tar -C "$WORK" -cf "$OUT" "intact-upgrade-${TAG}"
echo "[make-test-package] wrote ${OUT} ($(du -h "$OUT" | cut -f1))"
