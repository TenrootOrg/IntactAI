#!/usr/bin/env bash
# Bring the HOST's Docker and apt packages up to what a release expects.
#
# Deliberately separate from `upgrade.sh`, and deliberately run by a person.
#
# WHY IT IS NOT PART OF AN UPGRADE. The upgrade engine executes inside a helper
# container (services/upgrade_launcher.py, `docker run -d`, no restart policy).
# Installing docker-ce restarts the Docker daemon, which kills that container
# mid-run and leaves an interrupted apt behind -- broken dpkg state on the host
# is a worse outcome than the drift it was trying to fix. A container also
# cannot apt-get its host at all. So the upgrade REPORTS the drift
# (lib/upgrade/hostdeps.sh) and this script is what acts on it.
#
# THIS RESTARTS DOCKER. Every container on the box goes down and comes back,
# including the dashboard. That is the whole reason it is a separate,
# deliberate action rather than something that happens to you.
#
# Usage:
#   sudo bash scripts/update_host_deps.sh --package <dir|system-bundle.tar>
#   sudo bash scripts/update_host_deps.sh --tag <release>      (downloads it)
#   sudo bash scripts/update_host_deps.sh --package <...> --dry-run
#
# Reuses lib/deps.sh -- the same code install.sh uses for the air-gap path.
# None of that machinery was ever the problem; it was simply unreachable from
# anywhere but a fresh install.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_FILE="${SCRIPT_DIR}/data/tmp/update-host-deps.log"
mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true

for _lib in common config docker release deps; do
    # shellcheck source=/dev/null
    source "${SCRIPT_DIR}/lib/${_lib}.sh" || {
        echo "Cannot source lib/${_lib}.sh" >&2; exit 2; }
done

SRC=""
TAG=""
DRY=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --package)   SRC="${2:-}"; shift 2 ;;
        --package=*) SRC="${1#*=}"; shift ;;
        --tag)       TAG="${2:-}"; shift 2 ;;
        --tag=*)     TAG="${1#*=}"; shift ;;
        --dry-run)   DRY=1; shift ;;
        --help|-h)   sed -n '2,26p' "$0" | sed 's/^# \?//'; exit 0 ;;
        *) echo "Unknown option: $1" >&2; exit 2 ;;
    esac
done

if [[ -z "$SRC" && -z "$TAG" ]]; then
    echo "Give --package <dir|tar> or --tag <release>." >&2
    echo "Try: sudo bash scripts/update_host_deps.sh --help" >&2
    exit 2
fi
if (( EUID != 0 )); then
    log_error "This installs host packages; run it with sudo."
    exit 2
fi

# ── locate the bundle ─────────────────────────────────────────────────────
# A directory (the release page as downloaded), the bundle tar itself, or a
# tag to fetch. Same three shapes install.sh accepts, via the same helpers.
BUNDLE_SRC=""
if [[ -n "$SRC" ]]; then
    if [[ -d "$SRC" ]]; then
        if [[ -d "${SRC}/system-bundle" ]]; then
            BUNDLE_SRC="${SRC}/system-bundle"
        else
            BUNDLE_SRC="$(find "$SRC" -maxdepth 1 -name '*-system-bundle.tar' 2>/dev/null | head -1)"
        fi
    elif [[ -f "$SRC" ]]; then
        BUNDLE_SRC="$SRC"
    fi
    if [[ -z "$BUNDLE_SRC" ]]; then
        log_error "No *-system-bundle.tar found in: ${SRC}"
        log_error "  A release carries one; a package built by prepare_package.sh does not"
        log_error "  (its index lists only module assets). Point this at the release"
        log_error "  directory you downloaded, or use --tag."
        exit 1
    fi
else
    log_info "Fetching the dependency bundle for ${TAG}…"
    download_system_bundle "$TAG" "${SCRIPT_DIR}/data/tmp/system-bundle-pkg"
    case $? in
        0) BUNDLE_SRC="${SCRIPT_DIR}/data/tmp/system-bundle-pkg/system-bundle" ;;
        1) log_error "Release ${TAG} publishes no system bundle."; exit 1 ;;
        *) log_error "Could not fetch the dependency bundle for ${TAG}."; exit 1 ;;
    esac
fi

_stage_system_bundle_from_source "$BUNDLE_SRC" || exit 1
BUNDLE_DIR="$_STAGED_BUNDLE_DIR"
_verify_system_bundle_os_match "$BUNDLE_DIR" || exit 1

# ── what would change ─────────────────────────────────────────────────────
# Printed before anything is touched, and it is the whole of --dry-run.
_upstream() { local v="${1#*:}"; printf '%s' "${v%%-*}"; }
_bundle_version() {
    awk -v want="$1" '
        $1 == "Package:" { pkg = $2 }
        $1 == "Version:" && pkg == want { print $2; exit }' "${BUNDLE_DIR}/Packages" 2>/dev/null
}

HAVE_DOCKER="$(docker version --format '{{.Server.Version}}' 2>/dev/null || echo unknown)"
WANT_DOCKER="$(_upstream "$(_bundle_version docker-ce)")"
log_info ""
log_info "Host dependency update"
log_info "  bundle:    ${BUNDLE_DIR}"
log_info "  docker:    ${HAVE_DOCKER} -> ${WANT_DOCKER:-?}"
log_info ""

if [[ -n "$WANT_DOCKER" && "$HAVE_DOCKER" == "$WANT_DOCKER" ]]; then
    log_success "The host already runs the version this release expects. Nothing to do."
    exit 0
fi

if (( DRY )); then
    log_info "--dry-run: nothing was changed."
    exit 0
fi

log_warn "Docker's daemon will restart. Every container on this box — including"
log_warn "the dashboard — goes down and comes back. Do not interrupt this."
log_info ""

# ── apply ─────────────────────────────────────────────────────────────────
# The packages are NAMED rather than derived from _missing_host_deps(), which
# is what install_dependencies_from_package() uses. That function's job is to
# fill gaps on a fresh box, so it skips anything already present -- and an
# out-of-date Docker is present. Naming them makes apt upgrade them to the
# bundle's version, which is the entire point here.
if ! _apt_install_from_bundle "$BUNDLE_DIR" \
        docker-ce docker-ce-cli containerd.io docker-compose-plugin; then
    log_error "Failed to install from the bundle. See ${LOG_FILE}"
    log_error "  The previous packages are untouched unless apt got part way;"
    log_error "  check 'dpkg -l docker-ce' and 'systemctl status docker'."
    exit 1
fi

# ── confirm ───────────────────────────────────────────────────────────────
NOW_DOCKER="$(docker version --format '{{.Server.Version}}' 2>/dev/null || echo unknown)"
log_info ""
if [[ "$NOW_DOCKER" == "$WANT_DOCKER" ]]; then
    log_success "Docker is now ${NOW_DOCKER}."
else
    log_warn "Docker reports ${NOW_DOCKER}, expected ${WANT_DOCKER}."
    log_warn "  If the daemon is still starting, re-check in a moment:"
    log_warn "    docker version --format '{{.Server.Version}}'"
fi

# The containers come back on their own only if they have a restart policy;
# say so rather than assuming.
log_info ""
log_info "Check the appliance came back up:"
log_info "  docker ps"
log_info "  sudo bash ${SCRIPT_DIR}/install.sh --verify   # if anything is missing"
exit 0
