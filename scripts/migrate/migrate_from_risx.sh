#!/bin/bash
# migrate_from_risx.sh — turnkey in-place migration: risx-mssp -> intact,
# preserving the Velociraptor deployment (CA, nonce, server_urls, datastore)
# so every already-deployed client reconnects with its existing client_id.
#
# Run as the platform user (NOT root; sudo is used where needed):
#   bash scripts/migrate/migrate_from_risx.sh [options]
#
# Options:
#   --force               proceed past the ORANGE (<=0.6.x) compat gate
#   --datastore-mode M    copy (default; backup stays isolated) | bind
#                         (volume binds the backup dir — 1x disk, no isolated
#                         rollback copy; for very large datastores)
#   --release TAG         install a specific intact release (default: latest)
#   --from-dir DIR        use an already-downloaded intact tree (air-gap)
#   --intact-dir DIR      install destination (default: ~/intact)
#   --backup-dir DIR      reuse/place the phase-1 backup here
#   --skip-remove         leave risx-mssp on disk (stopped) instead of
#                         deleting it — needs 3x disk, extra-cautious mode
#
# Environment: GITHUB_TOKEN (repo read), RISX_ROOT (override discovery),
#              EDITOR (config editor, default nano)
#
# Phases: 0 preflight -> 1 backup -> 2 remove risx -> 3 download intact ->
#         4 config edit (guarded) -> 5 transplant + install.sh -> 6 verify ->
#         7 fleet-upgrade guidance.  See docs/RISX_MIGRATION.md.

set -o pipefail
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/risx_lib.sh"

FORCE=0
DATASTORE_MODE=copy
RELEASE_TAG=""
FROM_DIR=""
INTACT_DIR="${INTACT_DIR:-}"
BACKUP_DIR="${BACKUP_DIR:-}"
SKIP_REMOVE=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --force)            FORCE=1 ;;
        --datastore-mode)   DATASTORE_MODE="$2"; shift ;;
        --release)          RELEASE_TAG="$2"; shift ;;
        --from-dir)         FROM_DIR="$2"; shift ;;
        --intact-dir)       INTACT_DIR="$2"; shift ;;
        --backup-dir)       BACKUP_DIR="$2"; shift ;;
        --skip-remove)      SKIP_REMOVE=1 ;;
        -h|--help)          sed -n '2,30p' "$0"; exit 0 ;;
        *) die "unknown option: $1 (see --help)" ;;
    esac
    shift
done
[[ "$DATASTORE_MODE" == "copy" || "$DATASTORE_MODE" == "bind" ]] \
    || die "--datastore-mode must be copy or bind"
[[ "$(id -u)" -eq 0 ]] && die "run as the platform user, not root (the \
script calls sudo itself where needed)"

command -v docker  >/dev/null || die "docker is required"
command -v python3 >/dev/null || die "python3 is required"
python3 -c 'import yaml' 2>/dev/null || die "python3-yaml is required"

say "risx-mssp -> intact migration (in-place). The ONLY data preserved is"
say "Velociraptor (clients keep connecting; history survives). Everything"
say "else is removed and intact starts fresh."
confirm "Continue?" || exit 1

# Resume mode: risx already removed by an earlier run that failed later on —
# everything needed lives in the backup, which becomes the preflight source.
RESUME=0
if [[ -n "$BACKUP_DIR" && -f "$BACKUP_DIR/velociraptor/server.config.yaml" ]] \
    && ! discover_risx optional; then
    say "risx-mssp is already removed — RESUMING from backup $BACKUP_DIR"
    RESUME=1
    RISX_ROOT="$(dirname "$BACKUP_DIR")/setup_platform"   # for disk math only
    VELO_DIR=""
    VELO_DATA="$BACKUP_DIR/velociraptor"
elif [[ -z "${RISX_ROOT:-}" || ! -d "${RISX_ROOT:-}" ]]; then
    discover_risx
fi
preflight

if [[ "$RESUME" == "1" ]]; then
    say "phases 1-2 skipped (already done before the resume)"
elif [[ -n "$BACKUP_DIR" && -f "$BACKUP_DIR/velociraptor/server.config.yaml" ]]; then
    # Reuse an existing backup (re-run after a failure) instead of re-copying.
    say "reusing existing backup at $BACKUP_DIR"
    docker stop velociraptor >/dev/null 2>&1 || true
else
    backup_velo
fi

if [[ "$RESUME" == "1" ]]; then
    :
elif [[ "$SKIP_REMOVE" == "1" ]]; then
    say "=== Phase 2: SKIPPED (--skip-remove) — stopping risx-mssp only ==="
    for d in "$RISX_ROOT"/workdir/*/; do
        compgen -G "$d/docker-compose.y*ml" >/dev/null \
            && (cd "$d" && docker compose stop >/dev/null 2>&1) || true
    done
else
    remove_risx
fi

download_intact
edit_config
seed_and_install
verify_migration
fleet_upgrade_hint

say "MIGRATION COMPLETE."
say "  intact        : $INTACT_DIR (GUI: https://$INTACT_DOMAIN/)"
say "  velo backup   : $BACKUP_DIR  <- delete BY HAND once you are satisfied"
[[ "$DATASTORE_MODE" == "bind" ]] \
    && warn "bind mode: the backup dir IS the live datastore — do NOT delete it"
