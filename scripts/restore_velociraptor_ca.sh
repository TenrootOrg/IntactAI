#!/bin/bash
# Intact.AI — restore the original Velociraptor CA from the legacy config volume.
#
# WHY THIS EXISTS. Up to 0726 Velociraptor kept /velociraptor -- including
# server.config.yaml, i.e. THE CA -- in a named volume (`velociraptor_data`,
# compose-namespaced to `velociraptor_velociraptor_data`). The host-mount
# conversion replaced that with data/velociraptor and dropped the volume from
# the compose file, deferring to a migrate_velociraptor_config_to_host() that
# never existed in this tree. Any box upgraded before that migration was added
# therefore started against an EMPTY data dir, entrypoint.sh minted a brand new
# CA, and every client enrolled against the old one silently stopped reporting.
#
# The upgrade now migrates the CA forward on its own, and refuses to start when
# a legacy volume exists but no CA was recovered. This script is for the boxes
# that already went through the old path: their original CA is still sitting in
# the orphaned volume (nothing in the upgrade prunes volumes), and this puts it
# back.
#
# NOT part of any upgrade, and deliberately not automatic. Restoring the old CA
# cuts off anything enrolled since the box regenerated one -- that is a real
# trade-off only an operator can make, so it is its own deliberate command.
#
# Usage: sudo ./scripts/restore_velociraptor_ca.sh [-y|--yes] [--dry-run]

set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/config.yaml"
LOG_FILE="${SCRIPT_DIR}/restore_velo_ca_$(date +%Y%m%d_%H%M%S).log"
export INTACT_HOST_PATH="$SCRIPT_DIR"

source "${SCRIPT_DIR}/lib/common.sh"

ASSUME_YES=0
DRY_RUN=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        -y|--yes)   ASSUME_YES=1; shift ;;
        --dry-run)  DRY_RUN=1; shift ;;
        -h|--help)
            sed -n '2,25p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
            exit 0 ;;
        *) echo "Unknown option: $1" >&2; exit 2 ;;
    esac
done

(( DRY_RUN )) || check_root

DOCKER_BIN="${DOCKER_BIN:-docker}"
DATA="${SCRIPT_DIR}/data/velociraptor"
HOST_CFG="${DATA}/server.config.yaml"

# sha256[:16] of the CA private key, falling back to the client's copy of the CA
# certificate (they change in lockstep). Same fingerprint the upgrade prints, so
# the two can be compared directly.
_ca_fp() {
    python3 - "$1" <<'PY' 2>/dev/null
import hashlib, sys
try:
    import yaml
    d = yaml.safe_load(open(sys.argv[1], encoding="utf-8")) or {}
except Exception:
    print(""); raise SystemExit(0)
ca = (d.get("CA") or {}).get("private_key") \
     or (d.get("Client") or {}).get("ca_certificate") or ""
print(hashlib.sha256(ca.encode()).hexdigest()[:16] if ca else "")
PY
}

_legacy_volume() {
    local v
    while IFS= read -r v; do
        [[ "$v" == *velociraptor_data ]] && { printf '%s\n' "$v"; return 0; }
    done < <("$DOCKER_BIN" volume ls --format '{{.Name}}' 2>/dev/null)
    return 1
}

log_info "Velociraptor CA restore — $(date '+%Y-%m-%d %H:%M:%S')"
log_info "Log: ${LOG_FILE}"

VOL="$(_legacy_volume)" || {
    log_success "No legacy velociraptor config volume on this box — nothing to restore."
    log_info "  (A box installed at 0811 or later never had one.)"
    exit 0
}
log_info "Legacy volume: ${VOL}"

DRIVER="$("$DOCKER_BIN" volume inspect -f '{{.Driver}}' "$VOL" 2>/dev/null)"
if [[ "$DRIVER" != "local" ]]; then
    log_error "Volume ${VOL} uses the '${DRIVER:-unknown}' driver; its files cannot be read directly."
    exit 1
fi
MP="$("$DOCKER_BIN" volume inspect -f '{{.Mountpoint}}' "$VOL" 2>/dev/null)"
if [[ -z "$MP" || ! -d "$MP" ]]; then
    log_error "Volume ${VOL} has no readable mountpoint."
    exit 1
fi
if [[ ! -f "${MP}/server.config.yaml" ]]; then
    log_success "Volume ${VOL} holds no server.config.yaml — no CA to restore."
    exit 0
fi

OLD_FP="$(_ca_fp "${MP}/server.config.yaml")"
NEW_FP=""
[[ -f "$HOST_CFG" ]] && NEW_FP="$(_ca_fp "$HOST_CFG")"

log_info "  CA in the legacy volume : ${OLD_FP:-<unreadable>}"
log_info "  CA in use on this box   : ${NEW_FP:-<none>}"

if [[ -z "$OLD_FP" ]]; then
    log_error "Could not read a CA out of ${MP}/server.config.yaml — refusing to guess."
    exit 1
fi
if [[ -n "$NEW_FP" && "$NEW_FP" == "$OLD_FP" ]]; then
    log_success "Already running the original CA (${OLD_FP}) — nothing to do."
    exit 0
fi

echo
if [[ -z "$NEW_FP" ]]; then
    log_info "This box has no CA at all; the original will be put back."
else
    log_warn "This box is running a CA that was generated when it upgraded without"
    log_warn "the config migration. Restoring the original (${OLD_FP}) reconnects every"
    log_warn "client enrolled BEFORE that upgrade, and CUTS OFF anything enrolled since"
    log_warn "against ${NEW_FP}. The current config is backed up first, so this is"
    log_warn "reversible."
fi
echo

if (( DRY_RUN )); then
    log_info "--dry-run: nothing was changed."
    log_info "  would restore: server.config.yaml client.config.yaml api.config.yaml"
    log_info "  from: ${MP}"
    log_info "  to:   ${DATA}"
    exit 0
fi

if (( ! ASSUME_YES )); then
    read -r -p "Restore the original CA ${OLD_FP}? [y/N] " ans
    [[ "$ans" =~ ^[Yy]$ ]] || { log_info "Aborted — nothing changed."; exit 0; }
fi

# Stop the server before swapping the config out from under it, or it keeps
# serving the old one from memory and rewrites files on shutdown.
log_info "Stopping Velociraptor…"
"$DOCKER_BIN" compose -f "${SCRIPT_DIR}/modules/velociraptor/docker-compose.yaml" \
    stop >>"$LOG_FILE" 2>&1 || log_warn "  compose stop reported a problem; continuing"

BAK="${SCRIPT_DIR}/data/tmp/velo-ca-before-restore-$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BAK" || { log_error "Could not create ${BAK}"; exit 1; }
for f in server.config.yaml client.config.yaml api.config.yaml; do
    [[ -f "${DATA}/${f}" ]] && cp -p "${DATA}/${f}" "${BAK}/${f}"
done
log_info "  current config backed up to ${BAK}"

mkdir -p "$DATA" || { log_error "Could not create ${DATA}"; exit 1; }
n=0
for f in server.config.yaml client.config.yaml api.config.yaml; do
    if [[ -f "${MP}/${f}" ]]; then
        cp -p "${MP}/${f}" "${DATA}/${f}" || { log_error "  could not restore ${f}"; exit 1; }
        n=$((n + 1))
    fi
done
log_success "  restored ${n} config file(s) from ${VOL}"

log_info "Starting Velociraptor…"
"$DOCKER_BIN" compose -f "${SCRIPT_DIR}/modules/velociraptor/docker-compose.yaml" \
    up -d --no-build --pull never >>"$LOG_FILE" 2>&1 || {
    log_error "Velociraptor did not come back up — see ${LOG_FILE}"
    log_error "  the previous config is at ${BAK}"
    exit 1
}

FINAL_FP="$(_ca_fp "$HOST_CFG")"
if [[ "$FINAL_FP" == "$OLD_FP" ]]; then
    log_success "Velociraptor is running the original CA: ${FINAL_FP}"
    log_info "  Clients enrolled before the CA was regenerated should reconnect."
    log_info "  Anything enrolled against ${NEW_FP:-the previous CA} must be re-deployed."
    log_info "  The legacy volume ${VOL} was NOT modified."
else
    log_error "CA is ${FINAL_FP:-<unreadable>}, expected ${OLD_FP} — restore did not take."
    log_error "  The previous config is at ${BAK}"
    exit 1
fi
