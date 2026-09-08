#!/bin/bash
# Intact.AI — adopt another Velociraptor server's identity on an ALREADY-INSTALLED box.
#
# WHY THIS EXISTS. A customer's old risx-mssp box has a large deployed fleet.
# The platform is being retired, but the clients must keep checking in against a
# new Intact appliance. A Velociraptor client is pinned to its server by three
# things only -- Client.ca_certificate, Client.nonce and Client.server_urls --
# and Velociraptor's own guidance for moving a server is to re-use the same
# configuration file on the new machine. Client records are NOT needed: a client
# re-enrols and keeps its client_id.
#
# scripts/migrate/migrate_from_risx.sh already does this, but only as part of a
# whole-platform replacement that ends in install.sh, i.e. BEFORE the first
# install. deploy_velociraptor() short-circuits once the container is running
# (lib/modules/velociraptor.sh:23-26), so that path cannot adopt a config onto a
# box that is already up. This script is that missing path, and nothing else:
# it takes ONE file from the old box and makes this Velociraptor answer for it.
#
# Take from the old box:
#   /home/<user>/setup_platform/workdir/velociraptor/velociraptor/server.config.yaml
# client.config.yaml and api.config.yaml are DERIVED -- the entrypoint mints
# both on every boot from whatever CA is in server.config.yaml -- so they are
# neither needed nor wanted.
#
# NOT automatic, and never part of an install or upgrade. Adopting a foreign CA
# cuts off anything enrolled against this box's current one, so it is a trade-off
# only an operator can make.
#
# THE ONE THING THIS CANNOT DO: make the box reachable. Clients dial
# Client.server_urls verbatim. This appliance must answer at that address on
# 8000, by taking the old box's IP/DNS or by repointing DNS. The script checks
# and refuses when it diverges; it cannot fix it.
#
# Usage: sudo ./scripts/adopt_velociraptor_identity.sh --from <dir|server.config.yaml>
#            [--domain HOST] [--datastore DIR] [-y|--yes] [--dry-run]

set -o pipefail
umask 022

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/config.yaml"
LOG_FILE="${SCRIPT_DIR}/adopt_velo_identity_$(date +%Y%m%d_%H%M%S).log"
export INTACT_HOST_PATH="$SCRIPT_DIR"

source "${SCRIPT_DIR}/lib/common.sh"    # log_*, check_root
source "${SCRIPT_DIR}/lib/config.sh"    # read_config

FROM=""
DOMAIN=""
DATASTORE_SRC=""
ASSUME_YES=0
DRY_RUN=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --from)        FROM="${2:-}"; shift 2 ;;
        --from=*)      FROM="${1#*=}"; shift ;;
        --domain)      DOMAIN="${2:-}"; shift 2 ;;
        --domain=*)    DOMAIN="${1#*=}"; shift ;;
        --datastore)   DATASTORE_SRC="${2:-}"; shift 2 ;;
        --datastore=*) DATASTORE_SRC="${1#*=}"; shift ;;
        -y|--yes)      ASSUME_YES=1; shift ;;
        --dry-run)     DRY_RUN=1; shift ;;
        -h|--help)
            sed -n '2,46p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
            exit 0 ;;
        *) echo "Unknown option: $1" >&2; echo "Try: $0 --help" >&2; exit 2 ;;
    esac
done

DOCKER_BIN="${DOCKER_BIN:-docker}"
DATA="${SCRIPT_DIR}/data/velociraptor"
HOST_CFG="${DATA}/server.config.yaml"
COMPOSE="${SCRIPT_DIR}/modules/velociraptor/docker-compose.yaml"
TRANSFORM="${SCRIPT_DIR}/scripts/migrate/transform_config.py"

# --- helpers ---------------------------------------------------------------

# sha256[:16] of the CA private key, falling back to the client's copy of the CA
# certificate (they change in lockstep). The SAME fingerprint the upgrade and
# restore_velociraptor_ca.sh print, so all three can be compared directly.
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

# The host a deployed client actually dials, out of Client.server_urls.
_urls_host() {
    python3 - "$1" <<'PY' 2>/dev/null
import sys
try:
    import yaml
    d = yaml.safe_load(open(sys.argv[1], encoding="utf-8")) or {}
except Exception:
    print(""); raise SystemExit(0)
urls = (d.get("Client") or {}).get("server_urls") or []
print(urls[0].split("://", 1)[-1].split(":", 1)[0].split("/", 1)[0] if urls else "")
PY
}

# Does the DERIVED client config carry the trust material of this server config?
# Compares like-for-like: a server config's identity fingerprint is taken from
# CA.private_key, but a client config has no CA section at all, so fingerprinting
# it falls back to Client.ca_certificate and the two can NEVER match. Comparing
# them anyway made a correct adoption report a scary mismatch. What actually
# binds a client is the ca_certificate, the nonce and the URL -- so check those,
# by value, and say which one differs.
_client_trust_ok() {
    python3 - "$1" "$2" <<'PY' 2>/dev/null
import sys
try:
    import yaml
    srv = yaml.safe_load(open(sys.argv[1], encoding="utf-8")) or {}
    cli = yaml.safe_load(open(sys.argv[2], encoding="utf-8")) or {}
except Exception as exc:
    print(f"unreadable: {exc}"); raise SystemExit(1)
s, c = srv.get("Client") or {}, cli.get("Client") or {}
bad = [n for n, a, b in (("ca_certificate", s.get("ca_certificate"), c.get("ca_certificate")),
                         ("nonce", s.get("nonce"), c.get("nonce")),
                         ("server_urls", s.get("server_urls"), c.get("server_urls")))
       if a != b]
print("ok" if not bad else "differs: " + ", ".join(bad))
raise SystemExit(0 if not bad else 1)
PY
}

# The nonce is a SHARED SECRET; never print it, only whether it changed.
_nonce_fp() {
    python3 - "$1" <<'PY' 2>/dev/null
import hashlib, sys
try:
    import yaml
    d = yaml.safe_load(open(sys.argv[1], encoding="utf-8")) or {}
except Exception:
    print(""); raise SystemExit(0)
n = (d.get("Client") or {}).get("nonce") or ""
print(hashlib.sha256(n.encode()).hexdigest()[:12] if n else "")
PY
}

_is_local_address() {
    local host="$1" ip
    [[ -z "$host" ]] && return 1
    for ip in $(hostname -I 2>/dev/null) 127.0.0.1 localhost; do
        [[ "$host" == "$ip" ]] && return 0
    done
    # a DNS name that resolves to one of our addresses counts too
    for ip in $(getent ahostsv4 "$host" 2>/dev/null | awk '{print $1}' | sort -u); do
        for mine in $(hostname -I 2>/dev/null); do
            [[ "$ip" == "$mine" ]] && return 0
        done
    done
    return 1
}

_die() { log_error "$1"; [[ -n "${2:-}" ]] && log_error "  $2"; exit 1; }

# --- guards ----------------------------------------------------------------

log_info "Velociraptor identity adoption — $(date '+%Y-%m-%d %H:%M:%S')"
log_info "Log: ${LOG_FILE}"

[[ -f "$CONFIG_FILE" && -f "$COMPOSE" ]] \
    || _die "This is not an Intact.AI appliance directory (${SCRIPT_DIR})." \
            "Run it from the install root: sudo ./scripts/$(basename "$0") --from …"
[[ -f "$TRANSFORM" ]] \
    || _die "Missing ${TRANSFORM} — this script reuses it rather than reimplementing it."
[[ -n "$FROM" ]] \
    || _die "--from is required." \
            "Point it at the old box's server.config.yaml (or the directory holding it)."

# --from may be the file itself or the directory it lives in.
SRC="$FROM"
[[ -d "$SRC" ]] && SRC="${SRC%/}/server.config.yaml"
[[ -f "$SRC" ]] || _die "No server.config.yaml at ${SRC}"

(( DRY_RUN )) || check_root

if [[ -z "$DOMAIN" ]]; then
    DOMAIN="$(read_config "['domain']")"
    [[ -n "$DOMAIN" ]] || _die "Could not read 'domain' from ${CONFIG_FILE}; pass --domain."
fi

# --- read both identities ---------------------------------------------------

IN_FP="$(_ca_fp "$SRC")"
IN_NONCE="$(_nonce_fp "$SRC")"
IN_HOST="$(_urls_host "$SRC")"
[[ -n "$IN_FP" ]] || _die "Could not read a CA out of ${SRC} — refusing to guess."

CUR_FP=""; CUR_NONCE=""
[[ -f "$HOST_CFG" ]] && { CUR_FP="$(_ca_fp "$HOST_CFG")"; CUR_NONCE="$(_nonce_fp "$HOST_CFG")"; }

log_info "  incoming CA        : ${IN_FP}"
log_info "  CA on this box     : ${CUR_FP:-<none>}"
log_info "  clients dial       : ${IN_HOST:-<unknown>}"
log_info "  this box's domain  : ${DOMAIN}"

if [[ -n "$CUR_FP" && "$CUR_FP" == "$IN_FP" && "$CUR_NONCE" == "$IN_NONCE" ]]; then
    log_success "This box already runs that identity (${IN_FP}) — nothing to do."
    exit 0
fi

# --- the precondition the config cannot fix ---------------------------------

REACHABLE=1
if [[ -z "$IN_HOST" ]]; then
    log_warn "The incoming config lists no server_urls — clients have nothing to dial."
    REACHABLE=0
elif [[ "$IN_HOST" != "$DOMAIN" ]] && ! _is_local_address "$IN_HOST"; then
    REACHABLE=0
    echo
    log_warn "EVERY DEPLOYED CLIENT DIALS ${IN_HOST} AND THIS BOX IS NOT IT."
    log_warn "  Clients use Client.server_urls verbatim. Adopting the identity here"
    log_warn "  does not make them arrive: this appliance must answer at ${IN_HOST}"
    log_warn "  on port 8000 — take the old box's IP/DNS, or repoint DNS to here."
    log_warn "  (this box: $(hostname -I 2>/dev/null | tr -s ' '), domain ${DOMAIN})"
    echo
fi
(( REACHABLE )) && log_success "  reachability: ${IN_HOST} resolves to this box"

# --- what adoption costs ----------------------------------------------------

if [[ -n "$CUR_FP" ]]; then
    echo
    log_warn "Adopting ${IN_FP} REPLACES this box's Velociraptor identity (${CUR_FP}):"
    log_warn "  · anything enrolled against ${CUR_FP} stops reporting until re-deployed"
    log_warn "  · the incoming obfuscation_nonce makes this box's existing Velociraptor"
    log_warn "    datastore files unreadable (they are named with the current one)"
    log_warn "  The current config is backed up first, so this is reversible."
    echo
fi

if (( DRY_RUN )); then
    log_info "--dry-run: nothing was changed."
    log_info "  would transform : ${SRC}"
    log_info "             into : ${HOST_CFG}  (domain ${DOMAIN})"
    log_info "  would delete    : client.config.yaml api.config.yaml (regenerated on boot)"
    [[ -n "$DATASTORE_SRC" ]] && log_info "  would seed datastore from: ${DATASTORE_SRC}"
    log_info "  reachability    : $( ((REACHABLE)) && echo OK || echo "DIVERGES (${IN_HOST})" )"
    exit 0
fi

if (( ! ASSUME_YES )); then
    if (( ! REACHABLE )); then
        log_warn "Refusing by default: the clients' address does not point here."
        log_warn "  Re-run with -y if you are repointing DNS/IP separately."
        exit 2
    fi
    read -r -p "Adopt Velociraptor identity ${IN_FP} on this box? [y/N] " ans
    [[ "$ans" =~ ^[Yy]$ ]] || { log_info "Aborted — nothing changed."; exit 0; }
fi

# --- transform BEFORE touching anything running ------------------------------

STAGED="$(mktemp -t velo-adopt-XXXXXX.yaml)" || _die "Could not create a temp file"
trap 'rm -f "$STAGED"' EXIT

log_info "Transforming the legacy config to intact's layout…"
# The nonce is echoed by the transform; keep it out of the log file.
if ! python3 "$TRANSFORM" "$SRC" "$STAGED" --domain "$DOMAIN" 2>&1 \
        | sed -E 's/nonce=[^ ]+/nonce=<redacted>/' | tee -a "$LOG_FILE"; then
    _die "transform_config.py refused this file — see the errors above." \
         "Nothing was changed."
fi
[[ -s "$STAGED" ]] || _die "The transform produced an empty file; nothing was changed."

# --- swap --------------------------------------------------------------------

log_info "Stopping Velociraptor…"
"$DOCKER_BIN" compose -f "$COMPOSE" stop >>"$LOG_FILE" 2>&1 \
    || log_warn "  compose stop reported a problem; continuing"

BAK="${SCRIPT_DIR}/data/tmp/velo-before-adopt-$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BAK" || _die "Could not create ${BAK}"
for f in server.config.yaml client.config.yaml api.config.yaml; do
    [[ -f "${DATA}/${f}" ]] && cp -p "${DATA}/${f}" "${BAK}/${f}"
done
log_info "  current config backed up to ${BAK}"

_rollback() {
    log_warn "Rolling back to the previous config…"
    for f in server.config.yaml client.config.yaml api.config.yaml; do
        [[ -f "${BAK}/${f}" ]] && cp -p "${BAK}/${f}" "${DATA}/${f}"
    done
    "$DOCKER_BIN" compose -f "$COMPOSE" up -d --no-build --pull never >>"$LOG_FILE" 2>&1
}

mkdir -p "$DATA" || _die "Could not create ${DATA}"
cp "$STAGED" "$HOST_CFG" || { _rollback; _die "Could not write ${HOST_CFG}"; }
chmod 0600 "$HOST_CFG"

# DELETED, not overwritten: entrypoint.sh regenerates both on every boot from
# whatever CA server.config.yaml now holds. Leaving the old ones in place would
# hand the backend an api.config.yaml signed by a CA the server no longer has.
rm -f "${DATA}/client.config.yaml" "${DATA}/api.config.yaml"
log_success "  server.config.yaml adopted; derived configs cleared for regeneration"

if [[ -n "$DATASTORE_SRC" ]]; then
    if [[ ! -d "$DATASTORE_SRC" ]]; then
        _rollback; _die "--datastore ${DATASTORE_SRC} is not a directory"
    fi
    VOL="$("$DOCKER_BIN" volume inspect -f '{{.Mountpoint}}' \
           velociraptor_velociraptor_datastore 2>/dev/null)"
    if [[ -z "$VOL" || ! -d "$VOL" ]]; then
        log_warn "  datastore volume not found; skipping the datastore seed"
    else
        log_info "Seeding the datastore (this can take a while)…"
        # Same exclusions as risx_lib.sh:481-491 — config, the binary and the
        # repacked installers are intact's, only the RECORDS come across.
        rsync -a --info=stats2 \
            --exclude 'server.config.yaml*' --exclude 'client.config.yaml' \
            --exclude 'api.config.yaml' --exclude 'velociraptor' \
            --exclude 'clients/linux' --exclude 'clients/mac' \
            --exclude 'clients/windows' --exclude '.env' \
            "${DATASTORE_SRC%/}/" "${VOL}/" >>"$LOG_FILE" 2>&1 \
            || log_warn "  rsync reported a problem; see ${LOG_FILE}"
        log_success "  datastore seeded from ${DATASTORE_SRC}"
    fi
fi

log_info "Starting Velociraptor…"
"$DOCKER_BIN" compose -f "$COMPOSE" up -d --no-build --pull never >>"$LOG_FILE" 2>&1 || {
    log_error "Velociraptor did not come back up — see ${LOG_FILE}"
    log_error "  the previous config is at ${BAK}"
    exit 1
}

# --- verify -------------------------------------------------------------------

log_info "Verifying…"
FINAL_FP=""
for _ in $(seq 1 30); do
    FINAL_FP="$(_ca_fp "$HOST_CFG")"
    [[ -n "$FINAL_FP" ]] && break
    sleep 2
done
if [[ "$FINAL_FP" != "$IN_FP" ]]; then
    log_error "CA is ${FINAL_FP:-<unreadable>}, expected ${IN_FP} — adoption did not take."
    log_error "  The previous config is at ${BAK}"
    exit 1
fi
log_success "  CA in use: ${FINAL_FP}"

# The entrypoint must have re-derived both from the adopted CA.
DERIVED_OK=0
for _ in $(seq 1 45); do
    if [[ -f "${DATA}/api.config.yaml" && -f "${DATA}/client.config.yaml" ]]; then
        DERIVED_OK=1; break
    fi
    sleep 2
done
if (( DERIVED_OK )); then
    TRUST="$(_client_trust_ok "$HOST_CFG" "${DATA}/client.config.yaml")"
    if [[ "$TRUST" == "ok" ]]; then
        log_success "  client.config.yaml carries the adopted CA, nonce and server_urls"
        log_success "  api.config.yaml regenerated from the adopted CA"
    else
        log_warn "  the regenerated client.config.yaml ${TRUST}"
        log_warn "  clients validate exactly those fields — check: docker logs intact_velociraptor"
    fi
else
    log_warn "  the derived configs have not appeared yet — check: docker logs intact_velociraptor"
fi

if "$DOCKER_BIN" ps --filter 'name=^intact_velociraptor$' --format '{{.Status}}' 2>/dev/null \
        | grep -q '^Up'; then
    log_success "  intact_velociraptor is up"
else
    log_error "  intact_velociraptor is not running — see ${LOG_FILE}"
    log_error "  the previous config is at ${BAK}"
    exit 1
fi

# --- WAIT FOR THE FRONTEND TO ACTUALLY LISTEN ---------------------------------
#
# "Up" is not "serving", and everything above is satisfied roughly a MINUTE
# before a client could connect. entrypoint.sh writes client.config.yaml (:110)
# and api.config.yaml (:114), then REPACKS the Linux, Mac and Windows client
# binaries (:135-210, measured 63s on a real box), and only then execs the
# frontend (:225). The service has no healthcheck, so `docker ps` says Up the
# moment the container starts.
#
# Without this wait the script printed "Adopted … clients will reconnect" while
# nothing was listening on 8000. Reported from a real migration: the operator
# saw no clients, restarted containers, and the restart took the credit for the
# time that had simply passed. Waiting here is the fix; the restart was not.
log_info "Waiting for the Velociraptor frontend to accept connections…"
FRONTEND_UP=0
for _ in $(seq 1 90); do          # 90 x 2s = 180s, against an observed 8-63s
    # The PUBLISHED port, probed from the host — exactly the socket a deployed
    # client dials. Checked from outside rather than inside the container on
    # purpose: the velociraptor image ships neither `ss` nor `netstat`, so an
    # in-container probe silently never succeeds (measured).
    if timeout 3 bash -c "</dev/tcp/127.0.0.1/8000" 2>/dev/null; then
        FRONTEND_UP=1; break
    fi
    # Belt and braces for a box that publishes 8000 somewhere other than
    # loopback: the line the frontend prints once it is serving.
    if "$DOCKER_BIN" logs --tail 200 intact_velociraptor 2>&1 \
            | grep -q 'Frontend is ready to handle client TLS requests'; then
        FRONTEND_UP=1; break
    fi
    sleep 2
done
if (( FRONTEND_UP )); then
    log_success "  the frontend is listening — clients can connect"
else
    log_warn "  the frontend is still not listening after 180s."
    log_warn "  It repacks client installers before serving, which is slow on a"
    log_warn "  small box. Watch it finish:  docker logs -f intact_velociraptor"
    log_warn "  Do NOT restart the container — that starts the repack over."
fi

# Belt and braces, and deliberately NOT load-bearing: nginx already re-resolves
# a moved container by itself (modules/nginx/config/nginx.conf:16 sets
# `resolver 127.0.0.11 valid=30s` and :149-150 uses the variable proxy_pass
# idiom, so there is no pinned upstream to go stale — fixed in 87c30ce8). This
# only drops any upgraded/WebSocket connections a dashboard was holding to the
# container we just stopped, so the Velociraptor tab does not sit on a dead
# socket. Cheap, and it cannot make anything worse.
#
# intact_velociraptor is deliberately NOT restarted here: it would re-run the
# 60-second client repack and undo the wait above.
if "$DOCKER_BIN" ps --filter 'name=^intact_nginx$' --format '{{.Names}}' 2>/dev/null \
        | grep -q .; then
    "$DOCKER_BIN" restart intact_nginx >>"$LOG_FILE" 2>&1 \
        && log_success "  intact_nginx restarted (drops stale proxied connections)" \
        || log_warn "  could not restart intact_nginx; harmless — see ${LOG_FILE}"
fi

echo
log_success "Adopted Velociraptor identity ${IN_FP}."
log_info "  Clients dialling ${IN_HOST} will reconnect with their existing client_id."
log_info "  Watch them arrive:"
log_info "    docker exec intact_velociraptor ./velociraptor --config \\"
log_info "      /velociraptor/server.config.yaml query 'SELECT * FROM clients()'"
log_info "  Previous config kept at ${BAK}"
(( REACHABLE )) || log_warn "  REMINDER: this box still does not answer at ${IN_HOST}."
