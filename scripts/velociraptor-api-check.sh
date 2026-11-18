#!/bin/bash
# velociraptor-api-check.sh — is the backend's way into Velociraptor intact?
#
#   sudo bash scripts/velociraptor-api-check.sh          # check, change nothing
#   sudo bash scripts/velociraptor-api-check.sh --fix    # check, then repair
#
# Every Velociraptor feature of Intact (clients, hunts, collections, memory,
# offline collectors) goes through ONE identity: the Velociraptor user `api`,
# reached with the certificate in /velociraptor/api.config.yaml. Tested on
# 0.77.3 (2026-11-18), what breaks it:
#   - `api` deleted (Velociraptor GUI > Users)  -> "User not found: api". A
#     restart does NOT bring it back: the entrypoint re-creates the user only
#     when its stored password changes.
#   - its roles removed or reduced              -> "Permission denied ...".
#   - api.config.yaml missing/broken/stale      -> no connection; a restart
#     regenerates it from the server's CA.
#   - its password changed                      -> nothing (the backend uses
#     the certificate); reported, and reset with --fix.
# Repairs: `user add` (re-creates the user, sets both roles and the password
# Intact stored), then a restart -- a RUNNING server does not see a `user add`
# made from the command line until its process restarts. About 20 s; deployed
# clients reconnect by themselves.
#
# The stored password goes to Velociraptor through the container's environment
# (-e _P), never an argv, so it is not in `docker events` or `ps`. Everything
# printed also goes to velociraptor-api-check-<time>.log (mode 600) here.
# Exit: 0 healthy (or repaired), 1 a problem remains, 2 usage.

set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# The names are overridable only so the tests can run against a throwaway pair.
VELO="${INTACT_VELO_CONTAINER:-intact_velociraptor}"
BACKEND="${INTACT_BACKEND_CONTAINER:-intact_backend}"
API_USER=api
API_ROLES=api,administrator
CONN=intact_velociraptor:8001
WAIT="${VELO_API_WAIT:-120}"

FIX=0
case "${1:-}" in
    "") ;;
    --fix) FIX=1 ;;
    -h|--help) sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1 (see --help)" >&2; exit 2 ;;
esac
if [[ "${EUID}" -ne 0 ]]; then
    echo "Run as root: sudo bash scripts/velociraptor-api-check.sh${1:+ $1}" >&2; exit 2
fi
# shellcheck source=../lib/secrets.sh
source "$SCRIPT_DIR/lib/secrets.sh" || { echo "cannot load lib/secrets.sh" >&2; exit 2; }

LOG="$SCRIPT_DIR/velociraptor-api-check-$(date +%Y%m%d-%H%M%S).log"
( umask 077; : > "$LOG" ) && exec > >(tee -a "$LOG") 2>&1

ok()   { printf '  OK    %s\n' "$*"; }
bad()  { printf '  FAIL  %s\n' "$*"; PROBLEMS=$((PROBLEMS + 1)); }
note() { printf '  INFO  %s\n' "$*"; }
PROBLEMS=0
NEED_USER=0 NEED_RESTART=0 NEED_START=0

# vq <query> -- run VQL as `api`, through its certificate, inside the container.
vq() {
    docker exec "$VELO" ./velociraptor --api_config /velociraptor/api.config.yaml \
        query "$1" --format json 2>&1
}

check_container() {
    if docker ps --filter "name=^${VELO}\$" --format '{{.Status}}' 2>/dev/null | grep -q '^Up'; then
        ok "$VELO is running"
    else
        bad "$VELO is not running ($(docker ps -a --filter "name=^${VELO}\$" --format '{{.Status}}' 2>/dev/null || echo missing))"
        NEED_START=1
    fi
}

check_api_config() {
    local out
    out="$(docker exec "$VELO" sh -c 'cat /velociraptor/api.config.yaml; echo "@@SERVER@@"; cat /velociraptor/server.config.yaml' 2>/dev/null)"
    local py
    read -r -d '' py <<'PYEOF'
import subprocess, sys, yaml
conn, user = sys.argv[1], sys.argv[2]
raw = sys.stdin.read()
if "@@SERVER@@" not in raw:
    print("missing"); sys.exit()
api_txt, srv_txt = raw.split("@@SERVER@@", 1)
try:
    api = yaml.safe_load(api_txt) or {}
    srv = yaml.safe_load(srv_txt) or {}
except yaml.YAMLError:
    print("unparsable"); sys.exit()
if not api.get("client_cert") or not api.get("client_private_key"):
    print("missing"); sys.exit()
if api.get("api_connection_string") != conn:
    print("conn " + str(api.get("api_connection_string"))); sys.exit()
if (api.get("ca_certificate") or "").strip() != ((srv.get("Client") or {}).get("ca_certificate") or "").strip():
    print("ca"); sys.exit()
subj = subprocess.run(["openssl", "x509", "-noout", "-subject"], input=api["client_cert"],
                      capture_output=True, text=True).stdout
if "CN = " + user not in subj and "CN=" + user not in subj:
    print("cn " + subj.strip()); sys.exit()
print("ok")
PYEOF
    out="$(python3 -c "$py" "$CONN" "$API_USER" <<<"$out" 2>&1)"
    case "$out" in
        ok)         ok "api.config.yaml: certificate for '$API_USER', signed by the server's CA, points at $CONN" ;;
        missing)    bad "api.config.yaml is missing or has no certificate"; NEED_RESTART=1 ;;
        unparsable) bad "api.config.yaml is not valid YAML"; NEED_RESTART=1 ;;
        conn*)      bad "api.config.yaml points at ${out#conn }, not $CONN"; NEED_RESTART=1 ;;
        ca)         bad "api.config.yaml was signed by another CA than the server's (stale after a CA change)"; NEED_RESTART=1 ;;
        cn*)        bad "api.config.yaml's certificate is not for '$API_USER' (${out#cn })"; NEED_RESTART=1 ;;
        *)          bad "could not read api.config.yaml: $(tail -1 <<<"$out")"; NEED_RESTART=1 ;;
    esac
}

check_user() {
    local out roles
    out="$(vq "SELECT user(user='$API_USER') AS u FROM scope()")"
    case "$out" in
        *"User not found"*|*'"u": null'*)
            bad "the Velociraptor user '$API_USER' does not exist (deleted?) — every backend call fails"
            NEED_USER=1; return ;;
        *"Permission denied"*)
            bad "'$API_USER' exists but lost its roles: $(grep -o 'Permission denied[^"]*' <<<"$out" | head -1)"
            NEED_USER=1; return ;;
        *"rpc error"*|*"connection"*|*"error"*)
            local why; why="$(grep -o 'desc = [^"]*' <<<"$out" | head -1)"
            bad "the Velociraptor API does not answer: $(cut -c1-160 <<<"${why:-$(grep -v '^\s*$' <<<"$out" | tail -1)}")"
            NEED_RESTART=1; return ;;
    esac
    roles="$(python3 -c '
import json, re, sys
t = sys.stdin.read(); t = t[t.find("["):] if "[" in t else "[]"
try:
    u = (json.loads(t) or [{}])[0].get("u") or {}
    print(" ".join(sorted(u.get("roles") or [])))
except Exception:
    print("?")' <<<"$out")"
    if [[ " $roles " == *" administrator "* && " $roles " == *" api "* ]]; then
        ok "'$API_USER' exists with roles: $roles"
    else
        bad "'$API_USER' has roles '${roles:-none}', needs administrator and api"
        NEED_USER=1
    fi
}

# Informational: the backend never logs in with it. A login is a plain GUI
# request on the loopback port; the credentials go to curl on stdin, not argv.
check_password() {
    (( NEED_USER )) && return     # no user, or no roles: no login works, so nothing to tell
    local pw code v
    pw="$(secret_get velociraptor VELOX_PASSWORD_2)" || { note "no stored password for '$API_USER' (modules/velociraptor/secrets): not checked"; return; }
    v="$API_USER:$pw"; v="${v//\\/\\\\}"; v="${v//\"/\\\"}"
    code="$(printf 'user = "%s"\n' "$v" | curl -s -K - -o /dev/null -w '%{http_code}' --max-time 5 \
            "${INTACT_VELO_GUI:-http://127.0.0.1:8889}/velociraptor/app/index.html" 2>/dev/null)"
    case "$code" in
        200) ok "'$API_USER' still has the password Intact stored" ;;
        401) note "'$API_USER''s password differs from the stored one (harmless: the backend uses its certificate)"
             (( FIX )) && NEED_USER=1 ;;
        *)   note "could not check '$API_USER''s password (GUI answered ${code:-nothing})" ;;
    esac
}

check_backend() {
    if ! docker ps --filter "name=^${BACKEND}\$" --format '{{.Status}}' 2>/dev/null | grep -q '^Up'; then
        note "$BACKEND is not running: its connection was not checked"; return
    fi
    local out
    out="$(docker exec -w /app "$BACKEND" python3 -c '
import sys
from services.velociraptor_service import setup_velociraptor_connection
from services.vql_utils import execute_vql
from pyvelociraptor import api_pb2_grpc
ch = setup_velociraptor_connection()
if ch is None:
    print("RESULT no connection"); sys.exit()
try:
    execute_vql(api_pb2_grpc.APIStub(ch), "SELECT * FROM info()", timeout=20)
    print("RESULT ok")
except Exception as e:
    print("RESULT " + " ".join(str(e).split())[:200])
' 2>&1 | grep '^RESULT' | tail -1)"
    out="${out#RESULT }"
    if [[ "$out" == ok ]]; then ok "the backend reaches Velociraptor as '$API_USER'"
    else bad "the backend cannot use Velociraptor: ${out:-no answer}"; fi
}

run_checks() {
    PROBLEMS=0 NEED_USER=0 NEED_RESTART=0 NEED_START=0
    check_container
    if (( NEED_START )); then return; fi
    check_api_config
    check_user
    check_password
    check_backend
}

wait_for_api() {
    local i
    for (( i = 0; i < WAIT; i += 3 )); do
        vq "SELECT * FROM info()" | grep -q '"Hostname"\|"hostname"\|^\[' && return 0
        sleep 3
    done
    return 1
}

repair() {
    echo; echo "Repairing:"
    if (( NEED_START )); then
        echo "  starting $VELO"
        if docker ps -a --format '{{.Names}}' | grep -qx "$VELO"; then
            docker start "$VELO" >>"$LOG" 2>&1 || { echo "  could not start it — see $LOG"; return 1; }
        else    # gone altogether: compose re-creates it (as root: it reads secrets/creds.env)
            (cd "$SCRIPT_DIR/modules/velociraptor" && docker compose up -d --no-build --pull never velociraptor) >>"$LOG" 2>&1 \
                || { echo "  could not create it — see $LOG"; return 1; }
        fi
        wait_for_api || { echo "  it started but its API did not answer within ${WAIT}s"; return 1; }
        return 0
    fi
    if (( NEED_USER )); then
        local pw
        pw="$(secret_get velociraptor VELOX_PASSWORD_2)" \
            || { echo "  no stored password for '$API_USER' in modules/velociraptor/secrets/creds.env: cannot re-create it"; return 1; }
        echo "  re-creating '$API_USER' with roles $API_ROLES and the stored password"
        _P="$pw" docker exec -e _P "$VELO" sh -c \
            'exec /velociraptor/velociraptor --config /velociraptor/server.config.yaml user add "$1" "$_P" --role "$2"' \
            _ "$API_USER" "$API_ROLES" >>"$LOG" 2>&1 || { echo "  user add failed — see $LOG"; return 1; }
        NEED_RESTART=1
    fi
    if (( NEED_RESTART )); then
        echo "  restarting $VELO (about 20 s; clients reconnect by themselves)"
        docker restart "$VELO" >/dev/null || { echo "  restart failed"; return 1; }
        wait_for_api || { echo "  its API did not answer within ${WAIT}s after the restart"; return 1; }
    fi
}

echo "Velociraptor API check — $(date '+%F %T') on $(hostname)"
run_checks
if (( PROBLEMS == 0 && NEED_USER == 0 )); then
    echo; echo "Healthy."; echo "Log: $LOG"; exit 0
fi
if (( ! FIX )); then
    echo; echo "$PROBLEMS problem(s). To repair: sudo bash scripts/velociraptor-api-check.sh --fix"
    echo "Log: $LOG"; exit 1
fi
repair || { echo; echo "Repair did not finish. Log: $LOG"; exit 1; }
echo; echo "Checking again:"
run_checks
echo
if (( PROBLEMS == 0 )); then echo "Repaired."; echo "Log: $LOG"; exit 0; fi
echo "$PROBLEMS problem(s) remain."
grep -q 'the backend cannot use Velociraptor' "$LOG" && \
    echo "If only the backend still fails, restart it (interrupts running jobs): docker restart $BACKEND"
echo "Log: $LOG"; exit 1
