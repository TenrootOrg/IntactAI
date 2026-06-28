#!/usr/bin/env bash
# Tests for recreate_cert_consumers() in lib/health.sh (the cert-rotation reload
# used by change_ip.sh). Docker is fully stubbed on PATH; `sleep` is no-op'd so
# the health-wait loop is instant. Verifies:
#   - a healthy running consumer is restarted only (no recreate),
#   - one that stays unhealthy after restart is recreated (rm -f + compose up),
#   - an absent consumer is skipped entirely.
#
# Run:  bash tests/test_change_ip_cert_consumers.sh
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export LOG_FILE=/dev/null   # log_* helpers append here; keep them quiet in tests

PASS=0; FAIL=0
ok()   { echo "PASS $1"; PASS=$((PASS+1)); }
bad()  { echo "FAIL $1: $2"; FAIL=$((FAIL+1)); }

# --- docker stub --------------------------------------------------------------
STUB_DIR="$(mktemp -d)"
CALLS="$STUB_DIR/calls.log"
cat > "$STUB_DIR/docker" <<'STUB'
#!/usr/bin/env bash
calls="$DOCKER_CALLS"
extract_name() { for a in "$@"; do case "$a" in name=^*) echo "${a#name=^}" | sed 's/\$$//'; return;; esac; done; }
case "$1" in
  compose) echo "compose:$PWD" >> "$calls"; exit 0 ;;
  restart) echo "restart:$2"   >> "$calls"; exit 0 ;;
  rm)      echo "rm:$3"        >> "$calls"; exit 0 ;;   # docker rm -f <name>
  ps)
    name="$(extract_name "$@")"
    running=" $TEST_RUNNING "
    case "$*" in
      *Names*)  [[ "$running" == *" $name "* ]] && echo "$name" ;;
      *Status*) [[ "$running" == *" $name "* ]] && echo "$TEST_STATUS" ;;
    esac
    exit 0 ;;
esac
exit 0
STUB
chmod +x "$STUB_DIR/docker"
export DOCKER_CALLS="$CALLS"
export PATH="$STUB_DIR:$PATH"

# --- load the code under test -------------------------------------------------
SCRIPT_DIR="$REPO"
# shellcheck disable=SC1090
source "$REPO/lib/common.sh" >/dev/null 2>&1
source "$REPO/lib/health.sh"
sleep() { :; }   # no-op so _cert_consumer_healthy's wait loop is instant

run_case() {  # run_case "<running>" "<status>"
    : > "$CALLS"
    TEST_RUNNING="$1" TEST_STATUS="$2" recreate_cert_consumers >/dev/null 2>&1
}
calls() { cat "$CALLS"; }

# --- 1. healthy consumer -> restart only --------------------------------------
run_case "intact_nginx" "Up 3 minutes (healthy)"
if grep -q '^restart:intact_nginx$' "$CALLS" && ! grep -q '^rm:' "$CALLS" && ! grep -q '^compose:' "$CALLS"; then
    ok "healthy consumer is restarted, not recreated"
else
    bad "healthy consumer" "calls=[$(calls | tr '\n' ' ')]"
fi

# --- 2. persistently unhealthy -> recreate (rm -f + compose up) ---------------
run_case "intact_kibana" "Restarting (1) 2 seconds ago"
if grep -q '^restart:intact_kibana$' "$CALLS" && grep -q '^rm:intact_kibana$' "$CALLS" && grep -q '^compose:' "$CALLS"; then
    ok "unhealthy consumer is recreated after a failed restart"
else
    bad "unhealthy consumer" "calls=[$(calls | tr '\n' ' ')]"
fi

# --- 3. absent consumer -> skipped --------------------------------------------
run_case "" "n/a"
if [[ ! -s "$CALLS" ]] || ! grep -qE '^(restart|rm|compose):' "$CALLS"; then
    ok "absent consumers are skipped (no restart/rm/recreate)"
else
    bad "absent consumer" "calls=[$(calls | tr '\n' ' ')]"
fi

# --- 4. only cert consumers are touched (never elasticsearch/postgres) --------
run_case "intact_kibana" "Restarting (1)"
if ! grep -qE 'elasticsearch|postgres|velociraptor|volweb' "$CALLS"; then
    ok "non-cert containers (elasticsearch/postgres/velociraptor/volweb) untouched"
else
    bad "scope" "calls=[$(calls | tr '\n' ' ')]"
fi

rm -rf "$STUB_DIR"
echo
echo "$PASS/$((PASS+FAIL)) passed"
[[ $FAIL -eq 0 ]]
