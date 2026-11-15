#!/usr/bin/env bash
# The ELK upgrade must refuse, before touching anything, when loading the new
# images would push Elasticsearch over its high disk watermark. Above it ES
# places no new shard, Kibana's version migration needs one (.tasks), and the
# cluster turns red with Kibana stuck unhealthy -- seen 2026-11-12, 9.5.5 ->
# 9.5.6 on a box at 95%, after the module had already logged "cluster green".
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
PASS=0; TOTAL=0
ok()   { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  ok   - $1"; }
fail() { TOTAL=$((TOTAL+1)); echo "  FAIL - $1"; [[ -n "${2:-}" ]] && echo "         $2"; }

# Stubs: logging into a file, the module env, ES over curl, and docker.
LOG="${TMP}/log"
log_info()  { echo "INFO $*"  >> "$LOG"; }
log_warn()  { echo "WARN $*"  >> "$LOG"; }
log_error() { echo "ERROR $*" >> "$LOG"; }
_u_env_file()  { echo "${TMP}/elk.env"; }
read_env_var() { return 1; }
curl() {
    case "$*" in
        *_cat/allocation*)  printf '%s\n' "$ALLOC" ;;
        *_cluster/settings*) printf '%s\n' "$SETTINGS" ;;
    esac
}
cat > "${TMP}/docker" <<'EOF'
#!/bin/bash
# inspect <container> -> its image; image inspect <image> -> its size
if [[ "$1" == inspect ]]; then echo "img-$2"; exit 0; fi
if [[ "$1 $2" == "image inspect" ]]; then echo "${IMG_SIZE:-0}"; exit 0; fi
exit 1
EOF
chmod +x "${TMP}/docker"
export DOCKER_BIN="${TMP}/docker"

# shellcheck source=/dev/null
source "${ROOT}/lib/upgrade/modules/elk.sh"

GB=1000000000
run() {  # used_gb total_gb img_gb_each settings -> rc; log in $LOG
    : > "$LOG"
    local used=$1 total=$2
    ALLOC="$(( (total - used) * GB )) $(( total * GB ))"
    export IMG_SIZE=$(( $3 * GB ))
    SETTINGS="$4"
    _u_elk_disk_headroom
}

echo "== refuses when the new images would cross the watermark =="
# 128 of 148 used (86%), plus three 2 GB images -> 134 of 148 = 90%: at the line.
run 128 148 2 '{}'; rc=$?
if (( rc != 0 )) && grep -q 'ERROR.*would reach ~90%' "$LOG" && grep -q 'ERROR.*Free about [0-9]*G' "$LOG" \
   && grep -q 'ELK has not been touched' "$LOG"; then
    ok "86% now + 6G of images -> refused with how much to free"
else
    fail "86% now + 6G of images -> refused" "rc=$rc; $(tr '\n' '|' < "$LOG")"
fi
# The suggested amount must actually get under the watermark.
need=$(grep -o 'Free about [0-9]*G' "$LOG" | grep -o '[0-9]*')
run $((128 - ${need:-0})) 148 2 '{}' && ok "freeing the suggested ${need}G is enough" \
    || fail "freeing the suggested ${need}G is enough" "$(tr '\n' '|' < "$LOG")"

echo
echo "== passes with room to spare =="
run 60 148 2 '{}' && grep -q 'INFO.*40% now, ~44% with the new images (limit 90%)' "$LOG" \
    && ok "40% now -> passes and says so" || fail "40% now -> passes" "$(tr '\n' '|' < "$LOG")"

# A pass is a pass even when the log write fails (common.sh's log_info returns
# 1 with no log file -- found running this against a live box, 2026-11-12).
log_info() { return 1; }
run 60 148 2 '{}' && ok "a failing log write does not turn a pass into a refusal" \
    || fail "a failing log write does not turn a pass into a refusal"
log_info() { echo "INFO $*" >> "$LOG"; }

echo
echo "== Elasticsearch unreachable: warn and go on, as the other preflights do =="
: > "$LOG"; ALLOC=""; SETTINGS=""
_u_elk_disk_headroom && grep -q 'WARN.*skipping its watermark check' "$LOG" \
    && ok "no answer from ES -> warning, not a refusal" || fail "no answer from ES" "$(tr '\n' '|' < "$LOG")"

echo
echo "== a configured watermark is honoured =="
run 135 148 1 '{"defaults":{"cluster.routing.allocation.disk.watermark.high":"95%"}}' \
    && grep -q 'limit 95%' "$LOG" && ok "watermark 95% -> 91% now + 3G passes" \
    || fail "watermark 95% honoured" "$(tr '\n' '|' < "$LOG")"
run 135 148 1 '{"persistent":{"cluster.routing.allocation.disk.watermark.high":"90%"}}'; rc=$?
(( rc != 0 )) && ok "watermark 90% -> the same disk is refused" || fail "watermark 90% refuses" "$(tr '\n' '|' < "$LOG")"

echo
echo "== the check runs before ELK is backed up, loaded or stopped =="
f="${ROOT}/lib/upgrade/modules/elk.sh"
chk=$(grep -n 'u_do "elasticsearch disk headroom"' "$f" | cut -d: -f1)
for step in 'backup_file_for_rollback' 'u_do --timeout 900 "load elk images"' 'u_do --timeout 300 "stop elk"'; do
    ln=$(grep -nF "$step" "$f" | head -1 | cut -d: -f1)
    if [[ -n "$chk" && -n "$ln" ]] && (( chk < ln )); then ok "headroom check (line $chk) before: $step"
    else fail "headroom check before: $step" "check line '${chk}', step line '${ln}'"; fi
done

echo
echo "$PASS/$TOTAL passed"
(( PASS == TOTAL ))
