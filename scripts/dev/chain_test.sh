#!/usr/bin/env bash
# DEV-ONLY TOOL. Not shipped, not run by CI, not run by install.sh or upgrade.
#
# Drive a whole upgrade chain and assert the things that actually matter, so a
# regression costs a script run instead of a customer upgrade.
#
#   chain_test.sh --from <snapshot> --package <pkg> [--package <pkg> ...]
#   chain_test.sh --package <pkg>                    (no restore: test in place)
#
# WHY. Every fix this week was verified by reasoning or a unit test and then
# shipped for someone to try on a real box, which is how three identical
# 0726 -> 0811 failures happened before anyone saw the cause. The asserts below
# are exactly the properties those failures violated, and nothing else:
#
#   versions agree     VERSION, modules/backend/.env:BACKEND_VERSION and
#                      config.yaml versions.backend must ALL move. The 0726
#                      loop moved the first and silently rewrote the second
#                      back, so the box reported success on the old code.
#   image agrees       the RUNNING backend container's image must match that
#                      pin. Those two disagreeing IS the recreate-from-old-
#                      image bug; a pin nothing is running proves nothing.
#   nothing unhealthy  an upgrade that reports rc=0 over a dead container is
#                      the failure mode that reached a customer twice.
#   data survived      an IRIS canary row. A version bump that loses evidence
#                      is a failed upgrade however green the log looks.
#
# It prints one line per assert and a short diff-shaped summary, because a
# 40,000-line upgrade log is why these were missed in the first place.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SNAP=""
PACKAGES=()
KEEP_GOING=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --from)      SNAP="${2:-}"; shift 2 ;;
        --from=*)    SNAP="${1#*=}"; shift ;;
        --package)   PACKAGES+=("${2:-}"); shift 2 ;;
        --package=*) PACKAGES+=("${1#*=}"); shift ;;
        --keep-going) KEEP_GOING=1; shift ;;
        --help|-h)   sed -n '2,30p' "$0" | sed 's/^# \?//'; exit 0 ;;
        *) echo "Unknown option: $1" >&2; exit 2 ;;
    esac
done

(( ${#PACKAGES[@]} )) || { echo "give at least one --package" >&2; exit 2; }

C_OK=$'\033[0;32m'; C_NO=$'\033[0;31m'; C_W=$'\033[1;33m'; C_0=$'\033[0m'
PASS=0; FAIL=0; ASSERTED=0
say()  { printf '%s\n' "$*"; }
ok()   { PASS=$((PASS+1)); printf '  %sok%s   %s\n'   "$C_OK" "$C_0" "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  %sFAIL%s %s\n'   "$C_NO" "$C_0" "$1"
         [[ -n "${2:-}" ]] && printf '        %s\n' "$2"; }
warn() { printf '  %swarn%s %s\n' "$C_W" "$C_0" "$1"; }

# ── the canary ────────────────────────────────────────────────────────────
# Written once, then asserted after every hop. IRIS is the module with a real
# database and the one most likely to be recreated rather than reattached.
CANARY_NOTE="chain_test canary"
_canary_write() {
    docker exec intact_iris_db psql -U postgres -d iris_db -q \
        -c "CREATE TABLE IF NOT EXISTS chain_canary(id serial primary key, note text, at timestamptz default now());" \
        -c "INSERT INTO chain_canary(note) SELECT '${CANARY_NOTE}'
             WHERE NOT EXISTS (SELECT 1 FROM chain_canary WHERE note='${CANARY_NOTE}');" \
        >/dev/null 2>&1
}
_canary_count() {
    docker exec intact_iris_db psql -U postgres -d iris_db -tAc \
        "SELECT count(*) FROM chain_canary WHERE note='${CANARY_NOTE}';" 2>/dev/null | tr -d '[:space:]'
}

_enabled_modules() {
    python3 - "$ROOT/config.yaml" <<'PY' 2>/dev/null
import sys, yaml
c = yaml.safe_load(open(sys.argv[1])) or {}
for k, v in sorted((c.get('modules') or {}).items()):
    en = v.get('enabled') if isinstance(v, dict) else v
    if en in (True, 'true', 'True', 1):
        print(k)
PY
}

# ── the assert block ──────────────────────────────────────────────────────
assert_state() {
    local expect="$1" label="$2"
    say ""
    say "── asserts after ${label} ─────────────────────────────────────"

    local v_file v_env v_cfg img
    v_file="$(cat "$ROOT/VERSION" 2>/dev/null)"
    v_env="$(grep -E '^BACKEND_VERSION=' "$ROOT/modules/backend/.env" 2>/dev/null | cut -d= -f2)"
    v_cfg="$(python3 -c "
import yaml,sys
c=yaml.safe_load(open('$ROOT/config.yaml')) or {}
print((c.get('versions') or {}).get('backend',''))" 2>/dev/null)"
    img="$(docker inspect intact_backend --format '{{.Config.Image}}' 2>/dev/null)"

    [[ "$v_file" == "$expect" ]] && ok "VERSION = ${expect}" \
        || bad "VERSION = ${expect}" "got '${v_file}'"
    [[ "$v_env"  == "$expect" ]] && ok "BACKEND_VERSION = ${expect}" \
        || bad "BACKEND_VERSION = ${expect}" "got '${v_env}' — this is the 0726 loop's signature"
    [[ "$v_cfg"  == "$expect" ]] && ok "config.yaml versions.backend = ${expect}" \
        || bad "config.yaml versions.backend = ${expect}" "got '${v_cfg}'"
    [[ "$img" == *":${expect}" ]] && ok "running backend image = ${expect}" \
        || bad "running backend image = ${expect}" "running '${img}' — the pin and the process disagree"

    # Health. A container that is up but unhealthy is the thing an rc=0 hides.
    local unhealthy
    unhealthy="$(docker ps --format '{{.Names}}\t{{.Status}}' | grep -i unhealthy || true)"
    if [[ -z "$unhealthy" ]]; then
        ok "no unhealthy containers"
    else
        bad "no unhealthy containers" "$(tr '\n' ' ' <<< "$unhealthy")"
    fi

    # Every enabled module has at least one container. Catches a module that
    # rolled back so far it stopped existing.
    # Container names come from each module's OWN compose file. Guessing them
    # from the module name reported elk down while elasticsearch, kibana and
    # logstash were all healthy -- elk declares none of its containers
    # "intact_elk*". A chain test that cries wolf gets ignored, which costs
    # more than having no chain test.
    local m missing=() names running
    running="$(docker ps --format '{{.Names}}')"
    while IFS= read -r m; do
        [[ -n "$m" ]] || continue
        local compose="$ROOT/modules/$m/docker-compose.yaml"
        [[ -f "$compose" ]] || continue          # ruleset-only module, nothing to run
        names="$(grep -oE '^[[:space:]]*container_name:[[:space:]]*\S+' "$compose" \
                 | awk '{print $2}')"
        [[ -n "$names" ]] || continue
        local found=0 n
        while IFS= read -r n; do
            [[ -n "$n" ]] || continue
            grep -qx "$n" <<< "$running" && { found=1; break; }
        done <<< "$names"
        (( found )) || missing+=("$m")
    done < <(_enabled_modules)
    if (( ${#missing[@]} == 0 )); then
        ok "every enabled module has containers"
    else
        bad "every enabled module has containers" "down: ${missing[*]}"
    fi

    # Data.
    local n; n="$(_canary_count)"
    if [[ "$n" == "1" ]]; then
        ok "IRIS canary survived"
    elif [[ -z "$n" ]]; then
        warn "IRIS canary not checked (iris_db unreachable)"
    else
        bad "IRIS canary survived" "expected 1 row, found '${n}'"
    fi
}

# ── run ───────────────────────────────────────────────────────────────────
cd "$ROOT" 2>/dev/null || cd / || true
say "chain_test: root=${ROOT}"
if [[ -n "$SNAP" ]]; then
    say ""
    say "── restoring snapshot '${SNAP}' ──────────────────────────────"
    if ! bash "$ROOT/scripts/dev/appliance_snapshot.sh" restore "$SNAP"; then
        say "restore FAILED — a baseline that is not fully up is not a baseline."
        exit 1
    fi
    # The restore REPLACES the tree by moving it aside (mv $ROOT $ROOT.old),
    # so $ROOT is a new inode and this process's working directory is now a
    # deleted one. Every child inherits it, and the first thing that calls
    # getcwd() dies:
    #
    #   rsync: [Receiver] getcwd(): No such file or directory (2)
    #
    # which surfaced as "intact: step 'mirror the backend tree' failed" and
    # looked exactly like an upgrade bug. Re-enter the new tree.
    cd "$ROOT" || { say "cannot enter $ROOT after the restore"; exit 1; }
fi

_canary_write || warn "could not write the IRIS canary (is iris running?)"

for pkg in "${PACKAGES[@]}"; do
    [[ -e "$pkg" ]] || { bad "package exists: $pkg"; exit 1; }
    # The tag comes from the package's own manifest, never from the filename.
    # Taking it from the filename meant a package called chain814.tar produced
    # no tag, assert_state was skipped entirely, and the run reported GREEN on
    # one assert while the appliance had lost its backend container. A chain
    # test that can silently assert nothing is worse than no chain test.
    tag="$(tar -xOf "$pkg" --wildcards '*/manifest.json' 2>/dev/null \
           | python3 -c "
import json,sys
try:    print((json.load(sys.stdin).get('versions') or {}).get('intact',''))
except Exception: print('')" 2>/dev/null | head -1)"
    [[ -n "$tag" ]] || tag="$(basename "$pkg" | grep -oE 'intact-[0-9]{8}' | head -1)"
    say ""
    say "══ applying $(basename "$pkg")${tag:+  (expect ${tag})} ══════════════"

    log="$ROOT/data/tmp/chain-$(date +%s).log"
    if sudo bash "$ROOT/scripts/upgrade.sh" --package "$pkg" --root "$ROOT" \
            --log "$log" >/dev/null 2>&1; then
        ok "upgrade.sh rc=0"
    else
        rc=$?
        bad "upgrade.sh rc=0" "rc=${rc} — see ${log}"
        (( KEEP_GOING )) || { say ""; say "stopping (use --keep-going to continue)"; break; }
    fi

    if [[ -n "$tag" ]]; then
        assert_state "$tag" "$(basename "$pkg")"
        ASSERTED=$((ASSERTED+1))
    else
        bad "could determine the target tag for $(basename "$pkg")" \
            "no versions.intact in its manifest and no intact-YYYYMMDD in the name — refusing to pass a package whose result cannot be checked"
    fi
done

say ""
say "══════════════════════════════════════════════════════════════"
if (( FAIL == 0 && ASSERTED > 0 )); then
    printf '%sCHAIN GREEN%s  %d assert(s) passed across %d hop(s)\n' \
        "$C_OK" "$C_0" "$PASS" "$ASSERTED"
    exit 0
fi
if (( FAIL == 0 )); then
    printf '%sCHAIN INCONCLUSIVE%s  nothing was asserted — not a pass\n' "$C_W" "$C_0"
    exit 1
fi
printf '%sCHAIN RED%s    %d passed, %d FAILED\n' "$C_NO" "$C_0" "$PASS" "$FAIL"
exit 1
