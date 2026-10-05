#!/usr/bin/env bash
# An air-gapped appliance must be TOLD it cannot analyse Windows memory.
#
# Volatility3 ships no Windows symbols: it downloads ntkrnlmp.pdb from
# msdl.microsoft.com per kernel. With no egress that fails, VolWeb's extraction
# ends SUCCESS in ~36s having run zero plugins, and every Windows MEMORY run on
# the box fails. Nothing in the install said a word about it.
#
# seed_volweb_symbols() is the fix's install-time half: it copies whatever the
# operator staged in data/volweb-symbols into the media volume VolWeb reads
# symbols from, and then reports what the box actually HAS. This pins the three
# properties that make the report trustworthy:
#
#   1. files staged by the operator reach /home/app/web/media/symbols
#      (docker cp -- the volume is root-owned under /var/lib/docker and the
#      installer must not assume it can write there);
#   2. a file already in the container is not copied again -- re-running an
#      install or an upgrade must not re-push an 801 MiB symbol pack -- but a
#      NEWER pack of the same name replaces it, and older uploaded copies go;
#   3. zero symbols on an air-gapped install is a WARNING that names the
#      failure the operator is otherwise going to meet mid-investigation.
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PASS=0; TOTAL=0
ok()   { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  ok   - $1"; }
fail() { TOTAL=$((TOTAL+1)); echo "  FAIL - $1"; [[ -n "${2:-}" ]] && echo "         $2"; }

LOG_FILE="$(mktemp)"
SCRIPT_DIR="$ROOT"
DOCKER_CALLS="$(mktemp)"
# The container's filesystem: a temp dir the fake docker really writes to, so
# the copy / compare / rename / cleanup commands run for real.
FS="$(mktemp -d)"
LIB="/home/app/web/media/symbols"
trap 'rm -rf "$LOG_FILE" "$DOCKER_CALLS" "$FS"' EXIT

source "${ROOT}/lib/common.sh"
source "${ROOT}/lib/modules/volweb.sh"

# Collaborators deploy_volweb would have guaranteed. Stubbed rather than
# mocked-out so the function under test runs its real body.
read_config() { echo "true"; }
is_enabled() { [[ "${1:-}" == "true" ]]; }
is_module_installed() { return 0; }

# Fake docker: records every call, then runs it against $FS. `chown app:app`
# is the one thing a non-root test cannot do, and is only recorded.
docker() {
    echo "$*" >> "$DOCKER_CALLS"
    local a=() x
    case "${1:-}" in
        cp) command cp "$2" "${FS}${3#intact_volweb_backend:}" ;;
        exec)
            shift 2
            for x in "$@"; do a+=("${x//\/home\/app\/web\/media/${FS}/home/app/web/media}"); done
            [[ "${a[0]}" == chown ]] && return 0
            "${a[@]}" ;;
    esac
}
has() { [[ -f "${FS}${LIB}/$1" ]]; }

echo "== staged symbols reach the volume VolWeb reads =="
SEED="$(mktemp -d)"
mkdir -p "${SEED}/windows/ntkrnlmp.pdb"
echo isf > "${SEED}/windows/ntkrnlmp.pdb/3006AD7D-2.json.xz"
echo pack-2019 > "${SEED}/windows.zip"
: > "${SEED}/notes.txt"                # not an ISF: must be ignored
OUT="$(seed_volweb_symbols "$SEED" 2>&1)"

if has 3006AD7D-2.json.xz; then
    ok "a loose .json.xz ISF is copied in"
else
    fail "a loose .json.xz ISF is copied in" "$(tail -3 "$DOCKER_CALLS")"
fi
if has windows.zip; then
    ok "a whole .zip symbol pack is copied in (vol3 reads ISFs inside it)"
else
    fail "a whole .zip symbol pack is copied in" "$(tail -3 "$DOCKER_CALLS")"
fi
if ! grep -q "notes.txt" "$DOCKER_CALLS"; then
    ok "a non-ISF file in the staging dir is ignored"
else
    fail "a non-ISF file in the staging dir is ignored"
fi
case "$OUT" in
    *"offline memory analysis is covered"*) ok "and the install reports the box as covered" ;;
    *) fail "and the install reports the box as covered" "$OUT" ;;
esac

echo
echo "== re-running does not re-push an 801 MiB pack =="
: > "$DOCKER_CALLS"
OUT="$(seed_volweb_symbols "$SEED" 2>&1)"
if ! grep -q "^cp " "$DOCKER_CALLS"; then
    ok "nothing is copied when the container already has it"
else
    fail "nothing is copied when the container already has it" "$(grep '^cp ' "$DOCKER_CALLS")"
fi
case "$OUT" in
    *"2 ISF file(s)/pack(s) present"*) ok "the count still reports what the box holds" ;;
    *) fail "the count still reports what the box holds" "$OUT" ;;
esac

echo
echo "== a release's newer pack replaces the old one, and only that =="
# 2026-10-05: the seed skipped any name already present, so a newer windows.zip
# could never land, and earlier uploads (<12-hex>_windows.zip) stayed beside it.
echo older-upload > "${FS}${LIB}/0123456789ab_windows.zip"
echo own-pack > "${FS}${LIB}/my_windows.zip"
echo pack-2026 > "${SEED}/windows.zip"
OUT="$(seed_volweb_symbols "$SEED" 2>&1)"
if [[ "$(cat "${FS}${LIB}/windows.zip")" == pack-2026 ]]; then
    ok "the newer pack replaced the old one"
else
    fail "the newer pack replaced the old one" "$(cat "${FS}${LIB}/windows.zip")"
fi
if ! has 0123456789ab_windows.zip && has my_windows.zip; then
    ok "an older uploaded copy is removed; a differently named pack is not"
else
    fail "an older uploaded copy is removed; a differently named pack is not" "$(ls "${FS}${LIB}")"
fi
if ! ls -A "${FS}${LIB}" | grep -q incoming; then
    ok "no half-copied file is left behind"
else
    fail "no half-copied file is left behind" "$(ls -A "${FS}${LIB}")"
fi
case "$OUT" in
    *"replaced by the newer copy"*) ok "and the install says so" ;;
    *) fail "and the install says so" "$OUT" ;;
esac

echo
FS="$(mktemp -d)"                      # a box with an empty library
echo "== an air-gapped box with no symbols is warned, not left to find out =="
EMPTY="$(mktemp -d)"
OUT="$(INTACT_AIRGAP=1 seed_volweb_symbols "$EMPTY" 2>&1)"
case "$OUT" in
    *"NO Volatility symbols"*) ok "the warning names the condition" ;;
    *) fail "the warning names the condition" "$OUT" ;;
esac
case "$OUT" in
    *"kernel symbols"*) ok "and the failure the operator would otherwise meet" ;;
    *) fail "and the failure the operator would otherwise meet" "$OUT" ;;
esac
case "$OUT" in
    *"MEMORY_SYMBOLS_AIRGAP.md"*) ok "and where the fix is written down" ;;
    *) fail "and where the fix is written down" "$OUT" ;;
esac
# Advisory only: a site may install today and carry symbols in tomorrow.
if seed_volweb_symbols "$EMPTY" >/dev/null 2>&1; then
    ok "but it never fails the install"
else
    fail "but it never fails the install"
fi

echo
echo "== a connected box gets guidance, not a warning =="
OUT="$(seed_volweb_symbols "$EMPTY" 2>&1)"
case "$OUT" in
    *"msdl.microsoft.com"*) ok "it says symbols resolve from Microsoft on first use" ;;
    *) fail "it says symbols resolve from Microsoft on first use" "$OUT" ;;
esac

echo
echo "== the library is handed to app even when nothing was staged =="
# THE BUG THIS PINS, measured on a live appliance. The mkdir above runs through
# `docker exec`, which is root, so symbols/ is created root-owned. The chown
# that fixes that used to sit inside `if (( staged > 0 ))` -- and `staged` is 0
# on every stock install, because data/volweb-symbols ships only a .gitkeep.
# So VolWeb (running as `app`) could read what shipped and never write: the
# harvest that copies a run's learned symbols out of the worker failed EACCES
# into 2>/dev/null and reported 0 files, on a box with symbols sitting there.
: > "$DOCKER_CALLS"
seed_volweb_symbols "$EMPTY" >/dev/null 2>&1
if grep -q "exec intact_volweb_backend chown -R app:app" "$DOCKER_CALLS"; then
    ok "an install that stages nothing still chowns the directory to app"
else
    fail "an install that stages nothing still chowns the directory to app" \
         "$(cat "$DOCKER_CALLS")"
fi

echo
echo "== an upgrade notices if the symbol library shrank =="
# Sourcing lib/upgrade/modules/volweb.sh whole would drag in the engine; the
# two functions under test are self-contained, so lift just those.
eval "$(sed -n '/^_volweb_verify_symbols() {/,/^}/p' "${ROOT}/lib/upgrade/modules/volweb.sh")"
NEXT_COUNT=""
_volweb_symbol_count() { printf '%s' "$NEXT_COUNT"; }
verify() { NEXT_COUNT="$2"; _volweb_verify_symbols "$1" 2>&1; }

case "$(verify 3 1)" in
    *"SYMBOL LIBRARY SHRANK: 3 -> 1"*) ok "losing files is named, with the numbers" ;;
    *) fail "losing files is named, with the numbers" "$(verify 3 1)" ;;
esac
case "$(verify 3 1)" in
    *"MEMORY_SYMBOLS_AIRGAP.md"*) ok "and points at how to re-seed" ;;
    *) fail "and points at how to re-seed" "$(verify 3 1)" ;;
esac
case "$(verify 3 3)" in
    *"symbol library intact (3 file(s))"*) ok "an unchanged library is reported as kept" ;;
    *) fail "an unchanged library is reported as kept" "$(verify 3 3)" ;;
esac
case "$(verify 3 5)" in
    *"intact (5 file(s))"*) ok "growing is fine -- a run may have learned symbols" ;;
    *) fail "growing is fine" "$(verify 3 5)" ;;
esac
# EMPTY IS NOT ZERO. A docker hiccup, or a VolWeb that is not installed, reads
# as "" -- and reporting that as data loss is how a tripwire trains people to
# ignore it.
if [[ -z "$(verify '' 3)" && -z "$(verify 3 '')" ]]; then
    ok "a count it could not READ is never reported as a count that CHANGED"
else
    fail "a count it could not READ is never reported as a count that CHANGED" \
         "before-empty:[$(verify '' 3)] after-empty:[$(verify 3 '')]"
fi
# Policy 'report': VolWeb being unhappy has never been allowed to fail an
# upgrade, and symbols are recoverable in a way the Velociraptor CA is not.
NEXT_COUNT=0
if _volweb_verify_symbols 9 >/dev/null 2>&1; then
    ok "but it never fails the upgrade"
else
    fail "but it never fails the upgrade"
fi

rm -rf "$SEED" "$EMPTY"

echo
echo "-- ${PASS}/${TOTAL} passed"
(( PASS == TOTAL ))
