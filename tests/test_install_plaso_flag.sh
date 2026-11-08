#!/bin/bash
# install.sh pulls Plaso only when modules.plaso.enabled is true.
#
# QA 2026-11-08: Plaso was pulled whenever TimeSketch was enabled, so
# `plaso: enabled: false` still downloaded log2timeline/plaso. This runs the
# real pre-download block from install.sh with the pull functions stubbed.
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
fail=0

# The block between the "Timeline Processing" banner and the next banner.
BLOCK="$(awk '/# Timeline Processing \(Plaso\/Timesketch\)/{f=1;next}
              f&&/# Forensic Collection/{exit} f' "$ROOT/install.sh" | sed '$d')"
[[ "$BLOCK" == *pull_plaso_image* ]] || { echo "FAIL: could not find the pre-download block"; exit 1; }

run() {   # run <config-yaml>  -> prints the calls made
    printf '%s\n' "$1" > "$TMP/config.yaml"
    (
        CONFIG_FILE="$TMP/config.yaml"
        read_config() { python3 -c "import yaml; print(yaml.safe_load(open('${CONFIG_FILE}'))$1)" 2>/dev/null || echo ""; }
        is_enabled() { local v="${1,,}"; [[ "$v" == true || "$v" == yes || "$v" == 1 ]]; }
        log_info() { :; }
        log_warn() { echo "warn"; }
        pull_plaso_image() { echo plaso; }
        pull_python_alpine_image() { echo alpine; }
        download_timesketch_packages() { echo timesketch; }
        eval "f() { $BLOCK
}"
        f
    ) | tr '\n' ' '
}

check() {   # check <name> <config> <expected calls>
    local got; got="$(run "$2")"
    if [[ "${got% }" == "$3" ]]; then echo "ok   $1"; else echo "FAIL $1: got '${got% }', want '$3'"; fail=1; fi
}

check "plaso off, timesketch on: no Plaso pull, a warning" \
    $'modules:\n  plaso: {enabled: false}\n  timesketch: {enabled: true}' "warn timesketch"
check "plaso on, timesketch off: Plaso only" \
    $'modules:\n  plaso: {enabled: true}\n  timesketch: {enabled: false}' "plaso alpine"
check "both on" \
    $'modules:\n  plaso: {enabled: true}\n  timesketch: {enabled: true}' "plaso alpine timesketch"
check "both off: nothing" \
    $'modules:\n  plaso: {enabled: false}\n  timesketch: {enabled: false}' ""
check "old config without a plaso key follows timesketch" \
    $'modules:\n  timesketch: {enabled: true}' "plaso alpine timesketch"

exit $fail
