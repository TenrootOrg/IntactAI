#!/bin/bash
# Runs every tests/test_*.sh and tests/test_*.py and prints one summary.
#
# Zero dependencies: plain bash plus stdlib python3's unittest -- nothing to
# install on a dev box, in CI, or on a live appliance. Each test_*.sh runs as
# its own subprocess (not sourced in-process), so one file's stubbed
# collaborators (docker, apt-get, curl, ...) can never leak into another's.
#
# Usage: tests/run_tests.sh

set -u
cd "$(dirname "${BASH_SOURCE[0]}")"

suites_run=0
suites_failed=0
failed_names=()

for t in test_*.sh; do
    [[ -f "$t" ]] || continue
    echo "=== $t ==="
    suites_run=$((suites_run + 1))
    if ! bash "$t"; then
        suites_failed=$((suites_failed + 1))
        failed_names+=("$t")
    fi
    echo ""
done

for t in test_*.py; do
    [[ -f "$t" ]] || continue
    echo "=== $t ==="
    suites_run=$((suites_run + 1))
    if ! python3 "$t" -v; then
        suites_failed=$((suites_failed + 1))
        failed_names+=("$t")
    fi
    echo ""
done

echo "=============================================="
echo "Suites: ${suites_run} run, ${suites_failed} failed"
if (( suites_failed > 0 )); then
    echo "Failed:"
    printf '  - %s\n' "${failed_names[@]}"
    exit 1
fi
exit 0
