#!/bin/bash
# Zero-dependency bash test helpers -- no bats, no shellcheck, nothing to
# install. python3 is the only interpreter this suite ever needs, and it's
# already a hard product requirement (INTACT_HOST_DEPS), so the whole thing
# runs on a dev box, in CI, or on a live appliance with nothing added.
#
# Usage, at the top of every tests/test_*.sh:
#   source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"
#   test_something() { ... assert_* calls ... }
#   run_all_tests    # discovers every test_* function in THIS process and runs it

set -u

TESTS_RUN=0
TESTS_FAILED=0
_CURRENT_TEST=""

_fail() {
    TESTS_FAILED=$((TESTS_FAILED + 1))
    echo "  FAIL [${_CURRENT_TEST}] $1" >&2
}

assert_eq() {
    local actual="$1" expected="$2" desc="${3:-}"
    [[ "$actual" == "$expected" ]] || _fail "${desc:+$desc: }expected [$expected], got [$actual]"
}

assert_ne() {
    local actual="$1" unexpected="$2" desc="${3:-}"
    [[ "$actual" != "$unexpected" ]] || _fail "${desc:+$desc: }did not expect [$unexpected]"
}

assert_contains() {
    local haystack="$1" needle="$2" desc="${3:-}"
    [[ "$haystack" == *"$needle"* ]] || _fail "${desc:+$desc: }[$haystack] does not contain [$needle]"
}

assert_not_contains() {
    local haystack="$1" needle="$2" desc="${3:-}"
    [[ "$haystack" != *"$needle"* ]] || _fail "${desc:+$desc: }[$haystack] unexpectedly contains [$needle]"
}

# assert_true/assert_false run a command (function or binary) and check its
# exit status -- use for "does calling this return success/failure", as
# opposed to assert_eq's "does this string equal that string".
assert_true() {
    if ! "$@" >/dev/null 2>&1; then
        _fail "expected success: $*"
    fi
}

assert_false() {
    if "$@" >/dev/null 2>&1; then
        _fail "expected failure but it succeeded: $*"
    fi
}

# ---------------------------------------------------------------------------
# Stubbing collaborators (docker, apt-get, curl, tar, systemctl, wait_for_*,
# ...) so a unit test never touches the network, apt, or a real daemon.
#
# stub() defines a shell FUNCTION of the given name. Bash resolves a plain
# command name against defined functions before $PATH, so `apt-get ...`
# inside the code under test transparently calls this instead of the real
# binary -- no PATH tricks, no wrapper scripts.
# ---------------------------------------------------------------------------
STUB_LOG="$(mktemp)"
trap 'rm -f "${STUB_LOG}" "${STUB_LOG}".*.out' EXIT

reset_stubs() { : > "$STUB_LOG"; rm -f "${STUB_LOG}".*.out; }

# Usage:
#   stub docker              # always exits 0, records the call
#   stub apt-get 1           # always exits 1, records the call
#   stub curl 0 'the body'   # exits 0, ALSO writes "the body" to stdout
#
# $out is written to its own file at DEFINITION time, outside the eval'd
# string, so arbitrary content (quotes, $, backticks) in a stubbed command's
# output can never be interpreted as shell code -- only the stub $name (a
# plain identifier) and $rc (a digit) are ever spliced into the eval.
stub() {
    local name="$1" rc="${2:-0}" out="${3:-}"
    local out_file="${STUB_LOG}.${name}.out"
    printf '%s' "$out" > "$out_file"
    # shellcheck disable=SC2317 -- the eval'd body IS reachable, shellcheck
    # just can't see through the string.
    eval "
$name() {
    echo \"$name \$*\" >> \"$STUB_LOG\"
    [[ -s \"$out_file\" ]] && cat \"$out_file\"
    return $rc
}
"
}

stub_called_with() {
    local name="$1" args="$2"
    grep -qF -- "$name $args" "$STUB_LOG"
}

stub_call_count() {
    local name="$1"
    grep -c -- "^$name " "$STUB_LOG" 2>/dev/null || true
}

# Run every test_* function defined in this process, in definition order,
# resetting stubs between each so one test's recorded calls can never leak
# into the next. Call as the last line of every tests/test_*.sh.
run_all_tests() {
    local fn
    while IFS= read -r fn; do
        [[ -n "$fn" ]] || continue
        _CURRENT_TEST="$fn"
        TESTS_RUN=$((TESTS_RUN + 1))
        reset_stubs
        "$fn"
    done < <(declare -F | awk '{print $3}' | grep '^test_')
    echo "$(basename "$0"): ${TESTS_RUN} run, ${TESTS_FAILED} failed"
    [[ "$TESTS_FAILED" -eq 0 ]]
}
