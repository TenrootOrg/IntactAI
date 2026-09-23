#!/bin/bash
# parse_upgrade_args() (lib/upgrade/args.sh): the standalone maintenance modes.
#
# --velo-refresh re-registers THIS box's tools and artifacts; it has no target
# release by design and the docs give it as a standalone command. The
# "nothing to upgrade to" guard rejected it, so the documented command could
# never run: `sudo bash scripts/upgrade.sh --velo-refresh` exited 2 with
# "Nothing to upgrade to: give a release tag or --package."

set -u
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./helpers.sh

_parse() {  # _parse <args...> -> prints stdout+stderr, returns the exit code
    (
        SCRIPT_DIR="$(mktemp -d)"
        source ../lib/upgrade/args.sh
        parse_upgrade_args "$@"
    ) 2>&1
}

test_velo_refresh_needs_no_release_tag() {
    local out; out="$(_parse --velo-refresh)"
    assert_eq "$?" "0" "accepted on its own"
    assert_not_contains "$out" "Nothing to upgrade to" "and not told to give a tag"
}

test_velo_refresh_with_a_tag_is_refused_clearly() {
    local out; out="$(_parse --velo-refresh intact-20260903)"
    assert_ne "$?" "0" "refused"
    assert_contains "$out" "its own maintenance mode" "says why"
}

test_an_upgrade_with_no_target_is_still_refused() {
    local out; out="$(_parse)"
    assert_ne "$?" "0" "refused"
    assert_contains "$out" "Nothing to upgrade to" "the guard still works"
}

run_all_tests
