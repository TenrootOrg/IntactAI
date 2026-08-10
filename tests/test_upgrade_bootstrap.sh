#!/bin/bash
# scripts/upgrade.sh's bootstrap: finding the checkout, and refusing clearly
# when it cannot.
#
# This is the part an operator hits before anything else, and every failure
# mode here looks like a broken product rather than a wrong invocation. The
# script has to work when run from any directory, by relative or absolute
# path, through a symlink on $PATH, and under `sh` -- and when it genuinely
# cannot find the checkout it has to say THAT, not die 200 lines later on a
# missing lib/common.sh.

set -u
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./helpers.sh

REPO="$(cd .. && pwd)"
UP="${REPO}/scripts/upgrade.sh"

# --help is the probe throughout: it exits 0 before touching docker, config or
# root, so it isolates the bootstrap from everything downstream.
_usage_ok() { grep -q 'Usage:' <<< "$1"; }

test_runs_from_the_repo_root() {
    assert_true _usage_ok "$(cd "$REPO" && bash scripts/upgrade.sh --help 2>&1)"
}

test_runs_from_inside_the_scripts_directory() {
    # `dirname "$0"` is 'scripts' here and '.' is not the repo root, which is
    # what the /.. in the resolution is for.
    assert_true _usage_ok "$(cd "${REPO}/scripts" && bash ./upgrade.sh --help 2>&1)"
}

test_runs_from_an_unrelated_working_directory() {
    assert_true _usage_ok "$(cd / && bash "$UP" --help 2>&1)"
}

test_runs_via_a_relative_path_from_the_parent_directory() {
    assert_true _usage_ok "$(cd "$(dirname "$REPO")" && bash "$(basename "$REPO")/scripts/upgrade.sh" --help 2>&1)"
}

test_runs_as_an_executable_without_an_explicit_interpreter() {
    [[ -x "$UP" ]] || _fail "scripts/upgrade.sh is not executable"
    assert_true _usage_ok "$(cd / && "$UP" --help 2>&1)"
}

test_runs_when_invoked_with_sh_rather_than_bash() {
    # The file is bash (arrays, [[ ]], BASH_SOURCE). Under sh it would
    # otherwise fail somewhere in the middle with a syntax error and no clue
    # why, so it re-execs itself under bash.
    assert_true _usage_ok "$(cd / && sh "$UP" --help 2>&1)"
}

test_runs_through_a_symlink_from_somewhere_else_entirely() {
    # `ln -s .../scripts/upgrade.sh /usr/local/bin/intact-upgrade` is the
    # obvious thing to do once this is the documented entry point, and
    # dirname($0) then points at /usr/local/bin.
    local d; d="$(mktemp -d)"
    ln -s "$UP" "${d}/intact-upgrade"
    assert_true _usage_ok "$(cd / && bash "${d}/intact-upgrade" --help 2>&1)"
    rm -rf "$d"
}

test_runs_through_a_relative_symlink() {
    # A relative link target resolves against the LINK's directory, not the
    # caller's cwd -- the case a naive readlink loop gets wrong.
    local d; d="$(mktemp -d)"
    mkdir -p "${d}/bin"
    local rel; rel="$(realpath --relative-to="${d}/bin" "$UP")"
    ln -s "$rel" "${d}/bin/rel-upgrade"
    assert_true _usage_ok "$(cd / && bash "${d}/bin/rel-upgrade" --help 2>&1)"
    rm -rf "$d"
}

test_runs_through_a_chain_of_two_symlinks() {
    local d; d="$(mktemp -d)"
    ln -s "$UP" "${d}/first"
    ln -s "${d}/first" "${d}/second"
    assert_true _usage_ok "$(cd / && bash "${d}/second" --help 2>&1)"
    rm -rf "$d"
}

test_a_file_copied_out_of_the_checkout_says_exactly_that() {
    # The failure mode this replaces: "Cannot source lib/common.sh", which
    # reads as a broken install rather than "you moved one file".
    local d; d="$(mktemp -d)"
    cp "$UP" "${d}/upgrade.sh"
    local out rc
    out="$(cd / && bash "${d}/upgrade.sh" --help 2>&1)"; rc=$?
    assert_eq "$rc" "2" "an unusable checkout must exit 2, not 0 or 1"
    assert_contains "$out" "does not look like an Intact.AI checkout"
    assert_contains "$out" "resolved root:" "the operator needs to see WHERE it looked"
    assert_not_contains "$out" "Usage:" "it must not pretend it can run"
    rm -rf "$d"
}

test_the_checkout_probe_names_the_missing_piece() {
    local d; d="$(mktemp -d)"
    mkdir -p "${d}/scripts" "${d}/lib/upgrade" "${d}/modules"
    cp "$UP" "${d}/scripts/upgrade.sh"
    : > "${d}/install.sh"; : > "${d}/lib/common.sh"; : > "${d}/config.yaml"
    # lib/upgrade/core.sh deliberately absent
    local out; out="$(cd / && bash "${d}/scripts/upgrade.sh" --help 2>&1)"
    assert_contains "$out" "lib/upgrade/core.sh"
    rm -rf "$d"
}

test_a_non_root_caller_gets_the_sudo_command_it_needs() {
    # `check_root`'s "must be run as root" is true and unhelpful. The message
    # has to carry the command, because the resolved path is the bit the
    # operator does not know.
    if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
        return 0   # cannot test the non-root path while running as root
    fi
    local out rc
    out="$(cd / && bash "$UP" --package /nonexistent.tar 2>&1)"; rc=$?
    assert_eq "$rc" "2"
    assert_contains "$out" "needs root"
    assert_contains "$out" "sudo bash ${REPO}/scripts/upgrade.sh"
}

test_help_and_unknown_flags_do_not_require_root() {
    # Read-only commands must not demand sudo; an operator checking what a
    # flag does should not have to escalate to find out.
    assert_true _usage_ok "$(cd / && bash "$UP" --help 2>&1)"
    local out rc
    out="$(cd / && bash "$UP" --nonsense-flag 2>&1)"; rc=$?
    assert_eq "$rc" "2"
    assert_contains "$out" "Unknown option"
}

test_the_usage_text_shows_the_scripts_path() {
    # It moved from the repo root; usage that still says `bash upgrade.sh`
    # sends the operator to a file that is not there.
    local out; out="$(bash "$UP" --help 2>&1)"
    assert_contains "$out" "scripts/upgrade.sh"
    assert_not_contains "$out" "bash upgrade.sh"
}

test_no_shipped_file_still_points_at_the_old_root_path() {
    # Docs, the usage text, the remediation hints and the dashboard card all
    # print a command the operator will paste.
    # Assembled rather than written literally, so this test does not match
    # its own source and report itself as the offender.
    local needle="bash upg""rade\.sh"
    local hits
    hits="$(grep -rIl --exclude-dir=.git --exclude-dir=node_modules \
              --exclude="$(basename "${BASH_SOURCE[0]}")" \
              -e "$needle" "$REPO" 2>/dev/null || true)"
    assert_eq "$hits" "" "these files still send the operator to the old repo-root path"
}

run_all_tests
