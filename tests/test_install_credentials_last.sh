#!/bin/bash
# install.sh ends with the logins, the dashboard setup token at the very bottom.
#
# Until 2026-11-18 the credentials came right after the summary banner, and the
# notes, the ATTENTION block and the failure list printed below them -- the
# token, which the operator needs next, scrolled out of sight. They stay
# terminal-only (/dev/tty): never stdout, never the install log.
#
# The function runs for real under `script`, which gives it a terminal.

source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALL="$REPO/install.sh"

command -v script >/dev/null || { echo "$(basename "$0"): SKIP -- script(1) not installed"; exit 0; }

# The function under test, with stubs for what it reads, in a file to run.
_harness() {   # _harness <first_login>
    H="$(mktemp -d)"
    {
        echo 'LOG_FILE="'"$H"'/install.log"; : > "$LOG_FILE"'
        echo 'log_info() { echo "[INFO] $*"; echo "[INFO] $*" >> "$LOG_FILE"; }'
        echo 'is_enabled() { [[ "$1" == true ]]; }'
        echo 'read_config() { case "$1" in *first_login*) echo '"$1"' ;; *domain*) echo box.example ;; esac; }'
        echo 'ensure_setup_token() { echo TOK-abc123; }'
        echo 'credential_lines() { printf "Velociraptor|tenroot|PwVelo1\nIRIS|administrator|PwIris2\n"; }'
        sed -n '/^secret_show_once() {/,/^}/p' "$REPO/lib/secrets.sh"
        sed -n '/^_show_credentials_once() {/,/^}/p' "$INSTALL"
        echo '_show_credentials_once'
    } > "$H/run.sh"
}

test_main_no_longer_shows_them_before_the_reports() {
    local body; body="$(sed -n '/^main() {/,/^}/p' "$INSTALL")"
    assert_contains "$body" "print_final_issues_report"
    assert_not_contains "$body" "_show_credentials_once" "not in the middle any more"
}

test_they_are_the_last_thing_before_every_exit() {
    local tail; tail="$(sed -n '/^main "\$@"/,$p' "$INSTALL" | grep -v '^\s*#')"
    assert_eq "$(grep -B1 -E '^\s*exit 0$' <<<"$tail" | head -1 | tr -d ' ')" "_show_credentials_once"
    assert_eq "$(grep -B1 -E '^\s*exit 1$' <<<"$tail" | head -1 | sed 's/#.*//' | tr -d ' ')" "_show_credentials_once" \
        "a failed install still shows the logins of what came up"
}

test_on_a_terminal_the_token_is_the_very_last_line() {
    _harness true
    local out; out="$(script -q -c "bash $H/run.sh" /dev/null </dev/null 2>&1 | tr -d '\r')"
    local last2; last2="$(grep -v '^\s*$' <<<"$out" | tail -2)"
    assert_eq "$(head -1 <<<"$last2")" "  Dashboard setup: https://box.example/setup.html"
    assert_eq "$(tail -1 <<<"$last2")" "  Setup token:     TOK-abc123"
    assert_contains "$out" "PwVelo1" "the module logins come first"
    local log; log="$(cat "$H/install.log")"
    assert_not_contains "$log" "TOK-abc123" "the token never reaches the install log"
    assert_not_contains "$log" "PwVelo1"
    assert_contains "$log" "https://box.example/setup.html" "the URL is in the log, without the token"
    rm -rf "$H"
}

test_without_a_terminal_nothing_secret_is_printed() {
    _harness true
    local out; out="$(bash "$H/run.sh" 2>&1)"
    assert_not_contains "$out" "TOK-abc123"
    assert_not_contains "$out" "PwVelo1"
    assert_contains "$out" "sudo scripts/show-credentials.sh"
    rm -rf "$H"
}

test_a_claimed_box_gets_no_token_lines() {
    _harness false
    local out; out="$(script -q -c "bash $H/run.sh" /dev/null </dev/null 2>&1 | tr -d '\r')"
    assert_contains "$out" "PwVelo1"
    assert_not_contains "$out" "Setup token"
    rm -rf "$H"
}

run_all_tests
