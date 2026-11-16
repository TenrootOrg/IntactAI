#!/bin/bash
# scripts/reset-login.sh + lib/setup_token.sh: the dashboard login recovery.
# The config edit must keep config.yaml's inode (the backend bind-mounts it by
# inode) and every other byte; the token must be root-only and fresh; and the
# script must refuse to run as anyone but root.
cd "$(dirname "$0")" || exit 1
source ./helpers.sh

REPO="$(cd .. && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# A throwaway Intact root holding just what the script needs, plus an `id`
# stub on PATH that claims whatever uid FAKE_UID says.
mkbox() {
    local box="$WORK/box$1"
    mkdir -p "$box/scripts" "$box/lib" "$box/bin"
    cp "$REPO/scripts/reset-login.sh" "$box/scripts/"
    cp "$REPO/lib/setup_token.sh" "$box/lib/"
    printf '#!/bin/bash\n[[ "$1" == "-u" ]] && { echo "${FAKE_UID:-0}"; exit 0; }\nexec /usr/bin/id "$@"\n' >"$box/bin/id"
    chmod +x "$box/bin/id"
    echo "$box"
}

run_reset() { PATH="$1/bin:$PATH" FAKE_UID="$2" bash "$1/scripts/reset-login.sh" 2>&1; }

CONFIG='schema_version: 3
# Top comment the operator wrote.
first_login: false   # trailing comment goes with the line

domain: 10.0.0.5  # platform IP
modules:
  elk:
    first_login: false
'

test_edits_in_place_and_keeps_everything_else() {
    local box out ino token
    box="$(mkbox 1)"
    printf '%s' "$CONFIG" >"$box/config.yaml"
    ino="$(stat -c %i "$box/config.yaml")"
    out="$(run_reset "$box" 0)"
    assert_eq "$?" "0" "exits 0 as root"
    assert_eq "$(stat -c %i "$box/config.yaml")" "$ino" "config.yaml inode unchanged"
    assert_eq "$(grep -c '^first_login: true$' "$box/config.yaml")" "1" "top-level first_login set true"
    assert_eq "$(diff <(printf '%s' "$CONFIG") "$box/config.yaml" | grep -c '^[<>]')" "2" \
        "only the first_login line differs (comments, nested key kept)"
    assert_contains "$(cat "$box/config.yaml")" "    first_login: false" "nested key untouched"
    token="$(cat "$box/data/state/backend/setup_token")"
    assert_eq "${#token}" "43" "token is 43 chars"
    [[ "$token" =~ ^[A-Za-z0-9_-]+$ ]] || _fail "token not url-safe: $token"
    assert_eq "$(stat -c %a "$box/data/state/backend/setup_token")" "600" "token file 0600"
    assert_eq "$(stat -c %a "$box/data/state/backend")" "700" "token dir 0700"
    assert_contains "$out" "Setup token:  $token" "prints the token"
    assert_contains "$out" "https://10.0.0.5/setup.html" "prints the URL from domain:"
    assert_contains "$out" "old password stops working" "says the old login stops working"
}

test_each_run_mints_a_new_token() {
    local box a b
    box="$(mkbox 2)"
    printf '%s' "$CONFIG" >"$box/config.yaml"
    run_reset "$box" 0 >/dev/null
    a="$(cat "$box/data/state/backend/setup_token")"
    run_reset "$box" 0 >/dev/null
    b="$(cat "$box/data/state/backend/setup_token")"
    assert_ne "$a" "$b" "a second reset replaces the token"
}

test_inserts_the_key_when_absent() {
    local box
    box="$(mkbox 3)"
    printf 'schema_version: 3\ndomain: CHANGE-ME\n' >"$box/config.yaml"
    run_reset "$box" 0 >/dev/null
    assert_eq "$(sed -n 2p "$box/config.yaml")" "first_login: true" "inserted after schema_version"
    assert_eq "$(wc -l <"$box/config.yaml")" "3" "nothing else added"
}

test_refuses_non_root_and_changes_nothing() {
    local box out rc
    box="$(mkbox 4)"
    printf '%s' "$CONFIG" >"$box/config.yaml"
    out="$(run_reset "$box" 1000)"; rc=$?
    assert_eq "$rc" "1" "exits 1 when not root"
    assert_contains "$out" "must be run as root" "says why"
    assert_eq "$(cat "$box/config.yaml")" "$(printf '%s' "$CONFIG")" "config.yaml untouched"
    [[ -e "$box/data/state/backend/setup_token" ]] && _fail "token written by a non-root run"
    return 0
}

test_ensure_keeps_an_existing_token() {
    local box a b
    box="$(mkbox 5)"
    a="$(SCRIPT_DIR="$box" bash -c 'source "$SCRIPT_DIR/lib/setup_token.sh"; ensure_setup_token')"
    b="$(SCRIPT_DIR="$box" bash -c 'source "$SCRIPT_DIR/lib/setup_token.sh"; ensure_setup_token')"
    assert_eq "${#a}" "43" "ensure creates a token when none exists"
    assert_eq "$a" "$b" "ensure keeps the token already shown"
    assert_eq "$(cat "$box/data/state/backend/setup_token")" "$a" "printed token is the stored one"
}

run_all_tests
