#!/bin/bash
# lib/secrets.sh: the one place module passwords are generated, checked and
# stored. A wrong answer here either ships a weak password or locks an operator
# out of a tool, so every branch is pinned.
cd "$(dirname "$0")" || exit 1
source ./helpers.sh
source ../lib/common.sh
source ../lib/secrets.sh

WORK="$(mktemp -d)"
SCRIPT_DIR="$WORK"
LOG_FILE=/dev/null
trap 'rm -rf "$WORK"' EXIT

test_generate_meets_the_rule_every_time() {
    local i v bad=0
    for i in $(seq 1 200); do
        v="$(secret_generate)"
        secret_check "$v" >/dev/null || bad=$((bad + 1))
        [[ ${#v} -eq 24 ]] || bad=$((bad + 1))
    done
    assert_eq "$bad" "0" "200 generated passwords all pass the rule and are 24 long"
    assert_eq "$(secret_generate 32 | wc -c)" "32" "length argument is honoured"
    assert_ne "$(secret_generate)" "$(secret_generate)" "two generated passwords differ"
}

test_check_accepts_a_good_password() {
    assert_true secret_check "Str0ng-Pass.word_9"
}

test_check_refuses_with_a_reason_and_never_echoes_the_value() {
    local v out
    for v in "" "123123" "Ch4nge-Me!Intact2026" '1234qwer!@#$' "changeme" "Short1Aa" \
             "alllowercase123" "ALLUPPERCASE123" "NoDigitsHereAtAll" "-Leading1Dash" \
             "Has Space1Abc" 'Dollar$1Abcdefg' "Quote'1Abcdefgh"; do
        out="$(secret_check "$v")"
        assert_false secret_check "$v"
        [[ -n "$v" && "$out" == *"$v"* ]] && _fail "secret_check echoed the value: $out"
    done
    assert_eq "$(secret_check 123123)" "it is a publicly known default" "names the reason"
}

test_lab_switch_lets_weak_passwords_through_only_when_on() {
    local cfg="$WORK/config.yaml"
    printf 'first_login: true\nallow_weak_passwords: false\n' > "$cfg"
    CONFIG_FILE="$cfg" assert_false secret_check "123123"
    printf 'first_login: true\nallow_weak_passwords: true  # dev box\n' > "$cfg"
    CONFIG_FILE="$cfg" assert_true secret_check "123123"
    CONFIG_FILE="$cfg" assert_false secret_check ""                 # never empty
    CONFIG_FILE="$cfg" assert_false secret_check 'has$dollar'       # still .env/shell safe
    INTACT_ALLOW_WEAK_PASSWORDS=1 assert_true secret_check "123123"
    CONFIG_FILE="" assert_false secret_check "123123"               # no config: rule on
    # only true, exactly as the backend's weak_passwords_allowed() reads it
    local w
    for w in yes on 1 Yes "'true'" maybe; do
        printf 'allow_weak_passwords: %s\n' "$w" > "$cfg"
        CONFIG_FILE="$cfg" assert_false secret_weak_allowed "'$w' is not the lab switch"
    done
    for w in True TRUE; do
        printf 'allow_weak_passwords: %s\n' "$w" > "$cfg"
        CONFIG_FILE="$cfg" assert_true secret_weak_allowed "'$w' is"
    done
}

test_set_creates_private_file_and_dir() {
    secret_set elk ELASTIC_PASSWORD "Abc123Def456Ghi"
    assert_eq "$(stat -c %a "$WORK/modules/elk/secrets")" "700" "secrets dir is 0700"
    assert_eq "$(stat -c %a "$WORK/modules/elk/secrets/creds.env")" "600" "creds.env is 0600"
    assert_eq "$(secret_get elk ELASTIC_PASSWORD)" "Abc123Def456Ghi" "value reads back"
}

test_set_replaces_one_key_and_keeps_the_others() {
    secret_set iris IRIS_ADM_PASSWORD "First1Passwordx"
    secret_set iris OTHER_KEY "Keep1Thisvaluex"
    secret_set iris IRIS_ADM_PASSWORD "Second2Password"
    assert_eq "$(secret_get iris IRIS_ADM_PASSWORD)" "Second2Password" "key replaced"
    assert_eq "$(secret_get iris OTHER_KEY)" "Keep1Thisvaluex" "other key kept"
    assert_eq "$(grep -c '^IRIS_ADM_PASSWORD=' "$WORK/modules/iris/secrets/creds.env")" "1" "no duplicate line"
    assert_eq "$(ls -A "$WORK/modules/iris/secrets" | grep -c '^\.creds')" "0" "no temp file left"
}

test_set_keeps_the_inode_so_hard_links_follow() {
    secret_set elk ELASTIC_PASSWORD "Inode1Testvalue"
    local f="$WORK/modules/elk/secrets/creds.env" link="$WORK/state-link.env" i1
    ln -f "$f" "$link"                      # what state_registry does
    i1="$(stat -c %i "$f")"
    secret_set elk ELASTIC_PASSWORD "Inode2Newvalue9"
    assert_eq "$(stat -c %i "$f")" "$i1" "inode unchanged"
    assert_contains "$(cat "$link")" "Inode2Newvalue9" "the hard-linked copy sees the new value"
    assert_eq "$(stat -c %a "$f")" "600" "still 0600"
}

test_set_refuses_empty_and_bad_keys() {
    assert_false secret_set elk ELASTIC_PASSWORD ""
    assert_false secret_set elk "bad key" "Abc123Def456Ghi"
    assert_false secret_set elk GOOD_KEY $'two\nlines'
}

test_get_on_missing_is_empty_and_fails() {
    assert_false secret_get nosuchmodule ANY
    assert_eq "$(secret_get nosuchmodule ANY)" "" "nothing printed"
}

test_tool_is_new_by_path() {
    local p="$WORK/data/velociraptor/users"
    assert_true secret_tool_is_new "path:$p"
    mkdir -p "$p"
    assert_true secret_tool_is_new "path:$p"         # empty dir: still new
    : > "$p/bob.db"
    assert_true secret_tool_is_new "path:$p/missing.db"
    assert_false secret_tool_is_new "path:$p"        # has data: not new
    printf 'x' > "$WORK/f"
    assert_false secret_tool_is_new "path:$WORK/f"   # non-empty file: not new
    assert_false secret_tool_is_new "bogus:spec"     # unknown spec: not new (safe side)
}

test_tool_is_new_without_docker_answers_not_new() {
    # Unreachable docker must never read as "new": that would mint a password
    # the tool's existing data rejects.
    PATH="/nonexistent" assert_false secret_tool_is_new "vol:anything"
}

# No terminal: nothing written anywhere. A file here used to be a second
# plaintext copy of every password; show-credentials.sh reads the stores.
test_show_once_without_a_tty_writes_nothing_and_points_at_show_credentials() {
    local out
    command -v setsid >/dev/null || { echo "  (skipped: no setsid)"; return 0; }
    # setsid runs a program, not a function: a detached bash with no
    # controlling terminal, so /dev/tty cannot be opened.
    out="$(printf 'IRIS|administrator|Abc123Def456Ghi\n' | setsid -w bash -c \
        'source ../lib/common.sh; source ../lib/secrets.sh; SCRIPT_DIR="$1"; LOG_FILE=/dev/null; secret_show_once' _ "$WORK" 2>&1)"
    assert_contains "$out" "view them with: sudo scripts/show-credentials.sh" "says where to read them"
    [[ "$out" == *"Abc123Def456Ghi"* ]] && _fail "value leaked to stdout/stderr: $out"
    assert_eq "$(find "$WORK" -name 'credentials-once*' | wc -l)" "0" "no credentials file"
    assert_eq "$(grep -rl Abc123Def456Ghi "$WORK" 2>/dev/null | wc -l)" "0" "value written nowhere"
}

run_all_tests
