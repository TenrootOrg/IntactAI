#!/bin/bash
# _pin_module_version() (lib/config.sh): the only writer that edits config.yaml
# during install/upgrade.
#
# Two invariants dominate this file and both are load-bearing rather than
# stylistic:
#
#   * INODE PRESERVATION. config.yaml is bind-mounted into the backend by
#     inode. A temp-file-plus-`mv` swaps the file out from under the live
#     mount, so the edit lands on disk while the container keeps reading the
#     old content -- a change that reports success and has no effect.
#
#   * COMMENT AND QUOTE FIDELITY. config.yaml is the operator's file. A
#     yaml.safe_load + dump round-trip would silently delete every comment and
#     reorder every key, which is why this is a line-scan.

set -u
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./helpers.sh

LOG_FILE="$(mktemp)"
source ../lib/common.sh

# Each test gets its own config.yaml copy; CONFIG_FILE is what lib/config.sh
# reads, so pointing it at a temp copy keeps the real one untouched.
WORK=""
_setup() {
    WORK="$(mktemp -d)"
    CONFIG_FILE="${WORK}/config.yaml"
    cat > "$CONFIG_FILE" <<'YAML'
domain: 192.168.1.1
modules:
  elk:
    enabled: true
project_name: intact
versions:
  elk: '9.4.4'
  iris: v2.4.27
  # The AWS rule pack has no container image; this pins the rule-pack version.
  aws_sigma: '2026.04'
options:
  github_token: ''
YAML
}
_teardown() { [[ -n "$WORK" ]] && rm -rf "$WORK"; WORK=""; }

_versions_value() {  # _versions_value <key> -> the parsed YAML value
    python3 -c "
import yaml,sys
print((yaml.safe_load(open('${CONFIG_FILE}'))['versions']).get('$1','<absent>'))
"
}

source ../lib/config.sh

test_existing_quoted_key_keeps_its_quotes() {
    _setup
    assert_true _pin_module_version elk 9.4.5
    assert_contains "$(grep -F 'elk:' "$CONFIG_FILE")" "'9.4.5'" \
        "a key quoted in the file must stay quoted"
    assert_eq "9.4.5" "$(_versions_value elk)"
    _teardown
}

test_existing_unquoted_key_stays_unquoted() {
    _setup
    assert_true _pin_module_version iris v2.4.28
    assert_eq "  iris: v2.4.28" "$(grep -F 'iris:' "$CONFIG_FILE")"
    _teardown
}

test_absent_key_is_appended_inside_the_versions_block() {
    _setup
    assert_true _pin_module_version logstash 9.4.5
    assert_eq "9.4.5" "$(_versions_value logstash)"
    _teardown
}

test_numeric_looking_value_is_quoted_so_yaml_keeps_it_a_string() {
    # '9.4' unquoted parses as a float, and a float pin reaches docker as
    # "9.4" or "9.400000000000001" depending on the round-trip. Anything that
    # is not a bare identifier gets quoted.
    _setup
    assert_true _pin_module_version newmod 9.4
    assert_eq "str" "$(python3 -c "
import yaml
print(type(yaml.safe_load(open('${CONFIG_FILE}'))['versions']['newmod']).__name__)")"
    _teardown
}

test_inode_is_preserved() {
    _setup
    local before after
    before="$(stat -c %i "$CONFIG_FILE")"
    assert_true _pin_module_version elk 9.9.9
    after="$(stat -c %i "$CONFIG_FILE")"
    assert_eq "$before" "$after" \
        "config.yaml is bind-mounted by inode; the writer must truncate in place"
    _teardown
}

test_comments_and_unrelated_keys_survive() {
    _setup
    assert_true _pin_module_version elk 9.4.5
    assert_contains "$(cat "$CONFIG_FILE")" \
        "# The AWS rule pack has no container image" \
        "a yaml round-trip would have eaten this comment"
    assert_contains "$(cat "$CONFIG_FILE")" "github_token" \
        "operator options must be untouched"
    assert_eq "2026.04" "$(_versions_value aws_sigma)"
    assert_eq "192.168.1.1" "$(python3 -c "
import yaml; print(yaml.safe_load(open('${CONFIG_FILE}'))['domain'])")"
    _teardown
}

test_setting_the_value_it_already_has_does_not_rewrite_the_file() {
    # Not just cosmetic: install re-runs call this on every boot-ish path, and
    # a no-op that still rewrites would churn the mtime of a file the operator
    # may be watching, and burn a write on every idempotent install.
    _setup
    local before after
    before="$(stat -c %Y:%s "$CONFIG_FILE")"
    sleep 1
    assert_true _pin_module_version elk 9.4.4
    after="$(stat -c %Y:%s "$CONFIG_FILE")"
    assert_eq "$before" "$after" "an already-correct pin must not touch the file"
    _teardown
}

test_empty_key_or_value_is_refused() {
    _setup
    assert_false _pin_module_version elk ""
    assert_false _pin_module_version "" 9.4.5
    assert_eq "9.4.4" "$(_versions_value elk)"
    _teardown
}

test_missing_versions_block_is_refused_not_invented() {
    # A config.yaml with no versions: block is malformed. Appending one would
    # paper over a broken config and let the install continue onto a box whose
    # pins came from nowhere.
    _setup
    printf 'domain: x\nproject_name: intact\n' > "$CONFIG_FILE"
    assert_false _pin_module_version elk 9.4.5
    _teardown
}

test_missing_config_file_is_refused() {
    _setup
    rm -f "$CONFIG_FILE"
    assert_false _pin_module_version elk 9.4.5
    _teardown
}

run_all_tests
rm -f "$LOG_FILE"
