#!/bin/bash
# lib/modules/timesketch.sh render_timesketch_conf_templates: header SSO.
# The two Timesketch confs and the main nginx's include must name the same
# per-box secret, or header login either fails (mismatch) or is open to any
# container on intact_network (no secret). Runs against a temp tree.
cd "$(dirname "$0")" || exit 1
source ./helpers.sh
source ../lib/common.sh
source ../lib/secrets.sh
source ../lib/modules/timesketch.sh

WORK="$(mktemp -d)"
SCRIPT_DIR="$WORK"
LOG_FILE=/dev/null
trap 'rm -rf "$WORK"' EXIT

INC="$WORK/modules/nginx/config/local/timesketch-sso.conf"
CONF="$WORK/modules/timesketch/config/timesketch.conf"
LEGACY="$WORK/modules/timesketch/config/timesketch_legacy.conf"

_fresh_tree() {
    rm -rf "${WORK:?}/modules"
    mkdir -p "$WORK/modules/timesketch/config" "$WORK/modules/timesketch/secrets"
    cp ../modules/timesketch/config/timesketch.conf.template ../modules/timesketch/config/timesketch_legacy.conf.template \
        "$WORK/modules/timesketch/config/"
}

_secret_in_include() { sed -n 's/^proxy_set_header X-Intact-User-\([0-9a-f]*\) \$intact_auth;$/\1/p' "$INC"; }

test_install_render_agrees_on_one_secret() {
    _fresh_tree
    render_timesketch_conf_templates >/dev/null 2>&1
    local s; s="$(secret_get timesketch SSO_HEADER_SECRET)"
    assert_true eval '[[ "$s" =~ ^[0-9a-f]{32}$ ]]'
    assert_eq "$(wc -l < "$INC" | tr -d ' ')" "1" "include is exactly one line"
    assert_eq "$(_secret_in_include)" "$s" "include names the stored secret"
    assert_eq "$(stat -c %a "$INC")" "600" "include mode: the header name is the secret"
    local f
    for f in "$CONF" "$LEGACY"; do
        assert_eq "$(grep -c '^SSO_ENABLED = True$' "$f")" "1" "$(basename "$f") SSO on"
        assert_eq "$(grep -c '^SSO_ENABLED = False$' "$f")" "0" "$(basename "$f") no SSO off line left"
        assert_eq "$(grep '^SSO_USER_ENV_VARIABLE' "$f")" "SSO_USER_ENV_VARIABLE = 'HTTP_X_INTACT_USER_${s^^}'" \
            "$(basename "$f") env key is the uppercased secret"
    done
}

test_sso_env_is_written_for_the_web_containers() {
    _fresh_tree
    render_timesketch_conf_templates >/dev/null 2>&1
    local s; s="$(secret_get timesketch SSO_HEADER_SECRET)"
    local f="$WORK/modules/timesketch/secrets/sso.env"
    assert_eq "$(cat "$f")" "INTACT_SSO_HEADER=on" "sso.env is a marker, not the secret"
    assert_eq "$(stat -c %a "$f")" "600" "sso.env mode"
}

test_upgrade_reapplies_a_box_without_sso_env() {
    # The planner's own check: a same-version timesketch whose compose requires
    # a generated file the box lacks is re-applied, so an upgrade switches SSO on.
    source ../lib/upgrade/modules/shared.sh
    source ../lib/upgrade/plan.sh
    _fresh_tree
    cp ../modules/timesketch/docker-compose.yaml "$WORK/modules/timesketch/"
    touch "$WORK/modules/timesketch/secrets/postgres.env"
    local missing; missing="$(UPKG_DIR="" _plan_missing_generated_assets timesketch)"
    assert_true eval '[[ ",$missing," == *",secrets/sso.env,"* ]]'
    render_timesketch_conf_templates >/dev/null 2>&1
    missing="$(UPKG_DIR="" _plan_missing_generated_assets timesketch)"
    assert_true eval '[[ ",$missing," != *",secrets/sso.env,"* ]]'
}

test_rerender_is_stable_and_byte_identical() {
    _fresh_tree
    render_timesketch_conf_templates >/dev/null 2>&1
    local s1 sum1 ino1
    s1="$(secret_get timesketch SSO_HEADER_SECRET)"
    sum1="$(cat "$CONF" "$LEGACY" "$INC" | md5sum)"
    ino1="$(stat -c %i "$CONF")"
    render_timesketch_conf_templates >/dev/null 2>&1
    assert_eq "$(secret_get timesketch SSO_HEADER_SECRET)" "$s1" "secret kept"
    assert_eq "$(cat "$CONF" "$LEGACY" "$INC" | md5sum)" "$sum1" "nothing rewritten"
    assert_eq "$(stat -c %i "$CONF")" "$ino1" "same inode (state_registry hard link survives)"
}

test_existing_box_conf_gets_sso_in_place() {
    # An old box: confs rendered before this change (SSO off), no secret yet.
    _fresh_tree
    printf 'TIMESKETCH_PASSWORD=x\n' > "$WORK/modules/timesketch/secrets/creds.env"
    sed -e "s/__SECRET_KEY__/kept/" "$WORK/modules/timesketch/config/timesketch.conf.template" > "$CONF"
    # Hand-edited legacy conf that lost its SSO lines entirely.
    grep -v '^SSO_' "$WORK/modules/timesketch/config/timesketch_legacy.conf.template" > "$LEGACY"
    ln "$CONF" "$WORK/hardlink"
    render_timesketch_conf_templates >/dev/null 2>&1
    local s; s="$(secret_get timesketch SSO_HEADER_SECRET)"
    assert_eq "$(secret_get timesketch TIMESKETCH_PASSWORD)" "x" "other creds kept"
    assert_eq "$(grep -c "^SECRET_KEY = 'kept'" "$CONF")" "1" "conf not re-rendered"
    assert_eq "$(stat -c %h "$CONF")" "2" "hard link not split"
    assert_eq "$(grep -c "^SSO_USER_ENV_VARIABLE = 'HTTP_X_INTACT_USER_${s^^}'$" "$CONF")" "1" "old conf switched"
    assert_eq "$(grep -c '^SSO_ENABLED = True$' "$LEGACY")" "1" "missing line appended"
    assert_eq "$(grep -c "^SSO_USER_ENV_VARIABLE = 'HTTP_X_INTACT_USER_${s^^}'$" "$LEGACY")" "1" "missing env line appended"
    assert_eq "$(_secret_in_include)" "$s"
}

test_bad_stored_secret_is_replaced() {
    _fresh_tree
    printf 'SSO_HEADER_SECRET=Not_Hex\n' > "$WORK/modules/timesketch/secrets/creds.env"
    render_timesketch_conf_templates >/dev/null 2>&1
    local s; s="$(secret_get timesketch SSO_HEADER_SECRET)"
    assert_true eval '[[ "$s" =~ ^[0-9a-f]{32}$ ]]'
    assert_eq "$(_secret_in_include)" "$s"
}

run_all_tests
