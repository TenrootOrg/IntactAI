#!/bin/bash
# lib/credentials_apply.sh (creds_apply) and scripts/apply-passwords.sh: change a
# password inside a running tool, its store and every reader -- or, on any
# failure, none of them. A half-applied change locks the platform out of its own
# evidence, so every failure point is pinned against fake tools
# (tests/creds_stubs.sh) that keep the password where the real ones do.
cd "$(dirname "$0")" || exit 1
REPO="$(cd .. && pwd)"
source ./helpers.sh
source ../lib/common.sh
source ../lib/config.sh
source ../lib/secrets.sh
source ../lib/modules/iris.sh
source ../lib/modules/volweb.sh
source ../lib/credentials_apply.sh
source ./creds_stubs.sh

ROOTS="$(mktemp -d)"
trap 'rm -rf "$ROOTS" "${STUB_LOG}" "${STUB_LOG}".*.out' EXIT
LOG_FILE=/dev/null
ORIG_PATH="$PATH"
CREDS_WAIT=0

_world() {
    SCRIPT_DIR="$(mktemp -d -p "$ROOTS")"; T="$SCRIPT_DIR/.t"
    CONFIG_FILE="$SCRIPT_DIR/config.yaml"
    local m
    for m in elk timesketch velociraptor backend iris volweb portainer; do
        mkdir -p "$SCRIPT_DIR/modules/$m"; : > "$SCRIPT_DIR/modules/$m/.env"
        printf 'services: {}\n' > "$SCRIPT_DIR/modules/$m/docker-compose.yaml"
    done
    cat > "$CONFIG_FILE" <<'YAML'
first_login: false
allow_weak_passwords: false
modules:
  elk:
    enabled: true
    id: elastic
    # Elasticsearch: 6+ characters
    password: ''
  iris:
    enabled: true
    id: administrator
    password: ''
  portainer:
    enabled: true
    id: admin
    password: ''
  timesketch:
    enabled: true
    id: tenroot
    password: ''
  velociraptor:
    enabled: true
    id: tenroot
    password: ''
  volweb:
    enabled: true
    id: tenroot
    password: ''
YAML
    creds_stubs "$T"
    PATH="$T/bin:$ORIG_PATH"
    unset DOCKER_BIN
    CREDS_ROTATED=(); CREDS_ROTATED_SHOW=()
}
_calls() { cat "$T/calls"; }
# Every recorded docker and curl argv (docker events log exec commands whole).
_no_value_in_argv() {
    local v all; all="$(cat "$T/calls" "$T/argv")"
    for v in "$@"; do assert_not_contains "$all" "$v" "no value or JWT on a command line"; done
}
_save_cred_put() { eval "$(declare -f _cred_put | sed '1s/^_cred_put/_real_cred_put/')"; }
_restore_cred_put() { eval "$(declare -f _real_cred_put | sed '1s/^_real_cred_put/_cred_put/')"; }
_save_cred_put

# --- elk ------------------------------------------------------------------------

_elk_box() {
    printf '%s\n' intact_elasticsearch intact_logstash intact_kibana intact_backend intact_velociraptor > "$T/running"
    secret_set elk ELASTIC_PASSWORD Old1Elastic; secret_set elk KIBANA_PASSWORD Kib1Sys
    printf Old1Elastic > "$T/es_pw"
}

test_elk_changes_the_cluster_the_store_and_every_reader() {
    _world; _elk_box
    assert_true creds_apply elk New1Elastic2x
    assert_eq "$(cat "$T/es_pw")" "New1Elastic2x" "Elasticsearch has it"
    assert_eq "$(secret_get elk ELASTIC_PASSWORD)" "New1Elastic2x" "stored"
    assert_eq "$(secret_get elk KIBANA_PASSWORD)" "Kib1Sys" "kibana_system is separate and untouched"
    local c; c="$(_calls)"
    assert_contains "$c" "compose elk up -d --force-recreate --no-build --pull never" "ES healthcheck, logstash, setup, kibana"
    assert_contains "$c" "compose backend up -d --force-recreate --no-build --pull never backend"
    assert_contains "$c" "compose velociraptor up -d --force-recreate --no-build --pull never velociraptor"
    assert_not_contains "$c" "New1Elastic2x" "never on a command line"
}

test_elk_refused_by_the_cluster_changes_nothing() {
    _world; _elk_box; : > "$T/es_refuse"
    assert_false creds_apply elk New1Elastic2x
    assert_contains "$CREDS_APPLY_REASON" "refused"
    assert_eq "$(cat "$T/es_pw")" "Old1Elastic"
    assert_eq "$(secret_get elk ELASTIC_PASSWORD)" "Old1Elastic"
}

test_elk_reader_failure_puts_everything_back() {
    _world; _elk_box; echo 1 > "$T/compose_rc"
    assert_false creds_apply elk New1Elastic2x
    assert_contains "$CREDS_APPLY_REASON" "recreate"
    assert_eq "$(cat "$T/es_pw")" "Old1Elastic" "the cluster is back on the old password"
    assert_eq "$(secret_get elk ELASTIC_PASSWORD)" "Old1Elastic" "the store matches the cluster"
    assert_eq "$(grep -c 'compose elk up' "$T/calls")" "2" "the readers were recreated again on the old value"
}

test_elk_reader_not_coming_up_puts_everything_back() {
    _world; _elk_box
    sed -i '/intact_logstash/d' "$T/running"; echo intact_logstash > "$T/exists"   # it never starts again
    assert_false creds_apply elk New1Elastic2x
    assert_contains "$CREDS_APPLY_REASON" "did not come back up"
    assert_eq "$(cat "$T/es_pw")" "Old1Elastic"
    assert_eq "$(secret_get elk ELASTIC_PASSWORD)" "Old1Elastic"
}

test_elk_with_a_stored_value_the_cluster_refuses_is_not_touched() {
    _world; _elk_box; printf Other1Value > "$T/es_pw"
    assert_false creds_apply elk New1Elastic2x
    assert_contains "$CREDS_APPLY_REASON" "does not accept the stored password"
    assert_eq "$(cat "$T/es_pw")" "Other1Value"
}

test_elk_refusal_at_the_first_step_recreates_nothing() {
    _world; _elk_box; : > "$T/es_refuse"
    assert_false creds_apply elk New1Elastic2x
    assert_eq "$CREDS_APPLY_PUT_BACK" "1"
    assert_not_contains "$(_calls)" "compose" "nothing was written: no reader recreated"
}

test_elk_revert_that_cannot_confirm_says_so() {
    _world; _elk_box
    # the readers fail AND the cluster then takes neither value (down, or changed under us)
    _creds_readers() { printf Zzz9Other > "$T/es_pw"; return 1; }
    assert_false creds_apply elk New1Elastic2x
    assert_eq "$CREDS_APPLY_PUT_BACK" "0"
    assert_contains "$CREDS_APPLY_REASON" "state not confirmed: check Elasticsearch, then re-run"
    # the cluster keeps the NEW one: stored as what it accepts, and not called "put back"
    _world; _elk_box
    _creds_readers() { : > "$T/es_refuse"; return 1; }
    assert_false creds_apply elk New1Elastic2x
    assert_eq "$CREDS_APPLY_PUT_BACK" "0"
    assert_contains "$CREDS_APPLY_REASON" "the NEW one stays"
    assert_eq "$(secret_get elk ELASTIC_PASSWORD)" "New1Elastic2x" "the store matches the cluster"
    source ../lib/credentials_apply.sh
}

test_elk_public_kibana_system_gets_a_new_value_and_is_verified() {
    _world; _elk_box; secret_set elk KIBANA_PASSWORD 123123; printf 123123 > "$T/kib_pw"
    assert_true creds_apply elk New1Elastic2x
    local k; k="$(secret_get elk KIBANA_PASSWORD)"
    assert_ne "$k" "123123"; assert_true secret_check "$k"
    assert_eq "$(cat "$T/kib_pw")" "$k" "the setup container set it on the recreate"
    assert_contains "$(cat "$T/argv")" "_security/_authenticate" "kibana_system logged in"
    _no_value_in_argv New1Elastic2x "$k"
    # off the warning list
    creds_mark_defaults; assert_false test -e "$SCRIPT_DIR/data/state/default-passwords.json"
    # a failure puts kibana_system's old value back too
    _world; _elk_box; secret_set elk KIBANA_PASSWORD 123123; printf 123123 > "$T/kib_pw"
    sed -i '/intact_logstash/d' "$T/running"; echo intact_logstash > "$T/exists"
    assert_false creds_apply elk New1Elastic2x
    assert_eq "$(secret_get elk KIBANA_PASSWORD)" "123123"
    assert_eq "$(cat "$T/kib_pw")" "123123"
}

test_elk_cut_off_run_is_finished_by_the_next() {
    _world; _elk_box; printf New1Elastic2x > "$T/es_pw"     # ES took it, then the run died
    assert_true creds_apply elk New1Elastic2x
    assert_contains "$CREDS_APPLY_NOTE" "cut off"
    assert_eq "$(secret_get elk ELASTIC_PASSWORD)" "New1Elastic2x"
    assert_contains "$(_calls)" "compose backend up -d --force-recreate"
}

# --- timesketch ----------------------------------------------------------------

_ts_box() {
    printf '%s\n' intact_timesketch_web intact_timesketch_postgres intact_backend > "$T/running"
    secret_set timesketch TIMESKETCH_PASSWORD Old1Sketch; printf Old1Sketch > "$T/ts_pw"
}

test_timesketch_changes_the_user_on_stdin_and_recreates_the_backend() {
    _world; _ts_box
    assert_true creds_apply timesketch New1Sketch2x
    assert_eq "$(cat "$T/ts_pw")" "New1Sketch2x"
    assert_eq "$(secret_get timesketch TIMESKETCH_PASSWORD)" "New1Sketch2x"
    assert_contains "$(_calls)" "exec -i intact_timesketch_web tsctl create-user tenroot"
    assert_contains "$(_calls)" "compose backend up -d --force-recreate --no-build --pull never backend"
    assert_not_contains "$(_calls)" "New1Sketch2x" "on stdin, never --password"
}

test_timesketch_failures_put_the_old_password_back() {
    _world; _ts_box; echo 1 > "$T/ts_rc"
    assert_false creds_apply timesketch New1Sketch2x
    assert_contains "$CREDS_APPLY_REASON" "tsctl"
    assert_eq "$(secret_get timesketch TIMESKETCH_PASSWORD)" "Old1Sketch"
    _world; _ts_box; echo 1 > "$T/compose_rc"
    assert_false creds_apply timesketch New1Sketch2x
    assert_eq "$(cat "$T/ts_pw")" "Old1Sketch" "Timesketch is back on the old one"
    assert_eq "$(secret_get timesketch TIMESKETCH_PASSWORD)" "Old1Sketch"
}

test_timesketch_cut_off_run_is_finished_by_the_next() {
    _world; _ts_box; printf New1Sketch2x > "$T/ts_pw"
    assert_true creds_apply timesketch New1Sketch2x
    assert_contains "$CREDS_APPLY_NOTE" "cut off"
    assert_eq "$(secret_get timesketch TIMESKETCH_PASSWORD)" "New1Sketch2x"
    assert_not_contains "$(_calls)" "tsctl" "Timesketch already has it"
}

# --- velociraptor ----------------------------------------------------------------

_velo_box() {
    echo intact_velociraptor > "$T/running"
    printf 'VELOX_USER=tenroot\nVELOX_ROLE=administrator\n' > "$SCRIPT_DIR/modules/velociraptor/.env"
    secret_set velociraptor VELOX_PASSWORD Old1Velo; secret_set velociraptor VELOX_PASSWORD_2 Api1Random
    printf '%s\n' tenroot:Old1Velo api:Api1Random | tee "$T/velo_db" > "$T/velo_live"
}

test_velociraptor_gui_user_is_changed_and_the_server_recreated() {
    _world; _velo_box
    assert_true creds_apply velociraptor New1Velociraptor
    assert_true grep -qx tenroot:New1Velociraptor "$T/velo_live"
    assert_eq "$(secret_get velociraptor VELOX_PASSWORD)" "New1Velociraptor"
    assert_eq "$(secret_get velociraptor VELOX_PASSWORD_2)" "Api1Random" "api is not touched"
    assert_contains "$(_calls)" "compose velociraptor up -d --force-recreate --no-build --pull never velociraptor"
    assert_contains "$(_calls)" "exec -e _P intact_velociraptor sh -c" "the value goes in through the exec's env"
    _no_value_in_argv New1Velociraptor Old1Velo
}

test_velociraptor_failures_put_the_old_password_back() {
    _world; _velo_box; echo 1 > "$T/velo_rc"
    assert_false creds_apply velociraptor New1Velociraptor
    assert_contains "$CREDS_APPLY_REASON" "user add"
    assert_eq "$(secret_get velociraptor VELOX_PASSWORD)" "Old1Velo"
    # The recreate fails and leaves the container down: the old value cannot be
    # applied from outside, the revert's own recreate does it (the entrypoint
    # applies the store, the stamps having been dropped).
    _world; _velo_box; echo 1 > "$T/compose_fails"
    assert_false creds_apply velociraptor New1Velociraptor
    assert_contains "$CREDS_APPLY_REASON" "recreate"
    assert_eq "$CREDS_APPLY_PUT_BACK" "1"
    assert_eq "$(secret_get velociraptor VELOX_PASSWORD)" "Old1Velo"
    assert_true grep -qx tenroot:Old1Velo "$T/velo_live"
    # Down for good: honest about it, and the next start puts the old value back.
    _world; _velo_box; echo 1 > "$T/compose_rc"
    assert_false creds_apply velociraptor New1Velociraptor
    assert_eq "$CREDS_APPLY_PUT_BACK" "0"
    assert_contains "$CREDS_APPLY_REASON" "its next start applies it"
    assert_eq "$(secret_get velociraptor VELOX_PASSWORD)" "Old1Velo"
    assert_true grep -qx tenroot:New1Velociraptor "$T/velo_db"   # the datastore still has the new one now
    rm -f "$T/compose_rc"; _creds_recreate velociraptor velociraptor
    assert_true grep -qx tenroot:Old1Velo "$T/velo_live"   # the next start applied the stored one
    assert_true grep -qx api:Api1Random "$T/velo_live"
}

test_velociraptor_cut_off_run_is_finished_by_the_next() {
    # the store is written first: a run cut off after it leaves store new, server old
    _world; _velo_box; secret_set velociraptor VELOX_PASSWORD New1Velociraptor
    assert_true creds_apply velociraptor New1Velociraptor
    assert_true grep -qx tenroot:New1Velociraptor "$T/velo_live"
    # cut off after user add + recreate, before... the stored old no longer logs in
    _world; _velo_box; printf '%s\n' tenroot:New1Velociraptor api:Api1Random | tee "$T/velo_db" > "$T/velo_live"
    assert_true creds_apply velociraptor New1Velociraptor
    assert_contains "$CREDS_APPLY_NOTE" "cut off"
    assert_eq "$(secret_get velociraptor VELOX_PASSWORD)" "New1Velociraptor"
}

# --- portainer, iris, volweb ---------------------------------------------------------

test_portainer_changes_through_its_api_or_not_at_all() {
    _world; echo intact_portainer > "$T/running"
    _cred_put portainer Old1Portainer; printf Old1Portainer > "$T/pt_pw"
    assert_true creds_apply portainer New1Portainer2x
    assert_eq "$(cat "$T/pt_pw")" "New1Portainer2x"; assert_eq "$(cred_get portainer)" "New1Portainer2x"
    : > "$T/pt_refuse"
    assert_false creds_apply portainer Third1Portainer
    assert_contains "$CREDS_APPLY_REASON" "refused"
    assert_eq "$(cat "$T/pt_pw")" "New1Portainer2x"; assert_eq "$(cred_get portainer)" "New1Portainer2x"
    _no_value_in_argv New1Portainer2x Old1Portainer Third1Portainer "Bearer"
}

# After a password change Portainer refuses every earlier JWT: the way back
# needs a fresh login with the NEW password.
test_portainer_revert_logs_in_again_with_the_new_password() {
    _world; echo intact_portainer > "$T/running"
    _cred_put portainer Old1Portainer; printf Old1Portainer > "$T/pt_pw"
    _cred_put() { [[ "$2" == New1Portainer2x ]] && return 1; _real_cred_put "$@"; }
    assert_false creds_apply portainer New1Portainer2x
    assert_contains "$CREDS_APPLY_REASON" "could not store"
    assert_eq "$CREDS_APPLY_PUT_BACK" "1"
    assert_eq "$(cat "$T/pt_pw")" "Old1Portainer" "the PUT back was accepted (fresh JWT)"
    assert_eq "$(_real_cred_put_get)" "Old1Portainer"
    _restore_cred_put
    _no_value_in_argv New1Portainer2x Old1Portainer "Bearer" "J0" "J1"
    # the PUT back refused: the store keeps what Portainer accepts, and says so
    _world; echo intact_portainer > "$T/running"
    _cred_put portainer Old1Portainer; printf Old1Portainer > "$T/pt_pw"; printf Old1Portainer > "$T/pt_back_refuse"
    _creds_auth_portainer_real="$(declare -f _creds_auth_portainer)"
    local n=0
    # Portainer "does not accept" the new one the first time it is asked, then does
    _creds_auth_portainer() { if [[ "$1" == New1Portainer2x ]] && (( n++ == 0 )); then return 1; fi; _creds_portainer_login admin "$1" >/dev/null; }
    assert_false creds_apply portainer New1Portainer2x
    assert_eq "$CREDS_APPLY_PUT_BACK" "0"
    assert_contains "$CREDS_APPLY_REASON" "the NEW one stays"
    assert_eq "$(cat "$T/pt_pw")" "New1Portainer2x"
    assert_eq "$(cred_get portainer)" "New1Portainer2x" "stored as what Portainer accepts"
    eval "$_creds_auth_portainer_real"
}
_real_cred_put_get() { cat "$(_cred_file portainer)"; }

test_portainer_placeholder_is_adopted_when_portainer_takes_the_typed_value() {
    _world; echo intact_portainer > "$T/running"
    _cred_put portainer Random1Placeholder; : > "$(_cred_placeholder portainer)"
    printf Set1InTheUi99 > "$T/pt_pw"            # what the admin set in the Portainer UI
    assert_false creds_apply portainer Wrong1Guess99
    assert_contains "$CREDS_APPLY_REASON" "set it in the Portainer UI, then put that value in config.yaml"
    assert_true test -e "$(_cred_placeholder portainer)"
    assert_true creds_apply portainer Set1InTheUi99
    assert_eq "$CREDS_APPLY_NOTE" "adopted"
    assert_false test -e "$(_cred_placeholder portainer)"
    assert_eq "$(cred_get portainer)" "Set1InTheUi99"
    assert_not_contains "$(_calls)" "PUT" "adopting changes nothing in Portainer"
}

test_portainer_cut_off_run_is_finished_by_the_next() {
    _world; echo intact_portainer > "$T/running"
    _cred_put portainer Old1Portainer; printf New1Portainer2x > "$T/pt_pw"
    assert_true creds_apply portainer New1Portainer2x
    assert_contains "$CREDS_APPLY_NOTE" "cut off"
    assert_eq "$(cred_get portainer)" "New1Portainer2x"
}

test_iris_is_enforced_and_verified_or_put_back() {
    _world; printf '%s\n' intact_iris_app intact_iris_db > "$T/running"
    _cred_put iris Old1Iris; printf Old1Iris > "$T/iris_pw"
    assert_true creds_apply iris New1Iris2xyz
    assert_eq "$(cat "$T/iris_pw")" "New1Iris2xyz" "the real enforce_iris_admin_password wrote IRIS's row"
    assert_eq "$(cred_get iris)" "New1Iris2xyz"
    # an enforce that does not take: verified, and put back
    enforce_iris_admin_password() { :; }
    assert_false creds_apply iris Third1IrisXyz
    assert_contains "$CREDS_APPLY_REASON" "IRIS does not accept"
    assert_eq "$(cred_get iris)" "New1Iris2xyz"
    assert_eq "$CREDS_APPLY_PUT_BACK" "1"
    # nothing stored before: nothing to put back, and not claimed
    _world; printf '%s\n' intact_iris_app intact_iris_db > "$T/running"
    assert_false creds_apply iris Third1IrisXyz
    assert_eq "$CREDS_APPLY_PUT_BACK" "0"
    assert_contains "$CREDS_APPLY_REASON" "no earlier password was stored"
    source ../lib/modules/iris.sh
}

test_volweb_is_seeded_and_verified_or_put_back() {
    _world; echo intact_volweb_backend > "$T/running"
    _cred_put volweb Old1Volweb; printf Old1Volweb > "$T/vw_pw"
    assert_true creds_apply volweb New1Volweb2x
    assert_eq "$(cat "$T/vw_pw")" "New1Volweb2x"; assert_eq "$(cred_get volweb)" "New1Volweb2x"
    echo 1 > "$T/vw_rc"
    assert_false creds_apply volweb Third1Volweb
    assert_contains "$CREDS_APPLY_REASON" "seeding"
    assert_eq "$(cred_get volweb)" "New1Volweb2x"
    _world; echo intact_volweb_backend > "$T/running"; echo 1 > "$T/vw_rc"
    assert_false creds_apply volweb Third1Volweb
    assert_eq "$CREDS_APPLY_PUT_BACK" "0" "no old value: not claimed as put back"
}

# --- rules ------------------------------------------------------------------------

test_a_value_outside_the_rule_is_refused_unless_the_lab_switch_is_on() {
    _world; _ts_box
    assert_false creds_apply timesketch 123123
    assert_contains "$CREDS_APPLY_REASON" "publicly known"
    assert_eq "$(cat "$T/ts_pw")" "Old1Sketch"
    sed -i 's/^allow_weak_passwords: false/allow_weak_passwords: true/' "$CONFIG_FILE"
    assert_true creds_apply timesketch 123123
    assert_false creds_apply timesketch 'bad value'
}

test_a_stopped_tool_is_refused_before_anything_changes() {
    _world; secret_set timesketch TIMESKETCH_PASSWORD Old1Sketch
    assert_false creds_apply timesketch New1Sketch2x
    assert_contains "$CREDS_APPLY_REASON" "not running"
    assert_eq "$(grep -v inspect "$T/calls")" ""
}

test_a_successful_change_drops_the_module_from_the_marker_and_is_not_rotated() {
    _world; _ts_box
    secret_set timesketch TIMESKETCH_PASSWORD 123123; printf 123123 > "$T/ts_pw"
    creds_mark_defaults 2>/dev/null
    assert_true test -e "$SCRIPT_DIR/data/state/default-passwords.json"
    creds_apply timesketch New1Sketch2x >/dev/null && creds_mark_defaults
    assert_false test -e "$SCRIPT_DIR/data/state/default-passwords.json"
}

# --- scripts/apply-passwords.sh -----------------------------------------------------

_box_scripts() {   # the real scripts and libs, on the fake box
    mkdir -p "$SCRIPT_DIR/lib/modules" "$SCRIPT_DIR/scripts"
    cp ../lib/common.sh ../lib/secrets.sh ../lib/config.sh ../lib/credentials_apply.sh "$SCRIPT_DIR/lib/"
    cp ../lib/modules/iris.sh ../lib/modules/volweb.sh "$SCRIPT_DIR/lib/modules/"
    cp ../scripts/apply-passwords.sh "$SCRIPT_DIR/scripts/"
}
_set_cfg() { sed -i "/^  $1:/,/^  [a-z]*:/ s/^    password: .*/    password: '$2'/" "$CONFIG_FILE"; }
# Root inside a user namespace: the script refuses anyone else.
_apply() { RC=0; OUT="$(CREDS_WAIT=0 PATH="$PATH" unshare -r bash "$SCRIPT_DIR/scripts/apply-passwords.sh" </dev/null 2>&1)" || RC=$?; }

test_apply_passwords_changes_only_what_config_yaml_names_and_blanks_only_those() {
    _world; _box_scripts; _ts_box
    echo intact_portainer >> "$T/running"
    _cred_put portainer Old1Portainer; printf Old1Portainer > "$T/pt_pw"; : > "$T/pt_refuse"
    secret_set elk ELASTIC_PASSWORD Old1Elastic
    _set_cfg timesketch New1Sketch2x
    _set_cfg portainer New1Portainer2x
    local ino; ino="$(stat -c %i "$CONFIG_FILE")"
    _apply
    assert_eq "$RC" "1" "a module was reverted: $OUT"
    assert_contains "$OUT" "timesketch: changed"
    assert_contains "$OUT" "portainer: reverted: Portainer refused the change"
    assert_contains "$OUT" "sudo scripts/show-credentials.sh"
    assert_not_contains "$OUT" "elk:" "a blank line is not a request"
    assert_not_contains "$OUT" "New1Sketch2x"; assert_not_contains "$OUT" "New1Portainer2x"
    assert_eq "$(cat "$T/ts_pw")" "New1Sketch2x"
    assert_eq "$(_config_password_raw timesketch password)" "" "applied: blanked"
    assert_eq "$(_config_password_raw portainer password)" "New1Portainer2x" "reverted: left for the admin to fix"
    assert_contains "$(cat "$CONFIG_FILE")" "# Elasticsearch: 6+ characters" "comments kept"
    assert_eq "$(stat -c %i "$CONFIG_FILE")" "$ino" "in place (the backend mounts config.yaml by inode)"
    assert_eq "$(secret_get elk ELASTIC_PASSWORD)" "Old1Elastic"
    local logs; logs="$(cat "$SCRIPT_DIR"/apply-passwords_*.log)"
    assert_not_contains "$logs" "New1Sketch2x" "no value in the log"
}

test_apply_passwords_ignores_hangup_and_ctrl_c_while_it_applies() {
    _world; _box_scripts; _ts_box
    _set_cfg timesketch New1Sketch2x
    # the module's apply is hit by every signal a closed ssh or a Ctrl-C sends
    cat >> "$SCRIPT_DIR/lib/credentials_apply.sh" <<'EOF'
_creds_apply_timesketch() { kill -HUP $$; kill -INT $$; kill -TERM $$; CREDS_APPLY_NOTE=survived; return 0; }
EOF
    _apply
    assert_eq "$RC" "0" "$OUT"
    assert_contains "$OUT" "timesketch: changed (survived)"
    assert_eq "$(_config_password_raw timesketch password)" "" "and finished: blanked"
}

test_apply_passwords_reports_adopted_and_not_put_back() {
    _world; _box_scripts
    echo intact_portainer > "$T/running"
    _cred_put portainer Random1Placeholder; : > "$(_cred_placeholder portainer)"; printf Set1InTheUi99 > "$T/pt_pw"
    echo intact_volweb_backend >> "$T/running"; echo 1 > "$T/vw_rc"
    _set_cfg portainer Set1InTheUi99
    _set_cfg volweb New1Volweb2x         # no stored VolWeb password, and seeding fails
    _apply
    assert_contains "$OUT" "portainer: changed (adopted)"
    assert_contains "$OUT" "volweb: FAILED, not fully put back:"
    assert_eq "$RC" "1"
}

test_apply_passwords_refuses_a_rule_breaking_value_without_touching_the_tool() {
    _world; _box_scripts; _ts_box
    _set_cfg timesketch changeme
    _apply
    assert_eq "$RC" "1"
    assert_contains "$OUT" "timesketch: reverted: the value in config.yaml is not accepted"
    assert_eq "$(cat "$T/ts_pw")" "Old1Sketch"
}

test_apply_passwords_with_nothing_to_do_says_so() {
    _world; _box_scripts
    _apply
    assert_eq "$RC" "0"
    assert_contains "$OUT" "nothing to do"
}

test_apply_passwords_is_root_only() {
    _world; _box_scripts; _set_cfg timesketch New1Sketch2x
    local rc=0 out; out="$(bash "$SCRIPT_DIR/scripts/apply-passwords.sh" 2>&1)" || rc=$?
    assert_eq "$rc" "1"
    assert_contains "$out" "Run as root"
    assert_eq "$(_config_password_raw timesketch password)" "New1Sketch2x"
}

run_all_tests
