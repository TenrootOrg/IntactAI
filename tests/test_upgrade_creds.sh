#!/bin/bash
# lib/upgrade/modules/creds.sh: carrying an old box's module passwords into the
# private stores. A wrong branch here either leaves a public password working
# or locks the platform out of a tool it already has data in, so each is pinned
# against a fake appliance tree with docker, curl and the tools stubbed.
cd "$(dirname "$0")" || exit 1
REPO="$(cd .. && pwd)"
source ./helpers.sh
source ../lib/common.sh
source ../lib/config.sh
source ../lib/secrets.sh
source ../lib/upgrade/helpers.sh
source ../lib/upgrade/modules/creds.sh
source ./creds_stubs.sh

ROOTS="$(mktemp -d)"
trap 'rm -rf "$ROOTS" "${STUB_LOG}" "${STUB_LOG}".*.out' EXIT
LOG_FILE=/dev/null

# The published Timesketch key, read at test time so it is not copied here.
PUBLISHED_KEY="$(grep -oE '"[0-9a-f]{64}"' "$REPO/.gitleaks.toml" | tr -d '"' | head -1)"

# --- a fake appliance --------------------------------------------------------
# $SCRIPT_DIR/modules/<m>/{.env,docker-compose.yaml}, config.yaml, and docker +
# curl on PATH whose answers come from files under $T (tests/creds_stubs.sh).
_world() {
    SCRIPT_DIR="$(mktemp -d -p "$ROOTS")"; T="$SCRIPT_DIR/.t"
    CONFIG_FILE="$SCRIPT_DIR/config.yaml"
    mkdir -p "$T/bin" "$SCRIPT_DIR/data/velociraptor" "$SCRIPT_DIR/modules/timesketch/config" "$SCRIPT_DIR/lib"
    cp "$REPO/lib/config.sh" "$SCRIPT_DIR/lib/"    # this release's lib/ is on the box
    local m
    for m in elk timesketch velociraptor backend iris volweb portainer; do
        mkdir -p "$SCRIPT_DIR/modules/$m"; : > "$SCRIPT_DIR/modules/$m/.env"
    done
    cat > "$CONFIG_FILE" <<'YAML'
modules:
  elk:
    enabled: true
    id: elastic
    password: '123123'
  iris:
    enabled: true
    id: administrator #Cant be changed
    password: '123123'
  portainer:
    enabled: true
    id: admin
    password: 'Ch4nge-Me!Intact2026'
  timesketch:
    enabled: true
    id: tenroot
    password: '123123'
  velociraptor:
    api_id: api
    api_password: '123123'
    enabled: true
    id: tenroot
    password: '123123'
  volweb:
    enabled: true
    id: tenroot
    password: '123123'
versions:
  elk: '9.5.6'
YAML
    creds_stubs "$T"
    PATH="$T/bin:$ORIG_PATH"
    unset DOCKER_BIN
    declare -gA PLAN_ACTION=()
    U_CREDS_SHOW=(); CREDS_ROTATED=(); CREDS_ROTATED_SHOW=()
}
ORIG_PATH="$PATH"
CREDS_WAIT=0     # a recreated tool answers at once here
_compose_reads_stores() {   # the new composes (agent B's shape)
    printf 'services:\n  x:\n    env_file:\n      - .env\n      - path: ./secrets/creds.env\n        required: false\n' \
        > "$SCRIPT_DIR/modules/$1/docker-compose.yaml"
    local o; for o in "${@:2}"; do
        printf '      - path: ../%s/secrets/creds.env\n        required: false\n' "$o" >> "$SCRIPT_DIR/modules/$1/docker-compose.yaml"
    done
}
_env() { printf '%s\n' "${@:2}" > "$SCRIPT_DIR/modules/$1/.env"; }
_cfgval() { _config_password_raw "$1" "${2:-password}"; }

# --- 1. migration -------------------------------------------------------------

test_migration_copies_unchanged_and_blanks_where_the_compose_reads_the_store() {
    _world
    printf '%s\n' elk_elasticsearch_data > "$T/volumes"
    _env elk "ELASTIC_USER=elastic" "ELASTIC_PASSWORD=Live.Pass-1x" "KIBANA_PASSWORD=Kib.Pass-2y"
    _env backend "ELASTICSEARCH_PASSWORD=Live.Pass-1x" "TIMESKETCH_PASS=Ts1Live"
    _env velociraptor "VELOX_USER=tenroot" "ELASTIC_PASSWORD=Live.Pass-1x"
    _compose_reads_stores elk
    _compose_reads_stores backend elk timesketch
    _compose_reads_stores velociraptor elk
    _u_creds_migrate elk
    assert_eq "$(secret_get elk ELASTIC_PASSWORD)" "Live.Pass-1x" "elastic copied unchanged (even an off-rule value)"
    assert_eq "$(secret_get elk KIBANA_PASSWORD)" "Kib.Pass-2y" "kibana_system copied unchanged"
    assert_eq "$(stat -c %a "$(secret_file elk)")" "600"
    assert_eq "$(sed -n 's/^ELASTIC_PASSWORD=//p' "$SCRIPT_DIR/modules/elk/.env")" "Live.Pass-1x" "copy only: the old place still works until the commit"
    _u_creds_after elk
    assert_eq "$(grep '^ELASTIC_PASSWORD=' "$SCRIPT_DIR/modules/elk/.env")" "ELASTIC_PASSWORD=" "elk .env blanked"
    assert_eq "$(grep '^KIBANA_PASSWORD=' "$SCRIPT_DIR/modules/elk/.env")" "KIBANA_PASSWORD="
    assert_eq "$(grep '^ELASTICSEARCH_PASSWORD=' "$SCRIPT_DIR/modules/backend/.env")" "ELASTICSEARCH_PASSWORD=" "backend copy blanked"
    assert_eq "$(grep '^ELASTIC_PASSWORD=' "$SCRIPT_DIR/modules/velociraptor/.env")" "ELASTIC_PASSWORD=" "velociraptor copy blanked"
    assert_eq "$(grep '^ELASTIC_USER=' "$SCRIPT_DIR/modules/elk/.env")" "ELASTIC_USER=elastic" "non-secrets untouched"
    assert_eq "$(_cfgval elk)" "" "config.yaml cleared once every module is stored"
    assert_contains "$(cat "$CONFIG_FILE")" "id: administrator #Cant be changed" "config.yaml comments kept"
}

test_an_old_compose_keeps_its_env_values() {
    _world
    printf '%s\n' elk_elasticsearch_data > "$T/volumes"
    _env elk "ELASTIC_PASSWORD=Live.Pass-1x"
    printf 'services:\n  es:\n    environment:\n      - ELASTIC_PASSWORD=${ELASTIC_PASSWORD}\n' > "$SCRIPT_DIR/modules/elk/docker-compose.yaml"
    _u_creds_migrate elk && _u_creds_after elk
    assert_eq "$(secret_get elk ELASTIC_PASSWORD)" "Live.Pass-1x" "stored"
    assert_eq "$(sed -n 's/^ELASTIC_PASSWORD=//p' "$SCRIPT_DIR/modules/elk/.env")" "Live.Pass-1x" \
        "a compose that still interpolates .env must not lose its value"
}

test_config_yaml_is_kept_while_the_box_runs_an_older_lib() {
    _world
    printf 'update_env_files() { :; }\n' > "$SCRIPT_DIR/lib/config.sh"   # an old release's lib/
    printf '%s\n' elk_elasticsearch_data > "$T/volumes"
    _env elk "ELASTIC_PASSWORD=123123"
    _u_creds_migrate elk && _u_creds_after elk
    assert_eq "$(_cfgval elk)" "123123" "its update_env_files would write the blanks into .env"
}

test_kibana_without_its_own_value_keeps_the_elastic_one() {
    _world
    printf '%s\n' elk_elasticsearch_data > "$T/volumes"
    _env elk "ELASTIC_PASSWORD=Live.Pass-1x"
    _u_creds_migrate elk
    assert_eq "$(secret_get elk KIBANA_PASSWORD)" "Live.Pass-1x" "kibana_system keeps what every old release set it to"
}

test_a_second_run_changes_nothing() {
    _world
    printf '%s\n' elk_elasticsearch_data timesketch_timesketch_postgres_data > "$T/volumes"
    : > "$SCRIPT_DIR/data/velociraptor/server.config.yaml"; echo x > "$SCRIPT_DIR/data/velociraptor/server.config.yaml"
    _env elk "ELASTIC_PASSWORD=Live1Elastic"
    _env timesketch "TIMESKETCH_PASSWORD=Live1Sketch"
    _env velociraptor "VELOX_PASSWORD=Live1Velo" "VELOX_PASSWORD_2=Live2Api"
    local m; for m in elk timesketch velociraptor iris volweb portainer; do PLAN_ACTION[$m]="noop:already"; done
    for m in elk timesketch velociraptor; do _compose_reads_stores "$m"; done
    _u_creds_migrate_all && _u_creds_after_all
    local before; before="$(cat "$SCRIPT_DIR"/modules/*/secrets/* "$SCRIPT_DIR"/modules/*/.env "$CONFIG_FILE" | sha256sum)"
    _u_creds_migrate_all && _u_creds_after_all
    PLAN_ACTION[elk]=upgrade; _u_creds_after_all
    assert_eq "$(grep -c . "$SCRIPT_DIR/modules/timesketch/.env")" "1" "fixture: the .env was cleared on the first run"
    assert_eq "$(cat "$SCRIPT_DIR/modules/timesketch/.env")" "TIMESKETCH_PASSWORD="
    assert_eq "$(cat "$SCRIPT_DIR"/modules/*/secrets/* "$SCRIPT_DIR"/modules/*/.env "$CONFIG_FILE" | sha256sum)" "$before" "idempotent"
    assert_eq "$(secret_get timesketch TIMESKETCH_PASSWORD)" "Live1Sketch"
    assert_eq "$(secret_get velociraptor VELOX_PASSWORD_2)" "Live2Api"
}

test_a_module_not_in_the_package_loses_its_env_copy_once_its_compose_reads_the_store() {
    _world
    printf '%s\n' elk_elasticsearch_data timesketch_timesketch_postgres_data > "$T/volumes"
    _env elk "ELASTIC_PASSWORD=Live1Elastic"
    _env timesketch "TIMESKETCH_PASSWORD=Live1Sketch"
    _compose_reads_stores elk; _compose_reads_stores timesketch
    PLAN_ACTION[elk]="skip:not in this package"; PLAN_ACTION[timesketch]="skip:excluded by --skip"
    _u_creds_migrate_all && _u_creds_after_all
    assert_eq "$(grep '^ELASTIC_PASSWORD=' "$SCRIPT_DIR/modules/elk/.env")" "ELASTIC_PASSWORD=" "leftover copy cleared"
    assert_eq "$(secret_get elk ELASTIC_PASSWORD)" "Live1Elastic" "the store keeps it"
    assert_eq "$(sed -n 's/^TIMESKETCH_PASSWORD=//p' "$SCRIPT_DIR/modules/timesketch/.env")" "Live1Sketch" "--skip means hands off"
}

# --- 4. a module installed later (the upgrade engine's install path) -----------

test_ui_install_generates_only_for_a_tool_with_no_data() {
    _world
    # no volumes: every tool is new; .env/config.yaml carry the old public values
    _env elk "ELASTIC_PASSWORD=123123" "KIBANA_PASSWORD=123123"
    _u_creds_migrate elk
    local v; v="$(secret_get elk ELASTIC_PASSWORD)"
    assert_ne "$v" "123123" "a public value is never carried into a NEW tool"
    assert_true secret_check "$v"
    assert_ne "$(secret_get elk KIBANA_PASSWORD)" "$v" "kibana_system gets its own"
    _u_creds_migrate iris
    assert_true secret_check "$(cred_get iris)"
    assert_eq "$(stat -c %a "$(_cred_file iris)")" "644" "IRIS reads its file as uid 65534"
    # an operator-typed value that passes the rule is kept
    _env timesketch "TIMESKETCH_PASSWORD=Typed1ByOperator"
    _u_creds_migrate timesketch
    assert_eq "$(secret_get timesketch TIMESKETCH_PASSWORD)" "Typed1ByOperator"
}

test_ui_install_onto_existing_data_keeps_the_old_value_or_warns() {
    _world
    printf '%s\n' elk_elasticsearch_data volweb_volweb_postgres_data > "$T/volumes"
    _env elk "ELASTIC_PASSWORD=123123"
    _u_creds_migrate elk
    assert_eq "$(secret_get elk ELASTIC_PASSWORD)" "123123" "the data's own value, not a new one it would refuse"
    # data, and no value anywhere: nothing minted
    sed -i "/password:/d" "$CONFIG_FILE"
    local out; out="$(_u_creds_migrate volweb 2>&1)"
    assert_false cred_get volweb
    assert_contains "$out" "Not minting one"
}

# --- 2. rotation ----------------------------------------------------------------

_velo_box() {   # a running Velociraptor whose users still have the public value
    echo intact_velociraptor > "$T/running"
    _env velociraptor "VELOX_USER=tenroot" "VELOX_ROLE=administrator" "VELOX_USER_2=api"
    _compose_reads_stores velociraptor elk
    secret_set velociraptor VELOX_PASSWORD 123123
    secret_set velociraptor VELOX_PASSWORD_2 123123
    printf '%s\n' tenroot:123123 api:123123 | tee "$T/velo_db" > "$T/velo_live"
}

test_velociraptor_rotates_only_known_defaults_and_never_removes_api() {
    _world; _velo_box
    _creds_rotate_velociraptor
    local gui api calls; gui="$(secret_get velociraptor VELOX_PASSWORD)"; api="$(secret_get velociraptor VELOX_PASSWORD_2)"
    calls="$(cat "$T/calls")"
    assert_true secret_check "$gui"; assert_true secret_check "$api"
    assert_contains "$calls" '--role "$2" _ tenroot administrator'
    assert_contains "$calls" '--role "$2" _ api api,administrator' "api keeps its identity's roles"
    assert_not_contains "$(cat "$T/calls" "$T/argv")" "$gui" "the value is in the exec's env, not its argv"
    assert_not_contains "$(cat "$T/calls" "$T/argv")" "$api"
    assert_true grep -qx "tenroot:${gui}" "$T/velo_live"; assert_true grep -qx "api:${api}" "$T/velo_live"
    assert_not_contains "$calls" "delete" "api (the backend's API cert identity) is never removed"
    assert_not_contains "$calls" "user_delete"
    assert_eq "${#CREDS_ROTATED_SHOW[@]}" "1" "only the GUI user is shown, never api"
    assert_eq "${CREDS_ROTATED_SHOW[0]}" "Velociraptor|tenroot|${gui}"
    assert_eq "${CREDS_ROTATED[*]}" "velociraptor"
    : > "$T/calls"; CREDS_ROTATED_SHOW=()
    _creds_rotate_velociraptor
    assert_eq "$(grep -v 'inspect' "$T/calls")" "" "a value that is no longer public is left alone"
}

# The proven 0.77.3 behaviour: the running server keeps the users it loaded.
test_a_velociraptor_change_recreates_the_server_before_it_verifies() {
    _world; _velo_box
    _creds_rotate_velociraptor
    local calls; calls="$(cat "$T/calls")"
    assert_contains "$calls" "compose velociraptor up -d --force-recreate --no-build --pull never velociraptor" \
        "recreated (env_file re-read), not docker restart"
    assert_not_contains "$calls" "docker restart intact_velociraptor"
    local add rec login
    add="$(grep -n "user add.* _ tenroot " "$T/calls" | cut -d: -f1)"
    rec="$(grep -n 'force-recreate' "$T/calls" | head -1 | cut -d: -f1)"
    login="$(grep -n 'curl GET .*:8889' "$T/calls" | tail -1 | cut -d: -f1)"
    assert_true test "$add" -lt "$rec"; assert_true test "$rec" -lt "$login"
    assert_true grep -qx "tenroot:$(secret_get velociraptor VELOX_PASSWORD)" "$T/velo_live"
}

test_a_velociraptor_change_that_does_not_log_in_is_put_back() {
    _world; _velo_box
    : > "$T/velo_rc"; echo 0 > "$T/velo_rc"
    # user add "works" but the recreate never loads it (a broken compose up)
    echo 1 > "$T/compose_rc"
    _creds_rotate_velociraptor 2>/dev/null
    assert_eq "$(secret_get velociraptor VELOX_PASSWORD)" "123123" "store back on the old value"
    assert_eq "$(secret_get velociraptor VELOX_PASSWORD_2)" "123123"
    assert_eq "${#CREDS_ROTATED_SHOW[@]}" "0"
    # the failed recreate left it down, so the old value could not be applied
    # from outside: the next start does it (the store is authoritative)
    rm -f "$T/compose_rc"; _creds_recreate velociraptor velociraptor
    assert_true grep -qx "tenroot:123123" "$T/velo_live"
    assert_true grep -qx "api:123123" "$T/velo_live"
}

# Like Portainer and IRIS: a stored public value that no longer logs in was
# changed in the Velociraptor UI. Not rotated over the operator's head.
test_a_velociraptor_user_changed_in_its_ui_is_not_rotated() {
    _world; _velo_box
    printf '%s\n' tenroot:Mine1FromTheUi api:123123 | tee "$T/velo_db" > "$T/velo_live"
    # the entrypoint applied the stored value at an earlier start (its stamp)
    printf '%s' 123123 | sha256sum | cut -d' ' -f1 > "$SCRIPT_DIR/data/velociraptor/.gui_pw.sha256"
    local out; out="$(_creds_rotate_velociraptor 2>&1)"
    assert_contains "$out" "'tenroot' no longer logs in with its stored (public) password"
    assert_true grep -qx tenroot:Mine1FromTheUi "$T/velo_live" "the operator's password stands"
    assert_ne "$(secret_get velociraptor VELOX_PASSWORD_2)" "123123" "api is still rotated"
}

test_a_failed_velociraptor_rotation_keeps_the_old_value() {
    _world; _velo_box
    echo 1 > "$T/velo_rc"
    _creds_rotate_velociraptor 2>/dev/null
    assert_eq "$(secret_get velociraptor VELOX_PASSWORD)" "123123" "store and tool stay in step"
    assert_eq "${#CREDS_ROTATED_SHOW[@]}" "0"
}

test_a_stopped_velociraptor_is_not_touched() {
    _world
    secret_set velociraptor VELOX_PASSWORD 123123
    _creds_rotate_velociraptor
    assert_eq "$(grep -v inspect "$T/calls")" "" "rotation only against a running tool"
}

test_the_lab_switch_rotates_nothing() {
    _world; _velo_box
    echo 'allow_weak_passwords: true' >> "$CONFIG_FILE"
    _cred_put portainer 'Ch4nge-Me!Intact2026'; echo 'Ch4nge-Me!Intact2026' > "$T/pt_pw"; echo intact_portainer >> "$T/running"
    mkdir -p "$SCRIPT_DIR/data/state"; echo '{"modules":["elk"],"rotated":[],"since":"x"}' > "$SCRIPT_DIR/data/state/default-passwords.json"
    creds_rotate_known_defaults >/dev/null
    assert_eq "$(secret_get velociraptor VELOX_PASSWORD)" "123123"
    assert_eq "$(cred_get portainer)" 'Ch4nge-Me!Intact2026'
    assert_not_contains "$(cat "$T/calls")" "user add"
    assert_false test -e "$SCRIPT_DIR/data/state/default-passwords.json"
}

test_portainer_rotates_through_its_api_and_verifies() {
    _world
    echo intact_portainer > "$T/running"
    _cred_put portainer 'Ch4nge-Me!Intact2026'; echo 'Ch4nge-Me!Intact2026' > "$T/pt_pw"
    _creds_rotate_portainer
    local new; new="$(cred_get portainer)"
    assert_true secret_check "$new"
    assert_eq "$(cat "$T/pt_pw")" "$new" "the tool and the file hold the same new password"
    assert_contains "$(cat "$T/calls")" "curl PUT https://127.0.0.1:9443/api/users/3/passwd"
    assert_eq "${CREDS_ROTATED_SHOW[0]}" "Portainer|admin|${new}"
}

test_a_refused_portainer_change_keeps_the_old_password() {
    _world
    echo intact_portainer > "$T/running"
    _cred_put portainer 'Ch4nge-Me!Intact2026'; echo 'Ch4nge-Me!Intact2026' > "$T/pt_pw"
    : > "$T/pt_refuse"
    _creds_rotate_portainer 2>/dev/null
    assert_eq "$(cred_get portainer)" 'Ch4nge-Me!Intact2026'
    assert_eq "$(cat "$T/pt_pw")" 'Ch4nge-Me!Intact2026'
    assert_eq "${#CREDS_ROTATED_SHOW[@]}" "0"
}

test_a_portainer_placeholder_is_never_sent_or_rotated() {
    _world
    printf '%s\n' portainer_portainer_data > "$T/volumes"
    sed -i "/password:/d" "$CONFIG_FILE"
    source ../lib/upgrade/modules/portainer.sh
    _u_ensure_portainer_admin_secret >/dev/null 2>&1
    assert_true test -s "$(_cred_file portainer)"
    assert_eq "$(stat -c %a "$(_cred_file portainer)")" "600"
    assert_true test -e "$SCRIPT_DIR/modules/portainer/secrets/admin_password.placeholder"
    echo intact_portainer > "$T/running"
    _creds_rotate_portainer
    assert_not_contains "$(cat "$T/calls")" "curl" "Portainer is never asked to log in with a placeholder"
    assert_false creds_apply portainer New1Portainer2x
    assert_contains "$CREDS_APPLY_REASON" "not known"
}

test_iris_rotates_only_when_the_default_still_logs_in() {
    _world
    printf '%s\n' intact_iris_app intact_iris_db > "$T/running"
    _cred_put iris 123123; printf 123123 > "$T/iris_pw"
    enforce_iris_admin_password() { cred_get iris > "$T/iris_pw"; }
    _creds_rotate_iris
    local new; new="$(cred_get iris)"
    assert_ne "$new" "123123"; assert_eq "$(cat "$T/iris_pw")" "$new" "applied and verified"
    assert_eq "${CREDS_ROTATED_SHOW[0]}" "IRIS|administrator|${new}"
    # enforce that does not take: the file goes back
    _world
    printf '%s\n' intact_iris_app intact_iris_db > "$T/running"
    _cred_put iris 123123; printf 123123 > "$T/iris_pw"
    enforce_iris_admin_password() { return 0; }
    _creds_rotate_iris 2>/dev/null
    assert_eq "$(cred_get iris)" "123123" "an unapplied change is put back"
    # the operator already changed it in IRIS: nothing to do
    _world
    printf '%s\n' intact_iris_app intact_iris_db > "$T/running"
    _cred_put iris 123123; printf Their1Own > "$T/iris_pw"
    _creds_rotate_iris
    assert_eq "$(cred_get iris)" "123123"
    assert_eq "$(cat "$T/iris_pw")" "Their1Own"
    unset -f enforce_iris_admin_password
}

test_iris_adopts_the_config_value_it_actually_runs_with() {
    _world
    printf '%s\n' iris_iris_db_data > "$T/volumes"
    printf '%s\n' intact_iris_app intact_iris_db > "$T/running"
    _cred_put iris 123123; printf Cfg1Applied > "$T/iris_pw"
    sed -i "0,/password: '123123'/! {0,/password: '123123'/ s//password: 'Cfg1Applied'/}" "$CONFIG_FILE"
    assert_eq "$(_cfgval iris)" "Cfg1Applied" "fixture"
    _u_creds_migrate iris
    assert_eq "$(cred_get iris)" "Cfg1Applied" "enforce_iris_admin_password made config.yaml the live one"
}

test_timesketch_published_secret_key_is_replaced_and_web_restarted() {
    _world
    echo intact_timesketch_web > "$T/running"; echo intact_timesketch_worker >> "$T/running"
    local d="$SCRIPT_DIR/modules/timesketch/config"
    printf "X = 1\nSECRET_KEY = '%s'\nY = 2\n" "$PUBLISHED_KEY" > "$d/timesketch.conf"
    printf "SECRET_KEY = '%s'\n" "$(printf 'a%.0s' {1..64})" > "$d/timesketch_legacy.conf"
    local ino; ino="$(stat -c %i "$d/timesketch.conf")"
    _creds_rotate_timesketch
    assert_not_contains "$(cat "$d/timesketch.conf")" "$PUBLISHED_KEY"
    assert_true grep -qE "^SECRET_KEY = '[0-9a-f]{64}'$" "$d/timesketch.conf"
    assert_contains "$(cat "$d/timesketch.conf")" "Y = 2" "the rest of the conf kept"
    assert_eq "$(stat -c %i "$d/timesketch.conf")" "$ino" "rewritten in place (bind-mounted file)"
    assert_contains "$(cat "$d/timesketch_legacy.conf")" "$(printf 'a%.0s' {1..64})" "an unpublished key is left alone"
    assert_contains "$(cat "$T/calls")" "restart intact_timesketch_web intact_timesketch_worker"
    # a failed restart puts the published one back rather than half-apply
    printf "SECRET_KEY = '%s'\n" "$PUBLISHED_KEY" > "$d/timesketch.conf"; echo 1 > "$T/restart_rc"
    _creds_rotate_timesketch 2>/dev/null
    assert_contains "$(cat "$d/timesketch.conf")" "$PUBLISHED_KEY"
}

# --- 3. the default-password marker --------------------------------------------

_marker() { python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(",".join(d["modules"]) + "|" + ",".join(d["rotated"]))' "$SCRIPT_DIR/data/state/default-passwords.json"; }

test_the_marker_lists_machine_used_defaults_and_shrinks() {
    _world
    local f="$SCRIPT_DIR/data/state/default-passwords.json"
    secret_set elk ELASTIC_PASSWORD 123123; secret_set elk KIBANA_PASSWORD Kib1Random
    secret_set timesketch TIMESKETCH_PASSWORD changeme
    _cred_put volweb 123123
    secret_set velociraptor VELOX_PASSWORD 123123   # human-only: rotated, never marked
    creds_mark_defaults 2>/dev/null
    assert_eq "$(_marker)" "elk,timesketch,volweb|"
    assert_eq "$(stat -c %a "$f")" "600" "the backend reads it as root"
    local since; since="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["since"])' "$f")"
    assert_true grep -qE '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:]{8}Z$' <<<"$since"
    sleep 1
    secret_set elk ELASTIC_PASSWORD Changed1ByHand
    creds_mark_defaults 2>/dev/null
    assert_eq "$(_marker) $(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["since"])' "$f")" \
        "timesketch,volweb| ${since}" "elk dropped once it is no longer public; since kept"
    secret_set timesketch TIMESKETCH_PASSWORD Changed1ByHand; _cred_put volweb Changed1ByHand
    creds_mark_defaults
    assert_false test -e "$f"
}

test_the_marker_lists_what_a_rotation_changed_until_cleared() {
    _world; _velo_box
    creds_rotate_known_defaults velociraptor >/dev/null
    local f="$SCRIPT_DIR/data/state/default-passwords.json"
    assert_eq "$(_marker)" "|velociraptor" "rotated, so the operator has a password they have not seen"
    assert_eq "$(stat -c %a "$f")" "600"
    CREDS_ROTATED=()
    creds_mark_defaults
    assert_eq "$(_marker)" "|velociraptor" "kept across runs until the admin has seen it"
}

test_kibana_system_gets_a_new_value_when_the_old_one_is_public() {
    _world
    printf '%s\n' elk_elasticsearch_data > "$T/volumes"
    _env elk "ELASTIC_PASSWORD=123123" "KIBANA_PASSWORD=123123"
    _u_creds_migrate elk >/dev/null
    assert_eq "$(secret_get elk ELASTIC_PASSWORD)" "123123" "elastic is machine-used: kept (apply-passwords.sh changes it)"
    local k; k="$(secret_get elk KIBANA_PASSWORD)"
    assert_ne "$k" "123123" "kibana_system: the setup container sets it before Kibana starts"
    assert_true secret_check "$k"
    # on a lab box the public one is kept
    _world
    echo 'allow_weak_passwords: true' >> "$CONFIG_FILE"
    printf '%s\n' elk_elasticsearch_data > "$T/volumes"
    _env elk "ELASTIC_PASSWORD=123123"
    _u_creds_migrate elk >/dev/null
    assert_eq "$(secret_get elk KIBANA_PASSWORD)" "123123"
}

test_a_lost_store_names_its_recovery_sources() {
    _world
    printf '%s\n' elk_elasticsearch_data > "$T/volumes"
    sed -i "/password:/d" "$CONFIG_FILE"
    local out; out="$(_u_creds_migrate elk 2>&1)"
    assert_contains "$out" "data/state/elk/secrets/"
    assert_contains "$out" "docker inspect intact_elasticsearch"
}

test_an_unclaimed_box_gets_a_setup_token() {
    _world
    cp "$REPO/lib/setup_token.sh" "$SCRIPT_DIR/lib/"
    printf 'first_login: true\ndomain: box.example\n' >> "$CONFIG_FILE"
    _u_creds_after_all >/dev/null
    local f="$SCRIPT_DIR/data/state/backend/setup_token"
    assert_true test -s "$f"
    assert_eq "$(stat -c %a "$f")" "600"
    assert_eq "${U_CREDS_SHOW[*]: -1}" "Dashboard setup token|-|$(cat "$f")" "shown with the other credentials"
    local tok; tok="$(cat "$f")"; U_CREDS_SHOW=()
    _u_creds_after_all >/dev/null
    assert_eq "$(cat "$f")" "$tok" "an existing token is kept"
    assert_eq "${#U_CREDS_SHOW[@]}" "0"
    # a claimed box needs none
    _world; cp "$REPO/lib/setup_token.sh" "$SCRIPT_DIR/lib/"
    printf 'first_login: false\n' >> "$CONFIG_FILE"
    _u_creds_after_all >/dev/null
    assert_false test -e "$SCRIPT_DIR/data/state/backend/setup_token"
}

test_elk_installed_later_recreates_a_running_velociraptor() {
    _world
    echo intact_velociraptor > "$T/running"
    printf 'services: {}\n' > "$SCRIPT_DIR/modules/velociraptor/docker-compose.yaml"
    secret_set elk ELASTIC_PASSWORD Gen1Erated
    PLAN_ACTION[elk]=install
    _u_creds_after elk >/dev/null
    assert_contains "$(cat "$T/calls")" "compose velociraptor up -d --force-recreate --no-build --pull never velociraptor"
    : > "$T/calls"; PLAN_ACTION[elk]=upgrade
    _u_creds_after elk >/dev/null
    assert_not_contains "$(cat "$T/calls")" "compose velociraptor"
}

test_passwords_reach_their_stores_before_any_store_reading_compose_lands() {
    local f=../lib/upgrade/intact/intact.sh mig ref mir
    mig="$(grep -n 'u_do "module passwords into their stores"' "$f" | cut -d: -f1)"
    ref="$(grep -n 'u_do .*"refresh sidecar compose files and assets"' "$f" | cut -d: -f1)"
    mir="$(grep -n 'u_do .*"mirror the backend tree"' "$f" | cut -d: -f1)"
    assert_eq "$(grep -c '_u_creds_migrate_all' "$f")" "1" "one migration step"
    assert_true test "$mig" -lt "$ref"
    assert_true test "$mig" -lt "$mir"
}

test_a_lost_store_comes_back_from_data_state_before_the_migration() {
    _world
    source ../lib/state_registry.sh
    source ../lib/upgrade/modules/shared.sh
    printf '%s\n' elk_elasticsearch_data > "$T/volumes"
    sed -i "/password:/d" "$CONFIG_FILE"
    mkdir -p "$SCRIPT_DIR/data/state/elk/secrets"
    ( umask 077; printf 'ELASTIC_PASSWORD=Kept1InState\nKIBANA_PASSWORD=Kib1InState\n' > "$SCRIPT_DIR/data/state/elk/secrets/creds.env" )
    _u_state_migrate >/dev/null
    assert_eq "$(secret_get elk ELASTIC_PASSWORD)" "Kept1InState" "re-linked from data/state"
    assert_true test "$SCRIPT_DIR/modules/elk/secrets/creds.env" -ef "$SCRIPT_DIR/data/state/elk/secrets/creds.env"
    local out; out="$(_u_creds_migrate elk 2>&1)"
    assert_not_contains "$out" "stored nowhere"
    assert_eq "$(secret_get elk KIBANA_PASSWORD)" "Kib1InState"
}

# --- plumbing ---------------------------------------------------------------------

test_credentials_are_shown_once_when_the_run_exits() {
    local out
    out="$(
        secret_show_once() { cat; }
        _U_CREDS_TRAP=""   # earlier tests armed it in the parent shell
        trap 'echo previous-handler' EXIT
        _u_creds_show "Velociraptor|tenroot|Pw1"
        _u_creds_show "IRIS|administrator|Pw2"
        echo during-run
    )"
    assert_eq "$out" "$(printf 'during-run\nVelociraptor|tenroot|Pw1\nIRIS|administrator|Pw2\nprevious-handler')" \
        "one block, after the run, and the earlier EXIT handler still runs"
}

test_an_install_shows_its_human_credential() {
    _world
    secret_set timesketch TIMESKETCH_PASSWORD Gen1Erated
    PLAN_ACTION[timesketch]=install
    _u_creds_after timesketch
    assert_eq "${U_CREDS_SHOW[0]}" "Timesketch|tenroot|Gen1Erated"
}

test_optional_env_files_are_not_reported_missing() {
    _world
    source ../lib/upgrade/modules/shared.sh
    _compose_reads_stores backend elk
    printf '      - path: ./secrets/needed.env\n' >> "$SCRIPT_DIR/modules/backend/docker-compose.yaml"
    local out; out="$(_u_compose_sources "$SCRIPT_DIR/modules/backend/docker-compose.yaml")"
    assert_contains "$out" "envfile .env"
    assert_contains "$out" "envfile secrets/needed.env" "a required long-form entry is still checked"
    assert_not_contains "$out" "creds.env" "required: false entries are optional"
}

test_no_value_reaches_the_log() {
    _world
    LOG_FILE="$T/upgrade.log"; : > "$LOG_FILE"
    printf '%s\n' elk_elasticsearch_data > "$T/volumes"
    echo intact_velociraptor > "$T/running"
    _env elk "ELASTIC_PASSWORD=Secret1Elastic"
    _compose_reads_stores elk
    _u_creds_migrate elk >/dev/null 2>&1; _u_creds_after elk >/dev/null 2>&1
    _velo_box
    _creds_rotate_velociraptor >/dev/null 2>&1
    assert_not_contains "$(cat "$LOG_FILE")" "Secret1Elastic"
    assert_not_contains "$(cat "$LOG_FILE")" "$(secret_get velociraptor VELOX_PASSWORD)"
    LOG_FILE=/dev/null
}

run_all_tests
