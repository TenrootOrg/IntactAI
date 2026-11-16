#!/bin/bash
# Install-side module passwords (lib/config.sh ensure_module_credentials and
# friends). A wrong answer here ships a known password, writes one the tool
# rejects, or leaves a typed password in config.yaml -- the tracked file that
# is also bind-mounted into the backend.
set -u
cd "$(dirname "${BASH_SOURCE[0]}")" || exit 1
source ./helpers.sh

LOG_FILE=/dev/null
source ../lib/common.sh
source ../lib/config.sh

WORK=""
_setup() {  # _setup "<yaml under modules:>" -- an argument, not a pipe: a piped
            # function runs in a subshell and its variables never reach the test
    [[ -n "$WORK" ]] && rm -rf "$WORK"
    WORK="$(mktemp -d)"
    SCRIPT_DIR="$WORK"
    CONFIG_FILE="$WORK/config.yaml"
    mkdir -p "$WORK/modules/elk"
    {
        echo "domain: 10.0.0.5"
        echo "# top comment"
        echo "modules:"
        printf '%s\n' "${1:-}"
        echo "versions:"
        echo "  elk: '9.5.6'"
    } > "$CONFIG_FILE"
    # No docker data anywhere unless a test says otherwise.
    docker() { [[ "$*" == "volume inspect"* ]] && return 1; return 0; }
    _cred_have_tty() { return 1; }
}
_all_blank() {
    cat <<'Y'
  elk:
    enabled: true
    id: elastic
    password: ''
  timesketch:
    enabled: true
    id: tenroot
    password: ''
  velociraptor:
    enabled: true
    id: tenroot
    api_id: api
    password: ''
  iris:
    enabled: true
    id: administrator #Cant be changed
    password: ''
  volweb:
    enabled: false
    id: tenroot
    password: ''
  portainer:
    enabled: true
    id: admin
    password: ''
Y
}
trap '[[ -n "$WORK" ]] && rm -rf "$WORK"; rm -f "${STUB_LOG}"' EXIT

test_nothing_set_generates_a_good_password_for_every_module() {
    _setup "$(_all_blank)"
    assert_true ensure_module_credentials
    local m pw
    for m in elk timesketch velociraptor iris volweb portainer; do
        pw="$(cred_get "$m")" || { _fail "$m has no stored password"; continue; }
        assert_true secret_check "$pw"
    done
    assert_true secret_get elk KIBANA_PASSWORD
    assert_true secret_get velociraptor VELOX_PASSWORD_2
    assert_ne "$(secret_get elk KIBANA_PASSWORD)" "$(cred_get elk)" "kibana_system has its own password"
    assert_eq "$(stat -c %a "$WORK/modules/iris/secrets/IRIS_ADM_PASSWORD")" "644" "IRIS file stays readable for uid 65534"
    assert_eq "$(stat -c %a "$WORK/modules/iris/secrets")" "700" "inside a private dir"
    assert_eq "$(stat -c %a "$WORK/modules/portainer/secrets/admin_password")" "600" "portainer file 0600"
}

test_config_value_is_taken_raw_and_stored() {
    # 0x... would be an int under safe_load; it must arrive as typed.
    _setup "$(_all_blank | sed "/^  timesketch:/,/password/ s/password: ''/password: 0x1F2eAbCdEf99/")"
    assert_true ensure_module_credentials
    assert_eq "$(cred_get timesketch)" "0x1F2eAbCdEf99" "stored exactly as typed"
}

test_weak_config_value_stops_and_changes_nothing() {
    _setup "$(_all_blank | sed "/^  iris:/,/password/ s/password: ''/password: '123123'/")"
    local before; before="$(cat "$CONFIG_FILE")"
    assert_false ensure_module_credentials
    assert_eq "$(ls "$WORK/modules" | tr '\n' ' ')" "elk " "nothing stored for any module"
    assert_eq "$(cat "$CONFIG_FILE")" "$before" "config.yaml untouched on refusal"
}

test_stored_value_is_kept_and_a_different_config_value_stops() {
    _setup "$(_all_blank)"
    secret_set timesketch TIMESKETCH_PASSWORD "Kept1Password22"
    assert_true ensure_module_credentials
    assert_eq "$(cred_get timesketch)" "Kept1Password22" "stored password kept"
    sed -i "/^  timesketch:/,/password/ s/password: ''/password: 'Other1Password22'/" "$CONFIG_FILE"
    local out; out="$(ensure_module_credentials 2>&1)"
    assert_false ensure_module_credentials
    assert_contains "$out" "the Timesketch password is already set — to change it," "names the tool"
    assert_contains "$out" "keep the new value in config.yaml and run: sudo scripts/apply-passwords.sh" "points at the apply step"
    assert_eq "$(cred_get timesketch)" "Kept1Password22" "not replaced"
    assert_contains "$(cat "$CONFIG_FILE")" "Other1Password22" "the new value stays for apply-passwords.sh"
    # The same value as stored is fine (and gets blanked).
    sed -i "s/Other1Password22/Kept1Password22/" "$CONFIG_FILE"
    assert_true ensure_module_credentials
    assert_not_contains "$(cat "$CONFIG_FILE")" "Kept1Password22" "blanked"
}

test_prompt_typed_twice_rejects_weak_then_accepts() {
    _setup "$(_all_blank)"
    _cred_have_tty() { return 0; }
    # iris prompt: weak, then good twice; every other enabled module: Enter.
    # Order of prompts follows INTACT_CRED_MODULES (volweb is disabled).
    printf '\n\n\nshort\nGood1Password33\nGood1Password33\n\n' | ensure_module_credentials >/dev/null 2>&1
    assert_eq "$(cred_get iris)" "Good1Password33" "typed value stored after a refusal"
    assert_true secret_check "$(cred_get portainer)"
    assert_true secret_check "$(cred_get elk)"
}

test_prompt_mismatch_asks_again() {
    _setup "$(_all_blank)"
    _cred_have_tty() { return 0; }
    printf 'Good1Password33\nGood1Password34\nGood1Password35\nGood1Password35\n\n\n\n\n' \
        | ensure_module_credentials >/dev/null 2>&1
    assert_eq "$(cred_get elk)" "Good1Password35" "second, matching pair wins"
}

test_elasticsearch_with_data_keeps_the_old_password() {
    _setup "$(_all_blank)"
    docker() { [[ "$*" == "volume inspect elk_elasticsearch_data" ]] && return 0; [[ "$*" == "volume inspect"* ]] && return 1; return 0; }
    printf 'ELASTIC_VERSION=9.5.6\nELASTIC_PASSWORD=Old1Elastic999\n' > "$WORK/modules/elk/.env"
    assert_true ensure_module_credentials
    assert_eq "$(cred_get elk)" "Old1Elastic999" "the value ES was created with"
}

# Velociraptor's entrypoint creates the GUI user only when missing, so over an
# existing datastore a newly minted password would never reach the server and
# show-credentials would print one that does not work.
test_velociraptor_with_data_keeps_the_old_password() {
    _setup "$(_all_blank)"
    docker() { [[ "$*" == "volume inspect velociraptor_velociraptor_datastore" ]] && return 0; [[ "$*" == "volume inspect"* ]] && return 1; return 0; }
    mkdir -p "$WORK/modules/velociraptor"
    printf 'VELOX_USER=tenroot\nVELOX_PASSWORD=Old1Velociraptor\n' > "$WORK/modules/velociraptor/.env"
    assert_true ensure_module_credentials
    assert_eq "$(secret_get velociraptor VELOX_PASSWORD)" "Old1Velociraptor" "the value the datastore was created with"
}

# Portainer reads its file at first start only, so with data and nothing known
# the install goes on: a random file (the bind mount needs one) + a marker, and
# every display says "unknown" instead of a password that does not work.
test_portainer_with_data_and_nothing_known_gets_a_placeholder() {
    _setup "$(_all_blank)"
    docker() { [[ "$*" == "volume inspect portainer_portainer_data" ]] && return 0; [[ "$*" == "volume inspect"* ]] && return 1; return 0; }
    assert_true ensure_module_credentials
    local f="$WORK/modules/portainer/secrets/admin_password"
    assert_true test -s "$f"
    assert_eq "$(stat -c %a "$f")" "600" "placeholder file 0600"
    assert_true test -e "$f.placeholder"
    assert_eq "$(stat -c %s "$f.placeholder")" "0" "marker is empty"
    assert_eq "$(cred_get portainer)" "unknown" "cred_get says unknown"
    local lines; lines="$(credential_lines --ids)"
    assert_contains "$lines" "portainer|admin|unknown|" "unknown, with a hint field"
    assert_not_contains "$lines" "$(cat "$f")" "the placeholder value is never shown"
    assert_true ensure_module_credentials                 # a re-run keeps it
    # A real value stored later (apply-passwords, upgrade rotation) clears it.
    _cred_put portainer "Real1Portainer99"
    assert_false test -e "$f.placeholder"
    assert_eq "$(cred_get portainer)" "Real1Portainer99" "real value after a store"
}

test_elk_with_data_and_nothing_known_names_the_recovery_sources() {
    _setup "$(_all_blank)"
    docker() { [[ "$*" == "volume inspect elk_elasticsearch_data" ]] && return 0; [[ "$*" == "volume inspect"* ]] && return 1; return 0; }
    local out; out="$(ensure_module_credentials 2>&1)"
    assert_false ensure_module_credentials
    assert_contains "$out" "data/state/elk/secrets/creds.env" "names the data/state copy"
    assert_contains "$out" "docker inspect intact_elasticsearch" "names the container env"
    assert_false test -e "$WORK/modules/elk/secrets/creds.env"
}

test_velociraptor_with_data_and_nothing_known_still_stops() {
    _setup "$(_all_blank)"
    docker() { [[ "$*" == "volume inspect velociraptor_velociraptor_datastore" ]] && return 0; [[ "$*" == "volume inspect"* ]] && return 1; return 0; }
    local out; out="$(ensure_module_credentials 2>&1)"
    assert_false ensure_module_credentials
    assert_contains "$out" "data/state/velociraptor/secrets/creds.env" "names the data/state copy"
}

# generate_elk_secrets & co. call it for one module: the other modules' lines
# (maybe typed for scripts/apply-passwords.sh) must survive, and no EXIT trap.
test_single_module_call_blanks_only_its_own_line() {
    _setup "$(_all_blank | sed -e "/^  elk:/,/password/ s/password: ''/password: 'Elk1Password999'/" \
                             -e "/^  timesketch:/,/password/ s/password: ''/password: 'Ts1Password9999'/")"
    (
        unset _CRED_EXIT_ARMED
        ensure_module_credentials elk >/dev/null 2>&1 || exit 1
        [[ -z "${_CRED_EXIT_ARMED:-}" ]] || exit 2
    )
    assert_eq "$?" "0" "succeeds without arming the EXIT trap"
    assert_eq "$(cred_get elk)" "Elk1Password999" "elk stored"
    assert_eq "$(_config_password_raw elk password)" "" "elk line blanked"
    assert_eq "$(_config_password_raw timesketch password)" "Ts1Password9999" "timesketch line untouched"
    assert_false cred_get timesketch
}

# A store that fails must not leave an armed trap that wipes the operator's
# only typed copy on exit.
test_failed_store_leaves_config_and_no_trap() {
    _setup "$(_all_blank | sed "/^  iris:/,/password/ s/password: ''/password: 'Iris1Password99'/")"
    (
        unset _CRED_EXIT_ARMED
        _cred_put() { return 1; }
        ensure_module_credentials >/dev/null 2>&1 && exit 1
        [[ -z "${_CRED_EXIT_ARMED:-}" ]] || exit 2
    )
    assert_eq "$?" "0" "fails, no trap armed"
    assert_eq "$(_config_password_raw iris password)" "Iris1Password99" "typed value still in config.yaml"
}

# scripts/clean.sh empties data/, leaving the registered secrets dirs as
# symlinks to nothing; the re-install must store through them.
test_dangling_secrets_symlinks_do_not_break_a_reinstall() {
    _setup "$(_all_blank)"
    mkdir -p "$WORK/modules/velociraptor" "$WORK/modules/iris" "$WORK/data"
    ln -s ../../data/state/velociraptor/secrets "$WORK/modules/velociraptor/secrets"
    ln -s ../../data/state/iris/secrets "$WORK/modules/iris/secrets"
    assert_true ensure_module_credentials
    assert_true secret_check "$(cred_get velociraptor)"
    assert_true secret_check "$(cred_get iris)"
    assert_true test -L "$WORK/modules/velociraptor/secrets"
    assert_eq "$(stat -c %a "$WORK/data/state/velociraptor/secrets")" "700" "target dir private"
    assert_eq "$(stat -c %a "$WORK/data/state/velociraptor/secrets/creds.env")" "600" "creds.env 0600"
    assert_eq "$(stat -c %a "$WORK/data/state/iris/secrets/IRIS_ADM_PASSWORD")" "644" "IRIS mode kept"
}

test_blank_is_in_place_and_keeps_comments() {
    _setup "$(cat <<'Y'
  elk:
    enabled: true
    password: 'Abc123Def456Ghi'   # ES >= 6 gitleaks:allow
  velociraptor:
    api_password: "q\"uoted1A"
    password: plain1Value22 # trailing
  portainer:
    password: 'it''s1Valuexx'
Y
)"
    local ino; ino="$(stat -c %i "$CONFIG_FILE")"
    blank_config_passwords
    assert_eq "$(stat -c %i "$CONFIG_FILE")" "$ino" "same inode (backend bind mount)"
    local c; c="$(cat "$CONFIG_FILE")"
    assert_contains "$c" "    password: ''   # ES >= 6 gitleaks:allow" "comment kept"
    assert_contains "$c" "    password: '' # trailing" "unquoted value blanked, comment kept"
    assert_contains "$c" "    api_password: ''" "api_password blanked"
    assert_contains "$c" "# top comment" "other comments kept"
    assert_eq "$(grep -c "password: ''" "$CONFIG_FILE")" "4" "every password line empty"
    assert_eq "$(read_config "['versions']['elk']")" "9.5.6" "rest of the file intact"
    assert_eq "$(_config_password_raw portainer password)" "" "reads back empty"
}

test_exit_trap_blanks_and_chains_the_previous_trap() {
    _setup "$(_all_blank | sed "/^  elk:/,/password/ s/password: ''/password: 'Abc123Def456Ghi'/")"  # gitleaks:allow (fixture)
    local out
    out="$(bash -c '
        LOG_FILE=/dev/null; source ../lib/common.sh; source ../lib/config.sh
        SCRIPT_DIR="$1"; CONFIG_FILE="$1/config.yaml"
        trap "echo previous-trap-ran" EXIT
        _cred_arm_exit_blank
        exit 3' _ "$WORK")"
    assert_eq "$out" "previous-trap-ran" "earlier EXIT trap still runs"
    assert_not_contains "$(cat "$CONFIG_FILE")" "Abc123Def456Ghi" "blanked on exit"
}

test_update_env_var_refuses_empty_passwords_and_none() {
    _setup
    local f="$WORK/modules/elk/.env"
    printf 'ELASTIC_PASSWORD=keep\n' > "$f"
    assert_false update_env_var "$f" ELASTIC_PASSWORD ""
    assert_false update_env_var "$f" VELOX_PASSWORD_2 ""
    assert_false update_env_var "$f" ELASTIC_VERSION "None"
    assert_eq "$(cat "$f")" "ELASTIC_PASSWORD=keep" "file unchanged"
    assert_true update_env_var "$f" ELASTIC_USER ""   # empty non-password is allowed
}

test_update_env_files_writes_no_password() {
    _setup "$(_all_blank)"
    local m
    for m in velociraptor timesketch elk backend nginx; do mkdir -p "$WORK/modules/$m"; : > "$WORK/modules/$m/.env"; done
    : > "$WORK/modules/velociraptor/.env"
    _stamp_host_codex_paths() { :; }
    ensure_module_credentials >/dev/null 2>&1
    update_env_files >/dev/null 2>&1
    local all; all="$(cat "$WORK"/modules/*/.env)"
    assert_not_contains "$all" "PASSWORD" "no password key in any .env"
    assert_not_contains "$all" "TIMESKETCH_PASS" "no backend Timesketch password"
    assert_not_contains "$all" "None" "no None"
    assert_contains "$all" "VELOX_USER_2=api" "api user name still written"
}

test_read_config_null_is_empty() {
    _setup
    printf 'a:\nb: ~\nc: x\n' > "$CONFIG_FILE"
    assert_eq "$(read_config "['a']")" "" "empty value"
    assert_eq "$(read_config "['b']")" "" "~"
    assert_eq "$(read_config "['c']")" "x" "a value"
}

test_credential_lines_exclude_machine_users() {
    _setup "$(_all_blank)"
    ensure_module_credentials >/dev/null 2>&1
    local out; out="$(credential_lines)"
    assert_eq "$(wc -l <<< "$out")" "6" "one line per module"
    assert_not_contains "$out" "$(secret_get velociraptor VELOX_PASSWORD_2)" "no Velociraptor api password"
    assert_not_contains "$out" "$(secret_get elk KIBANA_PASSWORD)" "no kibana_system password"
    assert_not_contains "$out" "|api|" "no api user"
    assert_contains "$out" "IRIS|administrator|$(cred_get iris)" "label|user|password"
    assert_not_contains "$(credential_lines --enabled)" "VolWeb" "disabled module left out of the install display"
    assert_contains "$(credential_lines --ids)" "elk|elastic|" "ids for show-credentials"
}

test_show_credentials_refuses_non_root() {
    [[ $EUID -eq 0 ]] && { echo "  (skipped: running as root)"; return 0; }
    assert_false bash ../scripts/show-credentials.sh
    assert_contains "$(bash ../scripts/show-credentials.sh 2>&1)" "sudo" "says how to run it"
}

# show-credentials needs root; unshare -r gives a uid-0 namespace without sudo.
test_show_credentials_prints_token_and_unknown() {
    unshare -r true 2>/dev/null || { echo "  (skipped: no user namespaces)"; return 0; }
    _setup "$(_all_blank)"
    mkdir -p "$WORK/lib" "$WORK/scripts"
    cp ../lib/common.sh ../lib/config.sh ../lib/secrets.sh "$WORK/lib/"
    cp ../scripts/show-credentials.sh "$WORK/scripts/"
    ensure_module_credentials >/dev/null 2>&1
    local out; out="$(unshare -r bash "$WORK/scripts/show-credentials.sh" 2>&1)"
    assert_contains "$out" "elk | elastic | $(cred_get elk)" "module line"
    assert_not_contains "$out" "Dashboard setup token" "no token line without a token file"
    mkdir -p "$WORK/data/state/backend"
    printf 'TokEn_123-abc\n' > "$WORK/data/state/backend/setup_token"
    : > "$WORK/modules/portainer/secrets/admin_password.placeholder"
    out="$(unshare -r bash "$WORK/scripts/show-credentials.sh" 2>&1)"
    assert_contains "$out" "Dashboard setup token | - | TokEn_123-abc" "token line"
    assert_contains "$out" "portainer | admin | unknown | " "unknown with a 4th-column hint"
    assert_not_contains "$out" "$(secret_get velociraptor VELOX_PASSWORD_2)" "no api password"
    assert_not_contains "$out" "$(secret_get elk KIBANA_PASSWORD)" "no kibana_system password"
}

# install.sh wiring: restore before resolving; rotate once the tools are up,
# before the one-time display (which then shows the rotated values).
test_install_restores_before_and_rotates_after() {
    local f=../install.sh r e v rot show
    r="$(grep -n '^    state_restore_missing "\$SCRIPT_DIR"' "$f" | cut -d: -f1)"
    e="$(grep -n '^    ensure_module_credentials || exit 1' "$f" | cut -d: -f1)"
    v="$(grep -n '^    verify_installation$' "$f" | cut -d: -f1)"
    rot="$(grep -n '^    _rotate_known_defaults$' "$f" | cut -d: -f1)"
    show="$(grep -n '^    _show_credentials_once$' "$f" | cut -d: -f1)"
    [[ -n "$r" && -n "$e" && "$r" -lt "$e" ]] || _fail "state_restore_missing must run before ensure_module_credentials"
    [[ -n "$rot" && "$rot" -gt "$v" && "$rot" -lt "$show" ]] || _fail "rotation must sit between verify_installation and the display"
    _setup "$(_all_blank)"
    eval "$(sed -n '/^_rotate_known_defaults() {/,/^}/p' "$f")"
    local calls="$WORK/calls"
    creds_rotate_known_defaults() { echo called >> "$calls"; }
    _rotate_known_defaults
    assert_eq "$(cat "$calls" 2>/dev/null)" "called" "rotates when the lab switch is off"
    echo "allow_weak_passwords: true" >> "$CONFIG_FILE"
    _rotate_known_defaults
    # creds_rotate_known_defaults rotates nothing on a lab box itself, but its
    # marker refresh is what clears a stale "default password in use" warning.
    assert_eq "$(wc -l < "$calls")" "2" "lab switch on: still called (it skips the rotations itself)"
    unset -f creds_rotate_known_defaults
    sed -i '/^allow_weak_passwords/d' "$CONFIG_FILE"
    assert_true _rotate_known_defaults                    # no credentials_apply.sh: skipped quietly
}

# Once show-credentials has printed them, the "rotated" banner list is spent.
test_show_credentials_clears_the_rotated_list() {
    unshare -r true 2>/dev/null || { echo "  (skipped: no user namespaces)"; return 0; }
    _setup "$(_all_blank)"
    mkdir -p "$WORK/lib" "$WORK/scripts" "$WORK/data/state"
    cp ../lib/common.sh ../lib/config.sh ../lib/secrets.sh "$WORK/lib/"
    cp ../scripts/show-credentials.sh "$WORK/scripts/"
    ensure_module_credentials >/dev/null 2>&1
    local m="$WORK/data/state/default-passwords.json" ino
    printf '{"modules": ["elk"], "rotated": ["iris", "portainer"], "since": "2026-11-15T10:00:00Z"}\n' > "$m"
    chmod 600 "$m"; ino="$(stat -c %i "$m")"
    unshare -r bash "$WORK/scripts/show-credentials.sh" >/dev/null 2>&1
    assert_eq "$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d["modules"], d["rotated"], d["since"])' "$m")" \
        "['elk'] [] 2026-11-15T10:00:00Z" "rotated cleared, modules and since kept"
    assert_eq "$(stat -c %a "$m")" "600" "still 0600"
    assert_eq "$(stat -c %i "$m")" "$ino" "rewritten in place"
    printf '{"modules": [], "rotated": ["iris"], "since": "x"}\n' > "$m"
    unshare -r bash "$WORK/scripts/show-credentials.sh" >/dev/null 2>&1
    assert_false test -e "$m"
}

test_es_curl_keeps_the_password_out_of_argv() {
    _setup "$(_all_blank)"
    secret_set elk ELASTIC_PASSWORD 'Abc123Def456Ghi'
    curl() { echo "ARGV:$*"; echo "STDIN:$(cat)"; }
    local out; out="$(es_curl -sf http://localhost:9200)"
    unset -f curl
    assert_contains "$out" 'STDIN:user = "elastic:Abc123Def456Ghi"' "credentials on stdin"
    assert_not_contains "$(grep ARGV <<< "$out")" "Abc123" "not in argv"
}

run_all_tests
