#!/bin/bash
# Intact.AI upgrade — module passwords on boxes that predate the private stores.
#
# Up to this release every module password sat in git-tracked files: config.yaml
# and modules/<m>/.env (plus copies in backend/.env and velociraptor/.env), most
# of them on the public value 123123. The containers now read them from
# modules/<m>/secrets/ (lib/secrets.sh) and the tracked files carry blanks, so an
# old box has to be carried across without any tool noticing:
#
#   1. MIGRATE  copy each live value, UNCHANGED, into its store. Before anything
#               recreates a container that reads the store, or the container
#               starts with an empty password. Copying is harmless to undo
#               (the old place still has the same value), so it runs early.
#   2. ROTATE   values only HUMANS log in with, while still public: the
#               Velociraptor GUI user and `api`, the Portainer admin, the IRIS
#               administrator, Timesketch's SECRET_KEY. Only against a running
#               tool, store and tool changed together or not at all.
#   3. BLANK    the old copies, once the compose that runs the tool reads the
#               store (a blank in a .env an OLD compose still interpolates is a
#               container with no password).
#   4. MARK     machine-used values still public (ES `elastic`, the Timesketch
#               user, the VolWeb admin) are kept -- the backend logs in with
#               them and their hash is in the tool's own data -- and listed in
#               data/state/default-passwords.json for a Settings warning; the
#               admin changes them with scripts/apply-passwords.sh.
#
# Rotating, and the marker, are lib/credentials_apply.sh (shared with install.sh
# and scripts/apply-passwords.sh): tool, store and every reader change together
# or not at all.
#
# Per-module code only: called from the module files (and from the intact
# module, which runs first on every upgrade and so is where a module that does
# not move this run is carried across). core.sh / plan.sh / upgrade.sh are
# deliberately untouched. Helpers reused from lib/config.sh: cred_get,
# _cred_put, _cred_user, _cred_label, _config_password_raw,
# blank_config_passwords. Values never reach the log, stdout or a command line
# on the host, except `velociraptor user add`, which has no other input.

# upgrade.sh's source list predates lib/secrets.sh and is the general flow, so
# the module code loads it itself.
declare -F secret_get >/dev/null 2>&1 \
    || source "$(dirname "${BASH_SOURCE[0]}")/../../secrets.sh"
declare -F creds_apply >/dev/null 2>&1 \
    || source "$(dirname "${BASH_SOURCE[0]}")/../../credentials_apply.sh"

_U_CREDS_MODULES=(elk timesketch velociraptor iris volweb portainer)
U_CREDS_SHOW=()

# Store keys per module; FILE = the module's one-value file (cred_get/_cred_put).
_u_creds_keys() {
    case "$1" in
        elk)          echo ELASTIC_PASSWORD KIBANA_PASSWORD ;;
        timesketch)   echo TIMESKETCH_PASSWORD ;;
        velociraptor) echo VELOX_PASSWORD VELOX_PASSWORD_2 ;;
        iris|volweb|portainer) echo FILE ;;
    esac
}

# Where old releases kept each value, best first: "<dir>/.env VAR" or "cfg <key>".
_u_creds_sources() {
    case "$1:$2" in
        elk:ELASTIC_PASSWORD)  printf '%s\n' "elk ELASTIC_PASSWORD" "backend ELASTICSEARCH_PASSWORD" \
                                             "velociraptor ELASTIC_PASSWORD" "cfg password" ;;
        elk:KIBANA_PASSWORD)   printf '%s\n' "elk KIBANA_PASSWORD" ;;
        timesketch:*)          printf '%s\n' "timesketch TIMESKETCH_PASSWORD" "backend TIMESKETCH_PASS" "cfg password" ;;
        velociraptor:VELOX_PASSWORD)   printf '%s\n' "velociraptor VELOX_PASSWORD" "cfg password" ;;
        velociraptor:VELOX_PASSWORD_2) printf '%s\n' "velociraptor VELOX_PASSWORD_2" "cfg api_password" ;;
        *:FILE)                printf '%s\n' "cfg password" ;;
    esac
}

# What says the tool already has data (and so a password we must not replace).
_u_creds_tool_specs() {
    case "$1" in
        elk)          echo vol:elk_elasticsearch_data ;;
        timesketch)   echo vol:timesketch_timesketch_postgres_data ;;
        velociraptor) echo "path:${SCRIPT_DIR}/data/velociraptor/server.config.yaml vol:velociraptor_velociraptor_datastore" ;;
        iris)         echo vol:iris_iris_db_data ;;
        volweb)       echo vol:volweb_volweb_postgres_data ;;
        portainer)    echo vol:portainer_portainer_data ;;
    esac
}
_u_creds_tool_new() { local s; s="$(_u_creds_tool_specs "$1")"; [[ -n "$s" ]] && secret_tool_is_new $s; }

_u_creds_get() { if [[ "$2" == FILE ]]; then cred_get "$1"; else secret_get "$1" "$2"; fi; }
_u_creds_put() { if [[ "$2" == FILE ]]; then _cred_put "$1" "$3"; else secret_set "$1" "$2" "$3"; fi; }
_u_creds_env() { sed -n "s/^${2}=//p" "${SCRIPT_DIR}/modules/${1}/.env" 2>/dev/null | tail -1; }

# The value a pre-store box runs with, or nothing.
_u_creds_old() {
    local m="$1" k="$2" dir var v
    while read -r dir var; do
        if [[ "$dir" == cfg ]]; then v="$(_config_password_raw "$m" "$var")"
        else v="$(_u_creds_env "$dir" "$var")"; fi
        [[ -n "$v" ]] && { printf '%s' "$v"; return 0; }
    done < <(_u_creds_sources "$m" "$k")
    # WHY KIBANA FALLS BACK TO THE ELASTIC VALUE: kibana_system's password is
    # whatever the elk setup container last set, and every old release wrote
    # KIBANA_PASSWORD = the elastic password (update_env_files, and
    # ensure_elk_credentials on every upgrade). A public one is replaced in
    # _u_creds_migrate below.
    [[ "$m:$k" == elk:KIBANA_PASSWORD ]] && _u_creds_old elk ELASTIC_PASSWORD
}

# _u_creds_migrate <module> -- every store key ends up set. Idempotent.
#   stored                      -> kept
#   tool has data, old value    -> copied UNCHANGED (even 123123: it is what the
#                                  tool's data accepts; rotation/marker below)
#   tool has data, no value     -> warn, leave unset: never mint one it rejects
#   tool new (UI install later) -> the old value if it passes secret_check (the
#                                  operator typed it), else generated
# Runs BEFORE the module's backup_file_for_rollback, so no undo can drop a value
# the tool has already started with.
_u_creds_migrate() {
    local m="$1" k v new
    for k in $(_u_creds_keys "$m"); do
        _u_creds_get "$m" "$k" >/dev/null 2>&1 && continue
        v="$(_u_creds_old "$m" "$k")"
        if _u_creds_tool_new "$m"; then
            if [[ -z "$v" ]] || ! secret_check "$v" existing >/dev/null; then v="$(secret_generate)"; new=generated; else new=stored; fi
        elif [[ "$m:$k" == elk:KIBANA_PASSWORD && -n "$v" ]] && secret_is_known_default "$v" && ! secret_weak_allowed; then
            # Nobody types kibana_system's password, so a public one is simply
            # replaced: the elk setup container sets it from KIBANA_PASSWORD on
            # every `compose up` (POST _security/user/kibana_system/_password as
            # elastic, which works on an existing cluster -- proven on 9.5.6), and
            # Kibana depends_on setup: service_completed_successfully, so it never
            # starts before that. Until the next `compose up` the running Kibana
            # and the cluster both keep the old one, which still agree.
            v="$(secret_generate)"; new="generated (the old kibana_system value was public)"
        elif [[ -n "$v" ]]; then
            new="moved unchanged"
        elif [[ "$k" == VELOX_PASSWORD_2 ]]; then
            # The entrypoint re-applies `api`'s password on every start, so a
            # fresh one cannot lock anything out.
            v="$(secret_generate)"; new=generated
        else
            log_warn "  ${m}: $(_cred_label "$m") already has data, but its password (${k}) is stored nowhere on"
            log_warn "    this box. Not minting one the data would refuse; restore $(secret_dir "$m") by hand"
            log_warn "    from the per-box copy under ${SCRIPT_DIR}/data/state/${m}/secrets/ (or a backup of it)$(_u_creds_inspect_hint "$m")."
            continue
        fi
        _u_creds_put "$m" "$k" "$v" || { log_error "  ${m}: could not store ${k}"; return 1; }
        log_info "  ${m}: ${k/FILE/password} ${new} into its private store"
    done
    [[ "$m" == iris ]] && _u_creds_iris_adopt_config
    return 0
}

# IRIS is the one tool whose LIVE password followed config.yaml rather than its
# file: enforce_iris_admin_password re-asserted config.yaml after every install
# and upgrade. So when the two differ, ask IRIS which one it takes.
_u_creds_iris_adopt_config() {
    local cfg file
    cfg="$(_config_password_raw iris password)"
    file="$(cred_get iris 2>/dev/null)"
    [[ -n "$cfg" && "$cfg" != "$file" ]] || return 0
    if _creds_iris_matches "$cfg"; then
        _cred_put iris "$cfg" && log_info "  iris: the administrator runs with config.yaml's password; stored it"
    fi
    return 0
}

# A container created before the value was lost still has it in its env.
_u_creds_inspect_hint() {
    case "$1" in
        elk)          echo ", or from the running cluster's env: sudo docker inspect intact_elasticsearch (ELASTIC_PASSWORD)" ;;
        velociraptor) echo ", or from sudo docker inspect intact_velociraptor (VELOX_PASSWORD)" ;;
        timesketch)   echo ", or from sudo docker inspect intact_timesketch_web (TIMESKETCH_PASSWORD)" ;;
    esac
}

_u_creds_migrate_all() {
    local m
    for m in "${_U_CREDS_MODULES[@]}"; do _u_creds_migrate "$m" || return 1; done
}

# _u_creds_reads_store <consumer dir> <module> -- does that compose read <module>'s store?
_u_creds_reads_store() {
    local c="${SCRIPT_DIR}/modules/$1/docker-compose.yaml"
    if [[ "$1" == "$2" ]]; then
        grep -qE '(^|[^./[:alnum:]_])(\./)?secrets/creds\.env' "$c" 2>/dev/null
    else
        grep -qF "../$2/secrets/creds.env" "$c" 2>/dev/null
    fi
}

# Empty the old .env copies of <module>'s values -- only where the compose now
# reads the store, and only once the store has the value.
_u_creds_blank_env() {
    local m="$1" k dir var f
    for k in $(_u_creds_keys "$m"); do
        [[ "$k" == FILE ]] && continue
        secret_get "$m" "$k" >/dev/null 2>&1 || continue
        while read -r dir var; do
            [[ "$dir" == cfg ]] && continue
            f="${SCRIPT_DIR}/modules/${dir}/.env"
            grep -q "^${var}=." "$f" 2>/dev/null || continue
            _u_creds_reads_store "$dir" "$m" || continue
            sed -i "s|^${var}=.*|${var}=|" "$f" && log_info "  ${m}: cleared ${var} from modules/${dir}/.env"
        done < <(_u_creds_sources "$m" "$k")
    done
    return 0
}

# config.yaml in one go (blank_config_passwords clears every module), so only
# once every module's value is stored: a value cleared before it is stored is
# gone. Migrating all six first (copy-only, idempotent) is what lets a
# `--only <module>` run clear it too -- and an install's create-user step
# (ensure_module_credentials) refuses a config.yaml value that differs from
# the store, so it must be clear before a module is installed.
_u_creds_blank_config() {
    local m k
    # Not while the box still runs an older release's lib/ (a `--only <module>`
    # run that left intact out): its update_env_files would write the blanks
    # into every .env its old composes interpolate.
    grep -q '^blank_config_passwords()' "${SCRIPT_DIR}/lib/config.sh" 2>/dev/null || return 0
    _u_creds_migrate_all >/dev/null 2>&1
    for m in "${_U_CREDS_MODULES[@]}"; do
        for k in $(_u_creds_keys "$m"); do
            _u_creds_get "$m" "$k" >/dev/null 2>&1 || { log_info "  config.yaml passwords kept: ${m} has none stored yet"; return 0; }
        done
        local cfg; cfg="$(_config_password_raw "$m" password)"
        if [[ -n "$cfg" ]] && [[ "$cfg" != "$(cred_get "$m" 2>/dev/null)" ]]; then
            log_warn "  config.yaml modules.${m}.password is not what $(_cred_label "$m") runs with; clearing it."
            log_warn "    The tool keeps its current password: sudo bash scripts/show-credentials.sh"
        fi
    done
    blank_config_passwords
}

# _u_creds_show "label|user|password" -- one block when the run exits, after the
# report, by chaining whatever EXIT trap is set (interrupt.sh's cleanup).
_u_creds_show() {
    U_CREDS_SHOW+=("$1")
    [[ -n "${_U_CREDS_TRAP:-}" ]] && return 0
    _U_CREDS_TRAP=1
    eval "set -- $(trap -p EXIT)"
    # shellcheck disable=SC2064 -- the previous handler is fixed now, on purpose.
    trap "_u_creds_flush; ${3:-}" EXIT
}
_u_creds_flush() {
    local rc=$?
    (( ${#U_CREDS_SHOW[@]} )) && printf '%s\n' "${U_CREDS_SHOW[@]}" | secret_show_once
    U_CREDS_SHOW=()
    return $rc
}

# _u_creds_after <module> -- after a module's u_end succeeded: replace the public
# values nobody types (logins are only warned about), clear the old copies,
# refresh the marker, and show a module installed in this run.
# Never fails: the module is already applied.
_u_creds_after() {
    local m="$1" k u line
    # Rotation honours the lab switch (allow_weak_passwords) itself, and
    # refreshes the marker for every module.
    creds_rotate_known_defaults "$m" || true
    for line in "${CREDS_ROTATED_SHOW[@]}"; do _u_creds_show "$line"; done
    CREDS_ROTATED_SHOW=()
    _u_creds_blank_env "$m"
    _u_creds_blank_config
    if [[ "${PLAN_ACTION[$m]:-}" == install ]]; then
        case "$m" in elk) k=ELASTIC_PASSWORD ;; timesketch) k=TIMESKETCH_PASSWORD ;; velociraptor) k=VELOX_PASSWORD ;; *) k=FILE ;; esac
        u="$(_u_creds_get "$m" "$k" 2>/dev/null)" && _u_creds_show "$(_cred_label "$m")|$(_cred_user "$m")|${u}"
        # ELK added to a box whose Velociraptor already runs: Velociraptor read
        # ../elk/secrets/creds.env at create, when there was none, so its
        # Elastic upload artifact has no password until it is recreated.
        if [[ "$m" == elk ]] && _creds_running intact_velociraptor; then
            if _creds_recreate velociraptor velociraptor; then
                log_info "  velociraptor: recreated so its Elastic upload uses the new ELK password"
            else
                log_warn "  velociraptor: could not be recreated; its Elastic upload has no ELK password until it is"
            fi
        fi
    fi
    return 0
}

# The intact module's turn, after it committed: every module that stays on
# this box this run (moving or not). Excluded by --skip and being-installed
# ones are left to their own run. Excluded by --only is NOT left: the dashboard
# passes --only = whatever its plan saw moving, so a module whose version stays
# put never gets "its own run" -- after a 20261021 -> 20261116 upgrade
# (2026-11-16) IRIS's admin and the Velociraptor GUI still took 123123, with
# the value still in their .env, and nothing said so.
_u_creds_after_all() {
    local m
    for m in "${_U_CREDS_MODULES[@]}"; do
        case "${PLAN_ACTION[$m]:-}" in
            upgrade|noop:*) _u_creds_after "$m" ;;
            # Installed ones only: plan_build applies this label before it
            # looks at whether the module is on the box at all.
            "skip:excluded by --only") [[ -n "${PLAN_CURRENT[$m]:-}" ]] && _u_creds_after "$m" ;;
            # Not in the package, but the sidecar refresh just gave it a compose
            # that reads the store, so its .env copy is only a plaintext leftover
            # (2026-11-16 dev box: elk + timesketch kept their values in .env).
            "skip:not in this package") _u_creds_blank_env "$m" ;;
        esac
    done
    _u_creds_setup_token
    return 0
}

# An upgraded box nobody has claimed yet (first_login: true) and no setup token:
# the dashboard's setup now needs one (lib/setup_token.sh), and on a box
# installed before it existed none was ever made -- the dashboard could never
# be set up. Made here and shown with the other credentials.
_u_creds_setup_token() {
    is_enabled "$(read_config "['first_login']" 2>/dev/null)" || return 0
    declare -F new_setup_token >/dev/null || source "${SCRIPT_DIR}/lib/setup_token.sh" 2>/dev/null || return 0
    [[ -s "$(setup_token_file)" ]] && return 0
    local tok
    tok="$(new_setup_token)" || { log_warn "  could not create the dashboard setup token: sudo scripts/reset-login.sh"; return 0; }
    log_info "  dashboard setup: open https://$(read_config "['domain']")/setup.html and enter the setup token"
    _u_creds_show "Dashboard setup token|-|${tok}"
}
