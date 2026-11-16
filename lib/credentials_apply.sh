#!/bin/bash
# Intact.AI — change a module password on a RUNNING box, or put it all back.
#
#   creds_apply <module> <new_value>    0 changed / 1 reverted (reason in CREDS_APPLY_REASON)
#   creds_rotate_known_defaults [module...]
#                                       human-only logins still on a public value
#                                       get a generated one (upgrade, re-install)
#   creds_mark_defaults                 data/state/default-passwords.json
#
# WHY ONE PLACE. Every tool keeps its password in its OWN data (Elasticsearch's
# security index, Velociraptor's datastore, IRIS's and Timesketch's postgres,
# Portainer's DB, VolWeb's Django users) and every reader keeps the copy it read
# at container create (compose env_file). Changing only the store locks the
# platform out; changing only the tool leaves every reader on the old value.
# So the order is always: set it INSIDE the tool, store it, recreate every
# reader, verify -- and on ANY failure put the old value back in the tool, the
# store and the readers, so the box is exactly as it was.
#
# Machine-used logins (ES `elastic`, the Timesketch user, the VolWeb admin) are
# only ever changed here on the admin's request (scripts/apply-passwords.sh);
# upgrades and installs rotate the human-only ones (Velociraptor GUI + `api`,
# Portainer, IRIS, Timesketch's SECRET_KEY) and never on a lab box
# (allow_weak_passwords: true, secret_weak_allowed).
#
# Values never reach the log, stdout or a host command line (nor `docker
# events`, whose exec_create logs the whole exec command): curl reads them --
# and Portainer's JWT -- as a config on a file descriptor, docker exec gets them
# on stdin or in its own environment (-e NAME, never NAME=value). Only inside
# the Velociraptor container does a value sit in an argv, for the under-a-second
# life of `velociraptor user add`, which has no other input (see
# modules/velociraptor/entrypoint.sh).
#
# Needs lib/common.sh (log_*), lib/config.sh (cred_get, _cred_put, _cred_user,
# _cred_label, _config_password_raw); enforce_iris_admin_password and
# seed_volweb_admin (lib/modules/{iris,volweb}.sh) for those two modules.

declare -F secret_get >/dev/null 2>&1 || source "$(dirname "${BASH_SOURCE[0]}")/secrets.sh"

CREDS_APPLY_REASON=""
CREDS_APPLY_NOTE=""       # said beside "changed": adopted / finished a cut-off run
CREDS_APPLY_PUT_BACK=1    # 0: a failed change could NOT be put back everywhere
CREDS_ROTATED=()          # modules whose password this process rotated
CREDS_ROTATED_SHOW=()     # "label|user|password" for the operator, shown by the caller

_creds_docker()  { "${DOCKER_BIN:-docker}" "$@"; }
_creds_exists()  { _creds_docker inspect "$1" >/dev/null 2>&1; }
_creds_running() { [[ "$(_creds_docker inspect -f '{{.State.Running}}' "$1" 2>/dev/null)" == true ]]; }
_creds_fail()    { CREDS_APPLY_REASON="$1"; return 1; }
# _creds_step "<reason if it fails>" cmd... -- one step of a change.
_creds_step()    { local r="$1"; shift; "$@" || _creds_fail "$r"; }
# _creds_wait cmd... -- retry for CREDS_WAIT seconds: a recreated tool needs a
# moment before it answers.
# Elasticsearch sets _CREDS_WAIT_DEFAULT=600 (a local, so it reaches the calls
# below): a recreated cluster with big indices takes minutes to answer, and a
# revert that gives up early reports a state it never saw.
_creds_wait() {
    local n=$(( ${CREDS_WAIT:-${_CREDS_WAIT_DEFAULT:-120}} / 3 )) i=0
    until "$@"; do (( i++ >= n )) && return 1; sleep 3; done
}
# A login name goes into SQL and URLs below: config.yaml `id`, so restrict it.
_creds_user() {
    local u; u="$(_cred_user "$1")"
    [[ "$u" =~ ^[A-Za-z0-9._@-]+$ ]] || return 1
    printf '%s' "$u"
}
# curl's `user = "u:p"` with the quoting curl's config parser needs: an old
# box's value may hold " \ or spaces.
_creds_curlrc() { local v="${1}:${2}"; v="${v//\\/\\\\}"; v="${v//\"/\\\"}"; printf 'user = "%s"\n' "$v"; }
_creds_json() { python3 -c 'import json,os,sys; print(json.dumps({k: os.environ["_J_" + k] for k in sys.argv[1:]}))' "$@"; }

# _creds_recreate <module dir> [service...] -- a plain `docker restart` keeps
# the environment the container was created with, so a reader would keep the
# OLD password (and Velociraptor's entrypoint re-applies the old `api` one).
# Only for a stack that is deployed on this box.
_creds_recreate() {
    local d="${SCRIPT_DIR}/modules/$1"; shift
    [[ -f "${d}/docker-compose.yaml" ]] || return 0
    # -k: scripts/apply-passwords.sh ignores HUP/INT/TERM while it applies, and
    # an ignored signal is inherited -- timeout's TERM alone might not stop a
    # hung compose. KILL cannot be ignored.
    ( cd "$d" && timeout -k 30 900 "${DOCKER_BIN:-docker}" compose up -d --force-recreate --no-build --pull never "$@" ) \
        >>"${LOG_FILE:-/dev/null}" 2>&1
}

# Every container that read <module>'s store at create, recreated; the list of
# containers is left in _CREDS_READERS for _creds_readers_up.
_creds_readers() {
    local rc=0
    _CREDS_READERS=()
    case "$1" in
        elk)
            # The whole elk stack: Elasticsearch's own healthcheck logs in with
            # $ELASTIC_PASSWORD from its env, Logstash ships with it, and the
            # setup container (kibana_system) has to log in to finish -- Kibana
            # waits for it. kibana_system's own password is not changed here.
            if _creds_exists intact_elasticsearch; then
                _creds_recreate elk || rc=1
                _CREDS_READERS+=(intact_elasticsearch intact_logstash intact_kibana)
            fi
            if _creds_exists intact_backend; then _creds_recreate backend backend || rc=1; _CREDS_READERS+=(intact_backend); fi
            # The Elastic upload artifact (ELASTIC_PASSWORD via ../elk/secrets/creds.env).
            if _creds_exists intact_velociraptor; then _creds_recreate velociraptor velociraptor || rc=1; _CREDS_READERS+=(intact_velociraptor); fi ;;
        timesketch)
            if _creds_exists intact_backend; then _creds_recreate backend backend || rc=1; _CREDS_READERS+=(intact_backend); fi ;;
        velociraptor)
            _creds_recreate velociraptor velociraptor || rc=1; _CREDS_READERS+=(intact_velociraptor) ;;
    esac
    return $rc
}
_creds_readers_up() {
    local c
    for c in "${_CREDS_READERS[@]}"; do _creds_wait _creds_running "$c" || return 1; done
}

# _creds_resume <module> <stored> <new> -- a run cut off (power loss, kill -9)
# after the tool took <new> but before the store or the readers did leaves a
# box where the stored value no longer logs in and <new> does. Every module
# would then refuse ("does not accept the stored password") forever, so the
# re-run finishes that run instead: store, readers, verify.
# 0 finished, 1 failed, 2 not such a run (go on with a normal change).
_creds_resume() {
    local m="$1" old="$2" new="$3"
    [[ "$old" != "$new" ]] || return 2
    "_creds_auth_${m}" "$old" && return 2
    "_creds_auth_${m}" "$new" || return 2
    CREDS_APPLY_NOTE="finished an earlier run that was cut off"
    _creds_step "could not store the new password" _cred_put "$m" "$new" \
        && _creds_step "could not recreate the readers" _creds_readers "$m" \
        && _creds_step "$(_cred_label "$m") did not come back with the new password" _creds_wait "_creds_auth_${m}" "$new" \
        && _creds_step "a reader did not come back up" _creds_readers_up
}

# ---------------------------------------------------------------------------
# Elasticsearch `elastic`
# ---------------------------------------------------------------------------
_creds_es_auth_as() {  # <user> <password> -> 0 when that user logs in with it
    local code
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 6 -K <(_creds_curlrc "$1" "$2") \
            "http://127.0.0.1:9200/_security/_authenticate" 2>/dev/null)"
    [[ "$code" == 200 ]]
}
_creds_es_auth() { _creds_es_auth_as "$_CREDS_ES_USER" "$1"; }   # elastic (config.yaml id)
_creds_auth_elk() { _creds_es_auth "$1"; }
_creds_es_either() { _creds_es_auth "$1" || _creds_es_auth "$2"; }
_creds_es_set() {    # <current> <new>
    local code
    code="$(_J_password="$2" _creds_json password | curl -s -o /dev/null -w '%{http_code}' --max-time 20 \
            -K <(_creds_curlrc "$_CREDS_ES_USER" "$1") -H 'Content-Type: application/json' -X POST --data-binary @- \
            "http://127.0.0.1:9200/_security/user/${_CREDS_ES_USER}/_password" 2>/dev/null)"
    [[ "$code" == 200 ]]
}
_creds_apply_elk() {
    local new="$1" old kold knew="" r _CREDS_WAIT_DEFAULT=600
    _CREDS_ES_USER="$(_creds_user elk)" || { _creds_fail "the elk id in config.yaml is not a plain user name"; return 1; }
    old="$(secret_get elk ELASTIC_PASSWORD)" || { _creds_fail "no stored elastic password (modules/elk/secrets/creds.env)"; return 1; }
    _creds_running intact_elasticsearch || { _creds_fail "Elasticsearch is not running"; return 1; }
    _creds_resume elk "$old" "$new"; r=$?; (( r < 2 )) && return $r
    _creds_es_auth "$old" || { _creds_fail "Elasticsearch does not accept the stored password"; return 1; }
    # kibana_system on a public value kept elk on the dashboard's warning list
    # for good: nothing else ever changes it. The elk setup container sets it
    # from the store on the recreate below (as elastic, with the new value), so
    # a new one only has to be in the store first.
    kold="$(secret_get elk KIBANA_PASSWORD 2>/dev/null)"
    secret_is_known_default "$kold" && ! secret_weak_allowed && knew="$(secret_generate)"
    # A refusal while the cluster still takes the old value wrote nothing:
    # no readers to recreate. A timeout that did change it goes on below.
    if ! _creds_es_set "$old" "$new" && _creds_es_auth "$old"; then
        _creds_fail "Elasticsearch refused the change"; return 1
    fi
    _creds_step "Elasticsearch does not accept the new password" _creds_es_auth "$new" \
        && _creds_step "could not store the new password" secret_set elk ELASTIC_PASSWORD "$new" \
        && { [[ -z "$knew" ]] || _creds_step "could not store a new kibana_system password" secret_set elk KIBANA_PASSWORD "$knew"; } \
        && _creds_step "could not recreate the readers (elk, backend, velociraptor)" _creds_readers elk \
        && _creds_step "Elasticsearch did not come back with the new password" _creds_wait _creds_es_auth "$new" \
        && { [[ -z "$knew" ]] || _creds_step "kibana_system does not log in with its new password" _creds_wait _creds_es_auth_as kibana_system "$knew"; } \
        && _creds_step "a reader did not come back up" _creds_readers_up \
        && return 0
    local why="$CREDS_APPLY_REASON"
    # Back: ES first (with whichever password it takes once it answers), then
    # the store AS WHAT ES ACCEPTS -- a store that disagrees with the cluster is
    # the lockout this whole file exists to prevent.
    _creds_wait _creds_es_either "$old" "$new"
    _creds_es_auth "$old" || { _creds_es_auth "$new" && _creds_es_set "$new" "$old"; }
    [[ -n "$knew" ]] && secret_set elk KIBANA_PASSWORD "$kold"
    if _creds_es_auth "$old"; then
        secret_set elk ELASTIC_PASSWORD "$old"
    elif _creds_es_auth "$new"; then
        secret_set elk ELASTIC_PASSWORD "$new"
        why+=" -- the old password could not be put back in Elasticsearch: the NEW one stays (stored)"
        CREDS_APPLY_PUT_BACK=0
    else
        why+=" -- state not confirmed: check Elasticsearch, then re-run"
        CREDS_APPLY_PUT_BACK=0
    fi
    _creds_readers elk; _creds_readers_up
    CREDS_APPLY_REASON="$why"
    return 1
}

# ---------------------------------------------------------------------------
# Timesketch user
# ---------------------------------------------------------------------------
_creds_ts_set() {    # tsctl's own prompt, typed twice, on stdin: never --password (argv)
    printf '%s\n%s\n' "$1" "$1" | _creds_docker exec -i intact_timesketch_web tsctl create-user "$_CREDS_TS_USER" >/dev/null 2>&1
}
_creds_ts_matches() {   # asked of Timesketch's own flask_bcrypt; values in the exec's env
    local hash
    hash="$(_creds_docker exec intact_timesketch_postgres psql -U timesketch -d timesketch -tAc \
            "SELECT password FROM \"user\" WHERE username='${_CREDS_TS_USER}'" 2>/dev/null | head -1)"
    [[ "$hash" == \$2* ]] || return 1
    _TS_PW="$1" _TS_H="$hash" _creds_docker exec -e _TS_PW -e _TS_H intact_timesketch_web python3 -c \
        'import os,sys;from flask_bcrypt import check_password_hash;sys.exit(0 if check_password_hash(os.environ["_TS_H"],os.environ["_TS_PW"]) else 1)' \
        >/dev/null 2>&1
}
_creds_auth_timesketch() { _creds_ts_matches "$1"; }
_creds_apply_timesketch() {
    local new="$1" old
    _CREDS_TS_USER="$(_creds_user timesketch)" || { _creds_fail "the timesketch id in config.yaml is not a plain user name"; return 1; }
    old="$(secret_get timesketch TIMESKETCH_PASSWORD)" || { _creds_fail "no stored Timesketch password"; return 1; }
    { _creds_running intact_timesketch_web && _creds_running intact_timesketch_postgres; } \
        || { _creds_fail "Timesketch is not running"; return 1; }
    local r; _creds_resume timesketch "$old" "$new"; r=$?; (( r < 2 )) && return $r
    _creds_step "tsctl create-user failed" _creds_ts_set "$new" \
        && _creds_step "Timesketch does not accept the new password" _creds_ts_matches "$new" \
        && _creds_step "could not store the new password" secret_set timesketch TIMESKETCH_PASSWORD "$new" \
        && _creds_step "could not recreate the backend" _creds_readers timesketch \
        && _creds_step "the backend did not come back up" _creds_readers_up \
        && return 0
    local why="$CREDS_APPLY_REASON"
    _creds_ts_set "$old"
    secret_set timesketch TIMESKETCH_PASSWORD "$old"
    _creds_ts_matches "$old" || log_error "  timesketch: could not verify that the old password is back"
    _creds_readers timesketch; _creds_readers_up
    CREDS_APPLY_REASON="$why"
    return 1
}

# ---------------------------------------------------------------------------
# Velociraptor (GUI user, and `api`)
# ---------------------------------------------------------------------------
# The value goes in through the exec's environment (-e _P names it): on the
# host argv, and in `docker events` (exec_create logs the full command), there
# is only "$_P". Output dropped: it is the password's neighbourhood.
_creds_velo_user_add() {  # <user> <password> <roles>
    _P="$2" _creds_docker exec -e _P intact_velociraptor sh -c \
        'exec /velociraptor/velociraptor --config /velociraptor/server.config.yaml user add "$1" "$_P" --role "$2"' \
        _ "$1" "$3" >/dev/null 2>&1
}
# The entrypoint (re)applies a stored password whenever it differs from the
# sha256 stamp of the last one it applied. A `user add` from here goes behind
# its back, so the stamps are dropped first: then ANY later start -- also one
# after a revert that found the container down -- applies what the store holds.
# Only the stamps of the keys being changed: dropping the GUI one while only
# `api` rotates would let the recreate reset a GUI password set in the UI.
_creds_velo_unstamp() {   # KEY...
    local k
    for k in "$@"; do
        case "$k" in VELOX_PASSWORD) rm -f "${SCRIPT_DIR}/data/velociraptor/.gui_pw.sha256" ;;
                     VELOX_PASSWORD_2) rm -f "${SCRIPT_DIR}/data/velociraptor/.api_pw.sha256" ;; esac
    done
}
# Basic auth on the GUI port (127.0.0.1 only). 200 = logged in, 401 = refused;
# base_path is /velociraptor on every config entrypoint.sh generates, / tried
# as well for a hand-made one.
_creds_velo_login() {     # <user> <password>
    local p code base="${INTACT_VELO_GUI:-http://127.0.0.1:8889}"
    for p in /velociraptor/app/index.html /app/index.html; do
        code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 -K <(_creds_curlrc "$1" "$2") "${base}${p}" 2>/dev/null)"
        [[ "$code" == 200 ]] && return 0
    done
    return 1
}
_creds_velo_env() { sed -n "s/^${1}=//p" "${SCRIPT_DIR}/modules/velociraptor/.env" 2>/dev/null | tail -1; }
_creds_velo_row() {       # GUI|api -> "KEY|user|roles"
    if [[ "$1" == GUI ]]; then
        local u; u="$(_creds_velo_env VELOX_USER)"; u="${u:-$(_cred_user velociraptor)}"
        local r; r="$(_creds_velo_env VELOX_ROLE)"
        printf 'VELOX_PASSWORD|%s|%s' "$u" "${r:-administrator}"
    else
        local a; a="$(_creds_velo_env VELOX_USER_2)"
        printf 'VELOX_PASSWORD_2|%s|api,administrator' "${a:-api}"
    fi
}
_creds_auth_velociraptor() {   # the GUI user logs in with <password>
    local u; IFS='|' read -r _ u _ <<<"$(_creds_velo_row GUI)"
    _creds_velo_login "$u" "$1"
}
_creds_velo_all_login() {  # every row's user logs in with the value named by $1 (new|old)
    local i
    for i in "${!_V_KEY[@]}"; do
        if [[ "$1" == new ]]; then _creds_velo_login "${_V_USER[$i]}" "${_V_NEW[$i]}" || return 1
        else _creds_velo_login "${_V_USER[$i]}" "${_V_OLD[$i]}" || return 1; fi
    done
}
# _creds_velo_apply "KEY|user|roles|new"... -- all rows or none.
#
# `user add` on a RUNNING server writes the datastore but the server keeps the
# users it loaded: the new password is refused (and the old one still works)
# until the process restarts -- proven on 0.77.3. So: store first (the
# recreated container's entrypoint re-applies VELOX_PASSWORD_2 to `api` from
# its env_file, which must already be the new one), user add, recreate, then
# log in over the GUI port. `api` is never deleted: it is the backend's API
# certificate identity. On a revert the store is put back first, and the
# entrypoint makes it the datastore's at the recreate even when the container
# is down and the `user add` of the old value cannot run.
_creds_velo_apply() {
    local row k u r v i
    _V_KEY=(); _V_USER=(); _V_ROLE=(); _V_NEW=(); _V_OLD=()
    for row in "$@"; do
        IFS='|' read -r k u r v <<<"$row"
        _V_KEY+=("$k"); _V_USER+=("$u"); _V_ROLE+=("$r"); _V_NEW+=("$v")
        _V_OLD+=("$(secret_get velociraptor "$k" 2>/dev/null)")
        [[ -n "${_V_OLD[-1]}" ]] || { _creds_fail "no stored ${k} (modules/velociraptor/secrets/creds.env)"; return 1; }
    done
    _creds_running intact_velociraptor || { _creds_fail "Velociraptor is not running"; return 1; }
    local ok=1
    _creds_velo_unstamp "${_V_KEY[@]}"
    for i in "${!_V_KEY[@]}"; do
        _creds_step "could not store the new password" secret_set velociraptor "${_V_KEY[$i]}" "${_V_NEW[$i]}" || { ok=0; break; }
    done
    if (( ok )); then
        for i in "${!_V_KEY[@]}"; do
            _creds_step "velociraptor user add ${_V_USER[$i]} failed" \
                _creds_velo_user_add "${_V_USER[$i]}" "${_V_NEW[$i]}" "${_V_ROLE[$i]}" || { ok=0; break; }
        done
    fi
    (( ok )) && _creds_step "could not recreate Velociraptor" _creds_readers velociraptor \
        && _creds_step "Velociraptor does not accept the new password after the recreate" _creds_wait _creds_velo_all_login new \
        && return 0
    local why="$CREDS_APPLY_REASON"
    _creds_velo_unstamp "${_V_KEY[@]}"
    for i in "${!_V_KEY[@]}"; do
        secret_set velociraptor "${_V_KEY[$i]}" "${_V_OLD[$i]}"
        _creds_running intact_velociraptor && _creds_velo_user_add "${_V_USER[$i]}" "${_V_OLD[$i]}" "${_V_ROLE[$i]}"
    done
    _creds_readers velociraptor
    if ! _creds_wait _creds_velo_all_login old; then
        why+=" -- the old password is stored but Velociraptor was not seen taking it: its next start applies it; check that it runs"
        CREDS_APPLY_PUT_BACK=0
    fi
    CREDS_APPLY_REASON="$why"
    return 1
}
_creds_apply_velociraptor() {
    local old r; old="$(secret_get velociraptor VELOX_PASSWORD 2>/dev/null)"
    if [[ -n "$old" ]] && _creds_running intact_velociraptor; then
        _creds_resume velociraptor "$old" "$1"; r=$?; (( r < 2 )) && return $r
    fi
    _creds_velo_apply "$(_creds_velo_row GUI)|$1"
}

# ---------------------------------------------------------------------------
# Portainer admin: POST /api/auth -> jwt; PUT /api/users/<id>/passwd -> 204 (2.45.2)
# ---------------------------------------------------------------------------
# The JWT goes to curl as a config on a file descriptor (-K), not -H: argv.
_creds_portainer() {  # <method> <path> [jwt]; JSON body on stdin for POST/PUT. Prints body, then the code.
    local a=(-sk --max-time 15 -X "$1" -w '\n%{http_code}' -H 'Content-Type: application/json')
    [[ "$1" == GET ]] || a+=(--data-binary @-)
    if [[ -n "${3:-}" ]]; then
        curl "${a[@]}" -K <(printf 'header = "Authorization: Bearer %s"\n' "$3") "https://127.0.0.1:9443$2" 2>/dev/null
    else
        curl "${a[@]}" "https://127.0.0.1:9443$2" 2>/dev/null
    fi
}
_creds_portainer_login() {  # <user> <password> -> jwt
    local out
    out="$(_J_Username="$1" _J_Password="$2" _creds_json Username Password | _creds_portainer POST /api/auth)"
    [[ "${out##*$'\n'}" == 200 ]] || return 1
    python3 -c 'import json,sys; print(json.loads(sys.stdin.read()).get("jwt",""))' <<<"${out%$'\n'*}" | grep .
}
_creds_auth_portainer() { _creds_portainer_login "$(_cred_user portainer)" "$1" >/dev/null; }
_creds_portainer_passwd() {  # <jwt> <id> <current> <new>
    local out
    out="$(_J_Password="$3" _J_NewPassword="$4" _creds_json Password NewPassword | _creds_portainer PUT "/api/users/$2/passwd" "$1")"
    [[ "${out##*$'\n'}" == 204 ]]
}
# The stored admin_password is only the login when no placeholder
# (_cred_placeholder, lib/config.sh) marks it as one written for a Portainer
# whose real password nobody here knows -- cred_get then prints "unknown",
# which must never be sent to Portainer or "restored".
_creds_portainer_known() { [[ ! -e "$(_cred_placeholder portainer)" ]] && cred_get portainer; }
_creds_apply_portainer() {
    local new="$1" old user jwt id out r
    _creds_running intact_portainer || { _creds_fail "Portainer is not running"; return 1; }
    user="$(_cred_user portainer)"
    if ! old="$(_creds_portainer_known)"; then
        # The way out of a placeholder: the admin set a password in the Portainer
        # UI and typed that same value. Portainer taking it is the proof.
        if _creds_auth_portainer "$new"; then
            _creds_step "could not store the password" _cred_put portainer "$new" || return 1
            CREDS_APPLY_NOTE="adopted"
            return 0
        fi
        _creds_fail "the current Portainer admin password is not known here: set it in the Portainer UI, then put that value in config.yaml and run sudo scripts/apply-passwords.sh"
        return 1
    fi
    _creds_resume portainer "$old" "$new"; r=$?; (( r < 2 )) && return $r
    # Same value again: nothing to do in Portainer (no reader to recreate).
    [[ "$old" == "$new" ]] && _creds_auth_portainer "$new" && { CREDS_APPLY_NOTE="it already had this password"; return 0; }
    jwt="$(_creds_portainer_login "$user" "$old")" || { _creds_fail "Portainer does not accept the stored password"; return 1; }
    out="$(_creds_portainer GET /api/users "$jwt")"
    id="$(python3 -c 'import json,sys
for u in json.loads(sys.stdin.read()):
    if u.get("Username") == sys.argv[1]: print(u.get("Id"))' "$user" <<<"${out%$'\n'*}" 2>/dev/null)"
    [[ "$id" =~ ^[0-9]+$ ]] || { _creds_fail "could not find the Portainer user '${user}'"; return 1; }
    _creds_step "Portainer refused the change (it needs 12+ characters)" _creds_portainer_passwd "$jwt" "$id" "$old" "$new" || return 1
    _creds_step "Portainer does not accept the new password" _creds_auth_portainer "$new" \
        && _creds_step "could not store the new password" _cred_put portainer "$new" \
        && return 0
    local why="$CREDS_APPLY_REASON"
    # A password change ends every Portainer session: the JWT from before is
    # dead, so the way back starts with a fresh login on the NEW password. The
    # store gets the old value only once Portainer has it again (204).
    if jwt="$(_creds_portainer_login "$user" "$new")" && _creds_portainer_passwd "$jwt" "$id" "$new" "$old"; then
        _cred_put portainer "$old"
    elif _creds_auth_portainer "$old"; then
        _cred_put portainer "$old"
    elif _creds_auth_portainer "$new"; then
        _cred_put portainer "$new"
        why+=" -- the old password could not be put back in Portainer: the NEW one stays (stored)"
        CREDS_APPLY_PUT_BACK=0
    else
        why+=" -- state not confirmed: check Portainer, then re-run"
        CREDS_APPLY_PUT_BACK=0
    fi
    CREDS_APPLY_REASON="$why"
    return 1
}

# ---------------------------------------------------------------------------
# IRIS administrator (enforce_iris_admin_password rehashes with IRIS's bcrypt)
# ---------------------------------------------------------------------------
_creds_iris_matches() {   # asked of IRIS's own bcrypt; the value in the exec's env, never argv
    local user hash
    user="$(_creds_user iris)" || return 1
    hash="$(_creds_docker exec intact_iris_db psql -U iris -d iris_db -tAc \
            "SELECT password FROM \"user\" WHERE \"user\"='${user}'" 2>/dev/null | head -1)"
    [[ "$hash" == \$2* ]] || return 1
    _IRIS_PW="$1" _IRIS_H="$hash" _creds_docker exec -e _IRIS_PW -e _IRIS_H intact_iris_app python3 -c \
        'import os,sys;from flask_bcrypt import Bcrypt;sys.exit(0 if Bcrypt().check_password_hash(os.environ["_IRIS_H"],os.environ["_IRIS_PW"]) else 1)' \
        >/dev/null 2>&1
}
_creds_auth_iris() { _creds_iris_matches "$1"; }
_creds_apply_iris() {
    local new="$1" old r
    { _creds_running intact_iris_app && _creds_running intact_iris_db; } || { _creds_fail "IRIS is not running"; return 1; }
    declare -F enforce_iris_admin_password >/dev/null || { _creds_fail "enforce_iris_admin_password is not loaded"; return 1; }
    old="$(cred_get iris 2>/dev/null)"
    if [[ -n "$old" ]]; then _creds_resume iris "$old" "$new"; r=$?; (( r < 2 )) && return $r; fi
    _creds_step "could not store the new password" _cred_put iris "$new" \
        && { enforce_iris_admin_password >/dev/null 2>&1; true; } \
        && _creds_step "IRIS does not accept the new password" _creds_iris_matches "$new" \
        && return 0
    local why="$CREDS_APPLY_REASON"
    if [[ -n "$old" ]]; then
        _cred_put iris "$old"; enforce_iris_admin_password >/dev/null 2>&1
    else
        why+=" -- no earlier password was stored, so none could be put back (the new one stays stored)"
        CREDS_APPLY_PUT_BACK=0
    fi
    CREDS_APPLY_REASON="$why"
    return 1
}

# ---------------------------------------------------------------------------
# VolWeb admin (the backend reads secrets/ADMIN_PASSWORD live: no reader to recreate)
# ---------------------------------------------------------------------------
_creds_volweb_matches() {
    local out
    out="$(_VW_U="$(_cred_user volweb)" _VW_PW="$1" _creds_docker exec --user app -w /home/app/web -e _VW_U -e _VW_PW \
        intact_volweb_backend python3 manage.py shell -c \
        'import os;from django.contrib.auth import get_user_model as g;u=g().objects.filter(username=os.environ["_VW_U"]).first();print("PW-OK" if u and u.check_password(os.environ["_VW_PW"]) else "PW-NO")' \
        2>/dev/null)"
    [[ "$out" == *PW-OK* ]]
}
_creds_auth_volweb() { _creds_volweb_matches "$1"; }
_creds_apply_volweb() {
    local new="$1" old r
    _creds_running intact_volweb_backend || { _creds_fail "VolWeb is not running"; return 1; }
    declare -F seed_volweb_admin >/dev/null || { _creds_fail "seed_volweb_admin is not loaded"; return 1; }
    old="$(cred_get volweb 2>/dev/null)"
    if [[ -n "$old" ]]; then _creds_resume volweb "$old" "$new"; r=$?; (( r < 2 )) && return $r; fi
    _creds_step "could not store the new password" _cred_put volweb "$new" \
        && _creds_step "seeding the VolWeb admin failed" seed_volweb_admin >/dev/null 2>&1 \
        && _creds_step "VolWeb does not accept the new password" _creds_volweb_matches "$new" \
        && return 0
    local why="$CREDS_APPLY_REASON"
    if [[ -n "$old" ]]; then
        _cred_put volweb "$old"; seed_volweb_admin >/dev/null 2>&1
    else
        why+=" -- no earlier password was stored, so none could be put back (the new one stays stored)"
        CREDS_APPLY_PUT_BACK=0
    fi
    CREDS_APPLY_REASON="$why"
    return 1
}

# creds_apply <module> <new_value> -- see the top of this file.
creds_apply() {
    local m="$1" v="$2" reason
    CREDS_APPLY_REASON=""; CREDS_APPLY_NOTE=""; CREDS_APPLY_PUT_BACK=1
    case "$m" in elk|timesketch|velociraptor|portainer|iris|volweb) ;;
        *) _creds_fail "unknown module '${m}'"; return 1 ;; esac
    # secret_check respects the lab switch; the character set is checked either way.
    reason="$(secret_check "$v")" || { _creds_fail "the new password is not accepted: ${reason}"; return 1; }
    # No "already its password" shortcut: the value being stored proves nothing
    # about the tool or the readers (a cut-off run stores Velociraptor's first,
    # and ES's before its readers), so the same value is simply applied again.
    if "_creds_apply_${m}" "$v"; then
        log_success "  ${m}: $(_cred_label "$m") password changed (tool, store and readers)${CREDS_APPLY_NOTE:+ (${CREDS_APPLY_NOTE})}"
        return 0
    fi
    if (( CREDS_APPLY_PUT_BACK )); then
        log_warn "  ${m}: password NOT changed — ${CREDS_APPLY_REASON}; everything was put back"
    else
        log_error "  ${m}: password change FAILED and was not fully put back — ${CREDS_APPLY_REASON}"
    fi
    return 1
}

# ---------------------------------------------------------------------------
# Rotation of human-only logins still on a public value. Each only against a
# running tool; a failure leaves the old value everywhere (creds_apply).
# ---------------------------------------------------------------------------
_creds_rotated() { CREDS_ROTATED+=("$1"); [[ -n "${2:-}" ]] && CREDS_ROTATED_SHOW+=("$2"); return 0; }

_creds_rotate_velociraptor() {
    _creds_running intact_velociraptor || return 0
    local rows=() who key u old new show=""
    for who in GUI api; do
        IFS='|' read -r key u _ <<<"$(_creds_velo_row "$who")"
        old="$(secret_get velociraptor "$key" 2>/dev/null)" || continue
        secret_is_known_default "$old" || continue
        # Like Portainer and IRIS: a stored value that no longer logs in was
        # changed in the Velociraptor UI by someone who knows the new one.
        if ! _creds_velo_login "$u" "$old"; then
            log_warn "  velociraptor: '${u}' no longer logs in with its stored (public) password -- changed in the Velociraptor UI? Not rotated.$([[ "$who" == GUI ]] && printf ' Intact owns this password: set it with sudo scripts/apply-passwords.sh')"
            continue
        fi
        new="$(secret_generate)"
        rows+=("$(_creds_velo_row "$who")|${new}")
        [[ "$who" == GUI ]] && show="Velociraptor|${u}|${new}"
    done
    (( ${#rows[@]} )) || return 0
    if ! _creds_velo_apply "${rows[@]}"; then
        log_warn "  velociraptor: could not replace the public password (${CREDS_APPLY_REASON}); it keeps the old one"
        return 1
    fi
    log_success "  velociraptor: no user has the public default password any more"
    # `api` alone is nobody's login: nothing new for the operator to see.
    [[ -n "$show" ]] && _creds_rotated velociraptor "$show"
    return 0
}

_creds_rotate_portainer() {
    local old; old="$(_creds_portainer_known 2>/dev/null)" || return 0
    secret_is_known_default "$old" || return 0
    _creds_running intact_portainer || return 0
    local user; user="$(_cred_user portainer)"
    if ! _creds_portainer_login "$user" "$old" >/dev/null; then
        log_info "  portainer: '${user}' no longer logs in with the shipped default; nothing to rotate"
        return 0
    fi
    local new; new="$(secret_generate)"
    if ! _creds_apply_portainer "$new"; then
        log_warn "  portainer: ${CREDS_APPLY_REASON}; '${user}' keeps the old password"
        return 1
    fi
    log_success "  portainer: '${user}' no longer has the public default password"
    _creds_rotated portainer "Portainer|${user}|${new}"
}

_creds_rotate_iris() {
    local old; old="$(cred_get iris 2>/dev/null)" || return 0
    secret_is_known_default "$old" || return 0
    { _creds_running intact_iris_app && _creds_running intact_iris_db; } || return 0
    declare -F enforce_iris_admin_password >/dev/null || return 0
    if ! _creds_iris_matches "$old"; then
        log_info "  iris: the administrator no longer uses the shipped default; nothing to rotate"
        return 0
    fi
    local new; new="$(secret_generate)"
    if ! _creds_apply_iris "$new"; then
        log_warn "  iris: could not apply a new administrator password (${CREDS_APPLY_REASON}); it keeps the old one"
        return 1
    fi
    log_success "  iris: the administrator no longer has the public default password"
    _creds_rotated iris "IRIS|$(_cred_user iris)|${new}"
}

# Timesketch's SECRET_KEY as published in this repo (.gitleaks.toml stopword),
# as a sha256: comparing hashes keeps the value itself out of one more file.
_CREDS_TS_PUBLISHED_KEY_SHA256=06f9579840b34badb36aca9852a3a1258a4dc1a58373f9f5d865595d4d476e3d  # gitleaks:allow (a hash of a public value)

# Timesketch's Flask SECRET_KEY (session cookies, CSRF) when it is the one this
# repo published. Not a login, so neither shown nor listed as rotated: sessions
# end, that is all. It lives in the bind-mounted conf, so a restart (not a
# recreate) is enough here.
_creds_rotate_timesketch() {
    local d="${SCRIPT_DIR}/modules/timesketch/config" f key pub="" hit=() c
    for f in "${d}/timesketch.conf" "${d}/timesketch_legacy.conf"; do
        key="$(sed -n "s/^SECRET_KEY = '\([^']*\)'.*/\1/p" "$f" 2>/dev/null | head -1)"
        [[ -n "$key" ]] || continue
        [[ "$(printf '%s' "$key" | sha256sum | cut -d' ' -f1)" == "$_CREDS_TS_PUBLISHED_KEY_SHA256" ]] && { hit+=("$f"); pub="$key"; }
    done
    (( ${#hit[@]} )) || return 0
    _creds_running intact_timesketch_web || return 0
    local new; new="$(openssl rand -hex 32)" || return 1
    local -A was=()
    for f in "${hit[@]}"; do
        was[$f]="$(cat "$f")"
        # Rewritten in place (`>` truncates: the conf is a bind-mounted file) by
        # bash itself: printf is a builtin, so the new key is in no argv (it was
        # in sed's). Both keys are hex, so the pattern needs no escaping.
        printf '%s\n' "${was[$f]//"SECRET_KEY = '${pub}'"/"SECRET_KEY = '${new}'"}" > "$f"
    done
    local running=()
    for c in intact_timesketch_web intact_timesketch_web_legacy intact_timesketch_web_v3 intact_timesketch_worker; do
        _creds_running "$c" && running+=("$c")
    done
    if ! _creds_docker restart "${running[@]}" >/dev/null 2>&1; then
        for f in "${hit[@]}"; do printf '%s\n' "${was[$f]}" > "$f"; done
        _creds_docker restart "${running[@]}" >/dev/null 2>&1
        log_warn "  timesketch: could not restart with a new SECRET_KEY; it keeps the published one"
        return 1
    fi
    log_success "  timesketch: SECRET_KEY replaced (it was the value published in the repo)"
}

# creds_rotate_known_defaults [module...] -- default: every human-only one.
# Values rotated are in CREDS_ROTATED_SHOW for the caller to show (install.sh
# reads them back from the stores through credential_lines). 1 if any failed.
creds_rotate_known_defaults() {
    local mods=("$@") m rc=0
    (( ${#mods[@]} )) || mods=(velociraptor portainer iris timesketch)
    for m in "${mods[@]}"; do
        declare -F "_creds_rotate_${m}" >/dev/null || continue
        if secret_weak_allowed; then
            log_info "  ${m}: allow_weak_passwords is on — known passwords are not rotated"
            continue
        fi
        "_creds_rotate_${m}" || rc=1
    done
    creds_mark_defaults
    return $rc
}

# data/state/default-passwords.json, 0600 (the backend reads it as root):
#   {"modules": [machine-used logins still on a public value -- the backend
#                logs in with them, so they wait for scripts/apply-passwords.sh],
#    "rotated": [modules whose password a rotation changed and the operator
#                has not seen yet -- kept from earlier runs, plus this one's],
#    "since":   "<iso>"}
# Deleted when both lists are empty. A lab box lists no "modules".
creds_mark_defaults() {
    local f="${SCRIPT_DIR}/data/state/default-passwords.json" mods=() v
    if ! secret_weak_allowed; then
        for v in "$(secret_get elk ELASTIC_PASSWORD 2>/dev/null)" "$(secret_get elk KIBANA_PASSWORD 2>/dev/null)"; do
            secret_is_known_default "$v" && { mods+=(elk); break; }
        done
        secret_is_known_default "$(secret_get timesketch TIMESKETCH_PASSWORD 2>/dev/null)" && mods+=(timesketch)
        secret_is_known_default "$(cred_get volweb 2>/dev/null)" && mods+=(volweb)
    fi
    ( umask 077; mkdir -p "${f%/*}" ) || return 0
    python3 - "$f" "${mods[*]}" "${CREDS_ROTATED[*]}" <<'PY' || log_warn "  could not write ${f}"
import datetime, json, os, sys
path, mods, rotated = sys.argv[1], sys.argv[2].split(), sys.argv[3].split()
now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
old = {}
try:
    old = json.load(open(path))
except Exception:
    pass
for m in old.get("rotated") or []:
    if m not in rotated:
        rotated.insert(0, m)
if not mods and not rotated:
    if os.path.exists(path):
        os.unlink(path)
    sys.exit(0)
tmp = path + ".tmp"
fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w") as fh:
    json.dump({"modules": mods, "rotated": rotated, "since": old.get("since") or now}, fh)
os.chmod(tmp, 0o600)
os.replace(tmp, path)
PY
    (( ${#mods[@]} )) && log_warn "  public default password still in use (the backend logs in with it): ${mods[*]} — change it with sudo scripts/apply-passwords.sh"
    return 0
}
