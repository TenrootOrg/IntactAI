#!/bin/bash
# Module passwords reach containers ONLY from the box's private stores
# (modules/<m>/secrets/creds.env, lib/secrets.sh), never from compose text.
#
# `${X_PASSWORD:-changeme}` in a compose file is interpolated from the module's
# git-tracked .env, NOT from env_file -- so it either published a default (the
# fallback was live) or masked the store. And a password in a healthcheck or
# command is in argv and in `docker inspect`. These pin all three shut.

set -u
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./helpers.sh

M="$(cd ../modules && pwd)"

_code() { grep -vE '^\s*#' "$1"; }   # compose text minus comments

test_no_password_interpolation_or_changeme() {
    local f rel
    for f in "${M}"/*/docker-compose.yaml; do
        rel="${f#${M}/}"
        # volweb's VOLWEB_POSTGRES_PASSWORD is the one exception: a per-box random
        # value in an UNTRACKED .env (lib/modules/volweb.sh), not a known default.
        assert_false bash -c "grep -vE '^\s*#' '$f' | grep -v 'VOLWEB_POSTGRES_PASSWORD' | grep -qE '\\$\\{[A-Z0-9_]*PASS[A-Z0-9_]*'"
        assert_false bash -c "grep -vE '^\s*#' '$f' | grep -qi 'changeme'"
        assert_true true "${rel}: no password interpolation, no changeme"
    done
}

_count_optional() {  # file path -> how many `- path: <path>` entries say required: false
    grep -A1 -E "^\s*- path: ${2//./\\.}\s*$" "$1" | grep -cE '^\s*required: false\s*$'
}

test_every_long_env_file_is_optional() {
    local f n_path n_req
    for f in "${M}"/*/docker-compose.yaml; do
        n_path="$(_code "$f" | grep -cE '^\s*- path: ')"
        n_req="$(_code "$f" | grep -A1 -E '^\s*- path: ' | grep -cE '^\s*required: false\s*$')"
        assert_eq "$n_req" "$n_path" "${f#${M}/}: every env_file path is required: false"
    done
}

test_stores_wired_where_the_contract_says() {
    assert_eq "$(_count_optional "${M}/elk/docker-compose.yaml" ./secrets/creds.env)" 4 \
        "elk: elasticsearch, setup, logstash, kibana read creds.env"
    assert_eq "$(_count_optional "${M}/timesketch/docker-compose.yaml" ./secrets/creds.env)" 1 \
        "timesketch-web reads creds.env"
    assert_eq "$(_count_optional "${M}/velociraptor/docker-compose.yaml" ./secrets/creds.env)" 1 \
        "velociraptor reads its creds.env"
    assert_eq "$(_count_optional "${M}/velociraptor/docker-compose.yaml" ../elk/secrets/creds.env)" 1 \
        "velociraptor reads ELASTIC_PASSWORD from elk"
    assert_eq "$(_count_optional "${M}/backend/docker-compose.yaml" ../elk/secrets/creds.env)" 1 \
        "backend reads elk creds"
    assert_eq "$(_count_optional "${M}/backend/docker-compose.yaml" ../timesketch/secrets/creds.env)" 1 \
        "backend reads timesketch creds"
    # environment: beats env_file, so these would mask the store.
    assert_false grep -qE '^\s*- (ELASTICSEARCH_PASSWORD|TIMESKETCH_PASS)=' "${M}/backend/docker-compose.yaml"
}

test_elk_passwords_stay_out_of_argv() {
    local c="${M}/elk/docker-compose.yaml" s="${M}/elk/config/setup-kibana-user.sh"
    assert_contains "$(_code "$c")" 'curl -s -K- http://localhost:9200/_cluster/health' "healthcheck feeds curl a config on stdin"
    assert_contains "$(_code "$c")" '$$ELASTIC_PASSWORD' "healthcheck reads the password inside the container"
    assert_false bash -c "cat '$c' '$s' | grep -vE '^\s*#' | grep -qE -- '-u +\"?elastic:'"
    assert_false grep -qE -- '-d +"\{\\"password' "$s"
    # kibana-docker turns ELASTICSEARCH_PASSWORD into a --elasticsearch.password argv flag
    assert_false bash -c "grep -vE '^\s*#' '$c' | grep -qE 'ELASTICSEARCH_(USERNAME|PASSWORD)='"
    assert_contains "$(cat "${M}/elk/config/kibana.yml")" 'elasticsearch.password: "${KIBANA_PASSWORD}"' "kibana.yml expands KIBANA_PASSWORD"
    assert_contains "$(cat "${M}/elk/config/kibana.yml")" 'elasticsearch.username: "kibana_system"' "kibana logs in as kibana_system"
    assert_contains "$(_code "$c")" './config/kibana.yml:/usr/share/kibana/config/kibana.yml:ro' "kibana.yml mounted"
}

test_velociraptor_users() {
    local ep="${M}/velociraptor/entrypoint.sh"
    # never echo a password
    assert_false grep -qE 'echo .*\$\{?VELOX_PASSWORD' "$ep"
    # `api` is the backend's API-cert identity: re-keyed when its value changes, never deleted
    assert_contains "$(cat "$ep")" 'user add "$VELOX_USER_2" "$VELOX_PASSWORD_2" --role "$VELOX_ROLE_2"' "api password re-applied"
    assert_false grep -qE 'user (delete|rm)' "$ep"
    assert_contains "$(cat "$ep")" '--name api' "api client cert still created"
}

# The users block of entrypoint.sh, run for real against a stub ./velociraptor
# that records each `user add` (user name only, never the value).
_run_user_block() {  # dir VELOX_PASSWORD_2 [stub exit code]
    local d="$1"
    sed -n '/^# Users\./,/^# Skip certificate rotation/p' "${M}/velociraptor/entrypoint.sh" > "$d/block.sh"
    printf '#!/bin/bash\n[[ $3 == user && $4 == add ]] && echo "add $5" >> calls\n[[ $3 == user && $4 == show ]] && exit 0\nexit %s\n' \
        "${3:-0}" > "$d/velociraptor"
    chmod 755 "$d/velociraptor"
    (cd "$d" && VELOX_PASSWORD_2="$2" bash -e block.sh) > "$d/out" 2>&1
}

test_velociraptor_api_password_reapplied_only_on_change() {
    local d pw="Rand0mApiValue123456XYZ"
    d=$(mktemp -d)
    _run_user_block "$d" "$pw" 1                       # user add fails: no stamp, retried
    assert_eq "$(grep -c 'add api' "$d/calls")" 1 "failed apply attempted"
    assert_false test -e "$d/.api_pw.sha256"
    _run_user_block "$d" "$pw"
    assert_eq "$(grep -c 'add api' "$d/calls")" 2 "applied after the failure"
    assert_eq "$(stat -c %a "$d/.api_pw.sha256")" 600 "stamp is root-only"
    assert_false grep -q "$pw" "$d/.api_pw.sha256" "$d/out"
    _run_user_block "$d" "$pw"
    assert_eq "$(grep -c 'add api' "$d/calls")" 2 "unchanged value: no user add, not in argv"
    _run_user_block "$d" "Changed0ApiValue123456XY"
    assert_eq "$(grep -c 'add api' "$d/calls")" 3 "changed value re-applied"
    rm -rf "$d"
}

# The GUI user: the store is authoritative too (a revert by apply-passwords.sh
# that found the container down relies on the next start applying it).
test_velociraptor_gui_password_follows_the_store() {
    local d pw="Gui1StoredValue99"
    d=$(mktemp -d)
    sed -n '/^# Users\./,/^# Skip certificate rotation/p' "${M}/velociraptor/entrypoint.sh" > "$d/block.sh"
    # user show prints only for a user that exists; user add records the name only
    cat > "$d/velociraptor" <<'EOF'
#!/bin/bash
[[ $3 == user && $4 == show ]] && { grep -qx "$5" users 2>/dev/null && echo "$5"; exit 0; }
[[ $3 == user && $4 == add ]] && { echo "add $5" >> calls; [[ -e fail ]] && exit 1; echo "$5" >> users; }
exit 0
EOF
    chmod 755 "$d/velociraptor"
    _gui() { (cd "$d" && VELOX_USER=tenroot VELOX_ROLE=administrator VELOX_PASSWORD="$1" bash -e block.sh) > "$d/out" 2>&1; }
    : > "$d/fail"; _gui "$pw"
    assert_eq "$(grep -c 'add tenroot' "$d/calls")" 1 "missing user: created (attempted)"
    assert_false test -e "$d/.gui_pw.sha256" "no stamp after a failed apply"
    rm "$d/fail"; _gui "$pw"
    assert_eq "$(grep -c 'add tenroot' "$d/calls")" 2 "retried at the next start"
    assert_eq "$(stat -c %a "$d/.gui_pw.sha256")" 600 "stamp is root-only"
    _gui "$pw"
    assert_eq "$(grep -c 'add tenroot' "$d/calls")" 2 "same stored value: not re-applied (not in argv)"
    _gui "Gui2ChangedValue99"
    assert_eq "$(grep -c 'add tenroot' "$d/calls")" 3 "a changed store is applied to the existing user"
    rm "$d/.gui_pw.sha256"; _gui "Gui2ChangedValue99"
    assert_eq "$(grep -c 'add tenroot' "$d/calls")" 4 "a dropped stamp (apply-passwords.sh revert) re-applies"
    assert_false grep -q "$pw" "$d/.gui_pw.sha256" "$d/out"
    assert_false grep -q "Gui2ChangedValue99" "$d/out"
    rm -rf "$d"
}

test_backend_image_never_bakes_the_live_config() {
    local d="${M}/backend/Dockerfile"
    assert_false grep -qE '^COPY +config\.yaml +/app/' "$d"
    assert_eq "$(grep -cE '^COPY --from=config-template /tmp/config.yaml /app/config.yaml$' "$d")" 2 \
        "both config.yaml copies come from the sanitized stage"
    assert_contains "$(cat "$d")" 'RUN python3 /tmp/sanitize_config.py config.yaml /tmp/config.raw.yaml /tmp/config.yaml' "sanitizer runs"
}

run_all_tests
