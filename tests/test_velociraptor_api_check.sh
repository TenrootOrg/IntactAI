#!/bin/bash
# scripts/velociraptor-api-check.sh -- the safety net for the backend's one way
# into Velociraptor (the `api` user and its certificate).
#
# The real script runs against a fake docker that plays Velociraptor and the
# backend from small state files: the user `api` (ok / missing / reader), the
# api.config.yaml (good / garbage / stale CA), the container (up / stopped) and
# the GUI password (matches / changed). The certificate is a real one made here,
# because the script asks openssl whose it is. Root is faked with `unshare -r`.
# The same five breakages were also run against Velociraptor 0.77.3 itself.

source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

python3 -c 'import yaml' 2>/dev/null || { echo "$(basename "$0"): SKIP -- PyYAML not installed"; exit 0; }
command -v openssl >/dev/null || { echo "$(basename "$0"): SKIP -- openssl not installed"; exit 0; }
unshare -r true 2>/dev/null || { echo "$(basename "$0"): SKIP -- unshare -r not permitted"; exit 0; }

_world() {
    W="$(mktemp -d)"
    mkdir -p "$W/root/scripts" "$W/root/lib" "$W/root/modules/velociraptor/secrets" "$W/bin" "$W/s"
    cp "$REPO/scripts/velociraptor-api-check.sh" "$W/root/scripts/"
    cp "$REPO/lib/secrets.sh" "$W/root/lib/"
    printf 'VELOX_PASSWORD_2=StoredApiPw9\n' > "$W/root/modules/velociraptor/secrets/creds.env"
    # a real certificate, CN=api, and the "CA" both configs carry
    openssl req -x509 -newkey rsa:2048 -nodes -keyout /dev/null -out "$W/cert.pem" \
        -subj "/CN=api" -days 1 2>/dev/null
    python3 - "$W" <<'PYEOF'
import sys, yaml
w = sys.argv[1]
cert = open(f"{w}/cert.pem").read()
api = {"ca_certificate": "THE-CA", "client_cert": cert, "client_private_key": "FAKEKEY",
       "api_connection_string": "intact_velociraptor:8001", "name": "api"}
open(f"{w}/api.good", "w").write(yaml.safe_dump(api))
api["ca_certificate"] = "AN-OLD-CA"
open(f"{w}/api.staleca", "w").write(yaml.safe_dump(api))
open(f"{w}/server.yaml", "w").write(yaml.safe_dump({"Client": {"ca_certificate": "THE-CA"}}))
PYEOF
    echo up > "$W/s/container"; echo good > "$W/s/apicfg"; echo ok > "$W/s/user"; echo same > "$W/s/pw"
    cat > "$W/bin/docker" <<EOF
#!/bin/bash
S="$W/s"; echo "docker \$*" >> "$W/calls"
st() { cat "\$S/\$1"; }
case "\$*" in
  "ps --filter name=^intact_velociraptor\$ --format {{.Status}}") [[ \$(st container) == up ]] && echo "Up 3 hours" ;;
  "ps -a --filter name=^intact_velociraptor\$ --format {{.Status}}") [[ \$(st container) == up ]] && echo "Up 3 hours" || echo "Exited (0) 1 minute ago" ;;
  "ps --filter name=^intact_backend\$ --format {{.Status}}") echo "Up 3 hours (healthy)" ;;
  "ps -a --format {{.Names}}") echo intact_velociraptor; echo intact_backend ;;
  "exec intact_velociraptor sh -c "*)
      case \$(st apicfg) in good) cat "$W/api.good" ;; staleca) cat "$W/api.staleca" ;; garbage) echo "not: [valid" ;; esac
      echo "@@SERVER@@"; cat "$W/server.yaml" ;;
  "exec intact_velociraptor ./velociraptor --api_config"*)
      [[ \$(st container) == up ]] || { echo "Error response from daemon: container is not running"; exit 1; }
      [[ \$(st apicfg) == good ]] || { echo "velociraptor: error: query: rpc error: code = Unavailable desc = connection error"; exit 1; }
      case \$(st user) in
        missing) echo "velociraptor: error: query: rpc error: code = Unknown desc = User not found: api"; exit 1 ;;
        reader)  echo "velociraptor: error: query: rpc error: code = PermissionDenied desc = Permission denied: User api requires permission ANY_QUERY to run queries"; exit 1 ;;
        apionly) [[ "\$*" == *"user(user="* ]] && echo '[{"u": {"name": "api", "roles": ["api"]}}]' || echo '[{"Hostname": "v"}]' ;;
        *)       [[ "\$*" == *"user(user="* ]] && echo '[{"u": {"name": "api", "roles": ["administrator", "api"]}}]' || echo '[{"Hostname": "v"}]' ;;
      esac ;;
  "exec -e _P intact_velociraptor sh -c "*)
      echo "user add \${@: -2} pw=\$_P" >> "$W/useradd"; echo pending > "\$S/fix" ;;
  "restart intact_velociraptor")
      [[ -e "\$S/fix" ]] && { echo ok > "\$S/user"; echo same > "\$S/pw"; rm -f "\$S/fix"; }
      echo good > "\$S/apicfg" ;;
  "start intact_velociraptor") echo up > "\$S/container" ;;
  "exec -w /app intact_backend python3 -c "*)
      if [[ \$(st container) == up && \$(st apicfg) == good && \$(st user) == ok ]]; then echo "RESULT ok"
      else echo "RESULT <_MultiThreadedRendezvous of RPC that terminated with: status = StatusCode.PERMISSION_DENIED>"; fi ;;
esac
exit 0
EOF
    cat > "$W/bin/curl" <<EOF
#!/bin/bash
cat > "$W/curl_stdin"
[[ \$(cat "$W/s/pw") == same ]] && echo 200 || echo 401
EOF
    chmod +x "$W/bin/"*
}

# _run [--fix] -> $OUT, $RC
_run() {
    RC=0
    OUT="$(PATH="$W/bin:$PATH" VELO_API_WAIT=3 unshare -r bash "$W/root/scripts/velociraptor-api-check.sh" "$@" </dev/null 2>&1)" || RC=$?
}

test_a_healthy_box_passes_every_check_and_changes_nothing() {
    _world; _run
    assert_eq "$RC" "0" "$OUT"
    assert_contains "$OUT" "Healthy."
    assert_eq "$(grep -c '  OK  ' <<<"$OUT")" "5" "container, certificate, user and roles, password, backend"
    assert_not_contains "$(cat "$W/calls")" "restart"
    assert_false test -e "$W/useradd"
}

test_a_deleted_api_user_is_found_and_recreated() {
    _world; echo missing > "$W/s/user"
    _run
    assert_eq "$RC" "1"
    assert_contains "$OUT" "'api' does not exist"
    assert_contains "$OUT" "--fix"
    assert_not_contains "$(cat "$W/calls")" "restart" "a check alone never repairs"
    _run --fix
    assert_eq "$RC" "0" "$OUT"
    assert_contains "$(cat "$W/useradd")" "user add api api,administrator pw=StoredApiPw9" "the stored password, both roles"
    assert_contains "$(cat "$W/calls")" "restart intact_velociraptor" "a running server sees a CLI user add only after a restart"
    assert_contains "$OUT" "Repaired."
}

test_the_password_never_reaches_an_argv() {
    _world; echo missing > "$W/s/user"
    _run --fix
    assert_not_contains "$(cat "$W/calls")" "StoredApiPw9" "docker events log the full exec command"
    assert_contains "$(cat "$W/calls")" "exec -e _P intact_velociraptor"
    assert_not_contains "$OUT" "StoredApiPw9"
    assert_not_contains "$(cat "$W"/root/velociraptor-api-check-*.log)" "StoredApiPw9"
}

test_lost_roles_are_found_and_restored() {
    _world; echo reader > "$W/s/user"
    _run
    assert_eq "$RC" "1"
    assert_contains "$OUT" "lost its roles"
    assert_contains "$OUT" "the backend cannot use Velociraptor"
    _run --fix
    assert_eq "$RC" "0" "$OUT"
    assert_contains "$(cat "$W/useradd")" "api,administrator"
}

test_only_part_of_the_roles_is_also_a_problem() {
    _world; echo apionly > "$W/s/user"
    _run
    assert_eq "$RC" "1"
    assert_contains "$OUT" "has roles 'api', needs administrator and api"
}

test_a_broken_or_stale_api_config_is_regenerated_by_a_restart() {
    _world; echo garbage > "$W/s/apicfg"
    _run
    assert_eq "$RC" "1"
    assert_contains "$OUT" "api.config.yaml is not valid YAML"
    _run --fix
    assert_eq "$RC" "0" "$OUT"
    assert_contains "$(cat "$W/calls")" "restart intact_velociraptor"
    assert_false test -e "$W/useradd" "the user was fine: not touched"
    _world; echo staleca > "$W/s/apicfg"
    _run
    assert_contains "$OUT" "signed by another CA"
}

test_a_stopped_velociraptor_is_started_not_recreated() {
    _world; echo stopped > "$W/s/container"
    _run
    assert_eq "$RC" "1"
    assert_contains "$OUT" "intact_velociraptor is not running"
    _run --fix
    assert_eq "$RC" "0" "$OUT"
    assert_contains "$(cat "$W/calls")" "start intact_velociraptor"
    assert_not_contains "$(cat "$W/calls")" "compose"
}

test_a_changed_password_is_only_information_and_fix_resets_it() {
    _world; echo changed > "$W/s/pw"
    _run
    assert_eq "$RC" "0" "the backend does not use it: $OUT"
    assert_contains "$OUT" "INFO  'api''s password differs from the stored one"
    _run --fix
    assert_contains "$(cat "$W/useradd")" "pw=StoredApiPw9"
    assert_contains "$OUT" "'api' still has the password Intact stored"
    assert_not_contains "$(cat "$W/curl_stdin")" "StoredApiPw9 " "curl reads it from stdin, never argv"
}

test_it_needs_root_and_known_options() {
    local out rc=0
    out="$(bash "$REPO/scripts/velociraptor-api-check.sh" 2>&1)" || rc=$?
    assert_eq "$rc" "2"; assert_contains "$out" "sudo bash scripts/velociraptor-api-check.sh"
    rc=0; out="$(bash "$REPO/scripts/velociraptor-api-check.sh" --repair 2>&1)" || rc=$?
    assert_eq "$rc" "2"; assert_contains "$out" "unknown option"
    assert_contains "$(bash "$REPO/scripts/velociraptor-api-check.sh" --help)" "User not found"
}

run_all_tests
