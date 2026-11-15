#!/bin/bash
# scripts/change_ip.sh applies, in one run, whatever differs between what the
# box serves now (.env files) and NEW_IP + the ports in config.yaml: the IP,
# the ports, both, or nothing. docker is stubbed; every call is logged with the
# directory it ran in, so "which stack was recreated" is visible.

set -u
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./helpers.sh

LOG_FILE="$(mktemp)"
source ../scripts/change_ip.sh   # defines change_ip_main, runs nothing

# Logged as "docker <args> @<dir>"; DIFF_OUT fakes a server.config.yaml patch
# that touched more than the agent URL.
DIFF_OUT=""
# DOCKER_FAIL_ONCE: the first call matching it fails (a flag file, because
# compose runs in a subshell), like a host port that is already taken.
DOCKER_FAIL_ONCE=""
docker() {
    echo "docker $* @${PWD##*/}" >> "$STUB_LOG"
    if [[ -n "$DOCKER_FAIL_ONCE" && "docker $* @${PWD##*/}" == *"$DOCKER_FAIL_ONCE"* && ! -e "$WORK/.failed" ]]; then
        : > "$WORK/.failed"; return 1
    fi
    [[ "$*" == *"diff "* && -n "$DIFF_OUT" ]] && echo "$DIFF_OUT"
    return 0
}

WORK=""
_setup() {
    WORK="$(mktemp -d)"
    SCRIPT_DIR="$WORK"
    CONFIG_FILE="${WORK}/config.yaml"
    mkdir -p "$WORK/modules/nginx" "$WORK/modules/velociraptor" "$WORK/modules/backend" "$WORK/scripts"
    echo "NGINX_VERSION=1.31.2-alpine" > "$WORK/modules/nginx/.env"
    printf 'VELOX_PUBLIC_IP=10.0.0.5\nVELOX_SERVER_URL=https://10.0.0.5:8000/\n' > "$WORK/modules/velociraptor/.env"
    : > "$WORK/modules/backend/.env"
    : > "$WORK/scripts/generate_clients.sh"
    cat > "$CONFIG_FILE" <<'YAML'
# operator comment that must survive
domain: 10.0.0.5
modules:
  elk:
    enabled: false
  velociraptor:
    enabled: true
YAML
    stub check_root
    stub _stamp_host_codex_paths
    DIFF_OUT=""
    DOCKER_FAIL_ONCE=""
}
_teardown() { [[ -n "$WORK" ]] && rm -rf "$WORK"; WORK=""; }

_set_ports() {  # modules.<m>.<key>: <v> triples, written as the backend does (keys appended)
    python3 - "$CONFIG_FILE" "$@" <<'PY'
import sys, yaml
p, args = sys.argv[1], sys.argv[2:]
c = yaml.safe_load(open(p))
for i in range(0, len(args), 3):
    c["modules"].setdefault(args[i], {})[args[i + 1]] = yaml.safe_load(args[i + 2])
yaml.safe_dump(c, open(p, "w"))
PY
}

_env() { sed -n "s/^$2=//p" "$WORK/modules/$1/.env"; }
_run() { RUN_OUT="$( ( change_ip_main "$@" ) 2>&1)"; RUN_RC=$?; }

test_nothing_changed_touches_no_container() {
    _setup
    local before; before="$(cat "$CONFIG_FILE" "$WORK"/modules/*/.env)"
    _run
    assert_eq "$RUN_RC" "0"
    assert_contains "$RUN_OUT" "Nothing to change"
    _run 10.0.0.5 --yes
    assert_eq "$RUN_RC" "0" "explicit current IP is also nothing"
    assert_eq "$(stub_call_count docker)" "0" "no container touched"
    assert_eq "$(cat "$CONFIG_FILE" "$WORK"/modules/*/.env)" "$before"
    _teardown
}

test_invalid_port_refuses_and_writes_nothing() {
    _setup
    _set_ports volweb port 8000
    local before; before="$(cat "$CONFIG_FILE" "$WORK"/modules/*/.env)"
    _run 10.0.0.9
    assert_eq "$RUN_RC" "1"
    assert_contains "$RUN_OUT" "nothing was changed"
    assert_eq "$(cat "$CONFIG_FILE" "$WORK"/modules/*/.env)" "$before" "domain not written either"
    assert_eq "$(stub_call_count docker)" "0"
    _teardown
}

test_invalid_ip_is_refused() {
    _setup
    _run 10.0.0.256
    assert_eq "$RUN_RC" "1"
    assert_eq "$(stub_call_count docker)" "0"
    _teardown
}

test_ports_only_recreates_nginx_only() {
    _setup
    _set_ports timesketch port 6443
    _run
    assert_eq "$RUN_RC" "0"
    assert_eq "$(_env nginx TIMESKETCH_PORT)" "6443"
    assert_eq "$(_env nginx NGINX_VERSION)" "1.31.2-alpine" "existing key untouched"
    assert_true stub_called_with docker "compose up -d --pull never @nginx"
    assert_false stub_called_with docker "@velociraptor"
    assert_false stub_called_with docker "restart"
    assert_false stub_called_with docker "exec"
    assert_eq "$(stub_call_count docker)" "2" "docker info + the nginx stack"
    assert_false test -e "$WORK/modules/nginx/ssl/nginx-cert.crt" "no cert regenerated"
    assert_contains "$RUN_OUT" "Timesketch:  https://10.0.0.5:6443"
    assert_not_contains "$RUN_OUT" "cut off"
    assert_not_contains "$RUN_OUT" "OLD IP"
    # A second run finds nothing left to do.
    reset_stubs; _run
    assert_contains "$RUN_OUT" "Nothing to change"
    assert_eq "$(stub_call_count docker)" "0"
    _teardown
}

test_ip_only_behaves_as_before() {
    _setup
    local inode; inode="$(stat -c %i "$CONFIG_FILE")"
    _run 10.0.0.9 -y
    assert_eq "$RUN_RC" "0"
    assert_eq "$(read_config "['domain']")" "10.0.0.9"
    assert_eq "$(stat -c %i "$CONFIG_FILE")" "$inode" "config.yaml rewritten in place (the backend mounts it by inode)"
    assert_contains "$(cat "$CONFIG_FILE")" "# operator comment that must survive"
    assert_eq "$(_env velociraptor VELOX_PUBLIC_IP)" "10.0.0.9"
    assert_eq "$(_env velociraptor VELOX_SERVER_URL)" "https://10.0.0.9:8000/"
    assert_contains "$(openssl x509 -noout -subject -in "$WORK/modules/nginx/ssl/nginx-cert.crt")" "10.0.0.9"
    assert_true stub_called_with docker 'exec intact_velociraptor sed -i s|10\.0\.0\.5|10.0.0.9|g'
    assert_true stub_called_with docker "restart intact_velociraptor"
    assert_false stub_called_with docker "compose up -d --pull never @nginx"
    assert_false stub_called_with docker "cp -p"
    assert_contains "$RUN_OUT" "OLD IP (10.0.0.5)"
    _teardown
}

# Settings writes the new domain into config.yaml, then runs the script with no
# IP change visible in config.yaml: the applied IP comes from the .env files.
test_config_written_first_is_still_an_ip_change() {
    _setup
    sed -i 's/^domain:.*/domain: 10.0.0.9/' "$CONFIG_FILE"
    _run
    assert_eq "$RUN_RC" "0"
    assert_eq "$(_env velociraptor VELOX_PUBLIC_IP)" "10.0.0.9"
    assert_true stub_called_with docker 'exec intact_velociraptor sed -i s|10\.0\.0\.5|10.0.0.9|g'
    _teardown
}

test_agent_port_backs_up_patches_and_checks() {
    _setup
    _set_ports velociraptor agent_port 9100
    _run
    assert_eq "$RUN_RC" "0"
    assert_contains "$RUN_OUT" "cut off"
    assert_eq "$(_env velociraptor VELOX_AGENT_PORT)" "9100"
    assert_eq "$(_env velociraptor VELOX_SERVER_URL)" "https://10.0.0.5:9100/"
    assert_true stub_called_with docker "exec intact_velociraptor cp -p /velociraptor/server.config.yaml /velociraptor/server.config.yaml.before-port-8000-to-9100"
    assert_contains "$(cat "$STUB_LOG")" ':8000/#\1:9100/#g'
    assert_true stub_called_with docker "exec intact_velociraptor sh -c diff"
    assert_true stub_called_with docker "restart intact_velociraptor"
    assert_true stub_called_with docker "exec intact_velociraptor grep -q :9100/"
    _teardown
}

test_agent_port_patch_touching_more_is_restored() {
    _setup
    _set_ports velociraptor agent_port 9100
    DIFF_OUT="> ca_certificate: changed"
    _run
    assert_eq "$RUN_RC" "1"
    assert_contains "$RUN_OUT" "restored the original"
    assert_true stub_called_with docker "exec intact_velociraptor cp -p /velociraptor/server.config.yaml.before-port-8000-to-9100 /velociraptor/server.config.yaml"
    assert_false stub_called_with docker "restart intact_velociraptor"
    _teardown
}

# A failed agent-port patch must put the .env back, or the box publishes the
# new port while telling agents the old one and a re-run sees nothing to do.
test_agent_port_failure_reverts_env_so_rerun_retries() {
    _setup
    _set_ports velociraptor agent_port 9100
    DIFF_OUT="> ca_certificate: changed"
    _run
    assert_eq "$RUN_RC" "1"
    assert_eq "$(_env velociraptor VELOX_AGENT_PORT)" "8000"
    assert_eq "$(_env velociraptor VELOX_SERVER_URL)" "https://10.0.0.5:8000/"
    DIFF_OUT=""; reset_stubs; _run
    assert_not_contains "$RUN_OUT" "Nothing to change"
    assert_eq "$(_env velociraptor VELOX_AGENT_PORT)" "9100"
    _teardown
}

# A taken host port makes compose fail after it removed intact_nginx: the
# dashboard must come back on the old ports and the next run must retry.
test_nginx_recreate_failure_restores_old_ports() {
    _setup
    _set_ports timesketch port 6443
    DOCKER_FAIL_ONCE="compose up -d --pull never @nginx"
    _run
    assert_eq "$RUN_RC" "1"
    assert_eq "$(_env nginx TIMESKETCH_PORT)" "5443"
    assert_eq "$(grep -c 'compose up -d --pull never @nginx' "$STUB_LOG")" "2" "brought back up"
    reset_stubs; _run
    assert_eq "$RUN_RC" "0"
    assert_eq "$(_env nginx TIMESKETCH_PORT)" "6443"
    _teardown
}

test_agent_port_without_velociraptor_is_nothing() {
    _setup
    rm "$WORK/modules/velociraptor/.env"
    sed -i 's/enabled: true/enabled: false/' "$CONFIG_FILE"
    _set_ports velociraptor agent_port 9100
    _run
    assert_eq "$RUN_RC" "0"
    assert_contains "$RUN_OUT" "Nothing to change"
    assert_eq "$(stub_call_count docker)" "0"
    _teardown
}

test_ip_and_ports_in_one_run() {
    _setup
    _set_ports timesketch port 6443 velociraptor agent_port 9100
    _run 10.0.0.9
    assert_eq "$RUN_RC" "0"
    assert_eq "$(read_config "['domain']")" "10.0.0.9"
    assert_eq "$(_env nginx TIMESKETCH_PORT)" "6443"
    assert_eq "$(_env velociraptor VELOX_SERVER_URL)" "https://10.0.0.9:9100/"
    assert_true stub_called_with docker "compose up -d --pull never @nginx"
    # IP patch first, then the port patch, so the port's diff check sees only the port move.
    local ip_line port_line
    ip_line="$(grep -n 'sed -i s|10\\.0\\.0\\.5|10.0.0.9|g' "$STUB_LOG" | head -1 | cut -d: -f1)"
    port_line="$(grep -n ':8000/#' "$STUB_LOG" | head -1 | cut -d: -f1)"
    assert_ne "$ip_line" ""
    assert_ne "$port_line" ""
    (( ${ip_line:-0} < ${port_line:-0} )) || _fail "IP patch (line $ip_line) must precede the port patch (line $port_line)"
    assert_contains "$RUN_OUT" "Timesketch:  https://10.0.0.9:6443"
    assert_contains "$RUN_OUT" "Agents:      https://10.0.0.9:9100/"
    _teardown
}

test_force_reruns_the_ip_pipeline_when_nothing_changed() {
    _setup
    _run --force
    assert_eq "$RUN_RC" "0"
    assert_not_contains "$RUN_OUT" "Nothing to change"
    assert_true stub_called_with docker "restart intact_velociraptor"
    _teardown
}

run_all_tests; _rc=$?
rm -f "$LOG_FILE"
exit $_rc
