#!/bin/bash
# Public ports set per module in config.yaml (lib/config.sh config_public_ports,
# write_public_port_env, update_env_files). scripts/change_ip.sh, which applies
# them to a running box, is covered by tests/test_change_ip_ports.sh.
#
# The defaults are load-bearing: every box upgraded from before these keys has
# none of them, and must keep the exact ports it already serves.

set -u
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./helpers.sh

LOG_FILE="$(mktemp)"
source ../lib/common.sh
source ../lib/config.sh

WORK=""
_setup() {  # _setup [extra yaml lines appended under modules.velociraptor]
    WORK="$(mktemp -d)"
    SCRIPT_DIR="$WORK"
    CONFIG_FILE="${WORK}/config.yaml"
    mkdir -p "$WORK/modules/nginx" "$WORK/modules/velociraptor" "$WORK/modules/backend" "$WORK/scripts"
    echo "NGINX_VERSION=1.31.2-alpine" > "$WORK/modules/nginx/.env"
    echo "VELOX_SERVER_URL=https://10.0.0.5:8000/" > "$WORK/modules/velociraptor/.env"
    : > "$WORK/modules/backend/.env"
    : > "$WORK/scripts/generate_clients.sh"
    cat > "$CONFIG_FILE" <<'YAML'
domain: 10.0.0.5
modules:
  elk:
    enabled: false
  velociraptor:
    enabled: true
YAML
}
_teardown() { [[ -n "$WORK" ]] && rm -rf "$WORK"; WORK=""; }

_set_ports() {  # writes the given modules.<m>.<key>: <v> triples into config.yaml
    python3 - "$CONFIG_FILE" "$@" <<'PY'
import sys, yaml
p, args = sys.argv[1], sys.argv[2:]
c = yaml.safe_load(open(p))
for i in range(0, len(args), 3):
    c["modules"].setdefault(args[i], {})[args[i + 1]] = yaml.safe_load(args[i + 2])
yaml.safe_dump(c, open(p, "w"))
PY
}

# update_env_files also stamps codex paths through docker/npm: keep the real
# daemon out of a unit test.
_update_env_files() { stub _stamp_host_codex_paths; stub docker; update_env_files </dev/null >/dev/null 2>&1; }

_env() { sed -n "s/^$2=//p" "$WORK/modules/$1/.env"; }

test_missing_keys_mean_todays_ports() {
    _setup
    assert_eq "$(config_public_ports)" "KIBANA_PORT=5602
PORTAINER_PORT=9444
IRIS_PORT=8444
TIMESKETCH_PORT=5443
VOLWEB_PORT=8002
VELOX_AGENT_PORT=8000"
    _teardown
}

test_custom_values_land_in_the_env_files() {
    _setup
    _set_ports elk kibana_port 6601 iris port "'9001'" velociraptor agent_port 9100
    _update_env_files
    assert_eq "$(_env nginx KIBANA_PORT)" "6601"
    assert_eq "$(_env nginx IRIS_PORT)" "9001" "a quoted number is accepted"
    assert_eq "$(_env nginx TIMESKETCH_PORT)" "5443" "unset key keeps its default"
    assert_eq "$(_env nginx NGINX_VERSION)" "1.31.2-alpine" "existing key untouched"
    assert_eq "$(_env velociraptor VELOX_AGENT_PORT)" "9100"
    assert_eq "$(_env velociraptor VELOX_SERVER_URL)" "https://10.0.0.5:9100/"
    assert_eq "$(grep -c KIBANA_PORT "$WORK/modules/nginx/.env")" "1"
    _teardown
}

test_bad_values_are_refused() {
    local spec
    for spec in "iris port 0" "iris port 70000" "iris port abc" "iris port true" \
                "iris port 443" "iris port 8080" "iris port 5601" \
                "iris port 5443" "volweb port 8000"; do
        _setup
        # shellcheck disable=SC2086 -- spec is three words on purpose
        _set_ports $spec
        assert_false config_public_ports
        _teardown
    done
    _setup
    _set_ports iris port 5443
    assert_contains "$(config_public_ports 2>&1 >/dev/null)" "modules.timesketch.port: 5443 is also modules.iris.port"
    _teardown
}

test_install_check_config_refuses_a_bad_port() {
    _setup
    _set_ports portainer port 80
    local out rc
    out="$(check_config 2>&1)"; rc=$?
    assert_eq "$rc" "1"
    assert_contains "$out" "modules.portainer.port: 80 is already used by the dashboard"
    out="$(INTACT_CONFIG_DOMAIN_SOFT=1 check_config 2>&1)"; rc=$?
    assert_eq "$rc" "0" "an upgrade only warns"
    _teardown
}

test_bad_config_keeps_the_current_env_ports() {
    _setup
    echo "VELOX_AGENT_PORT=9100" >> "$WORK/modules/velociraptor/.env"
    echo "IRIS_PORT=9001" >> "$WORK/modules/nginx/.env"
    _set_ports iris port 443
    _update_env_files
    assert_eq "$(_env nginx IRIS_PORT)" "9001"
    assert_eq "$(_env velociraptor VELOX_SERVER_URL)" "https://10.0.0.5:9100/"
    _teardown
}

# An upgrade runs update_env_files ADD-ONLY: a box whose ports were moved keeps
# them even when config.yaml (or a missing key's default) says otherwise, and
# only the keys it lacks are added.
test_upgrade_add_only_keeps_custom_env_ports() {
    _setup
    echo "IRIS_PORT=9001" >> "$WORK/modules/nginx/.env"
    echo "VELOX_AGENT_PORT=9100" >> "$WORK/modules/velociraptor/.env"
    sed -i 's|:8000/|:9100/|' "$WORK/modules/velociraptor/.env"
    _set_ports iris port 8444
    stub _stamp_host_codex_paths; stub docker
    UPDATE_ENV_ADD_ONLY=1 update_env_files </dev/null >/dev/null 2>&1
    assert_eq "$(_env nginx IRIS_PORT)" "9001" "custom port survives the upgrade"
    assert_eq "$(_env nginx KIBANA_PORT)" "5602" "a missing key is added"
    assert_eq "$(_env velociraptor VELOX_AGENT_PORT)" "9100"
    assert_eq "$(_env velociraptor VELOX_SERVER_URL)" "https://10.0.0.5:9100/"
    assert_eq "$(grep -c IRIS_PORT "$WORK/modules/nginx/.env")" "1"
    _teardown
}

run_all_tests; _rc=$?
rm -f "$LOG_FILE"
exit $_rc
