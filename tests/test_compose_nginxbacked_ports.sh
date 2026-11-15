#!/bin/bash
# Every web UI is served through the main nginx (login-gated), so the module
# ports must be published on 127.0.0.1 only -- never removed, because every
# install and upgrade probe (including old engines and rollbacks) still calls
# 127.0.0.1:<port> from the host. A plain "P:P" mapping re-opens the service to
# the LAN around the login gate.

set -u
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./helpers.sh

M="$(cd ../modules && pwd)"

_assert_loopback() {  # file port
    local f="${M}/$1" p="$2"
    assert_contains "$(cat "$f")" "\"127.0.0.1:${p}:${p}\"" "$1 publishes ${p} on loopback"
    assert_false grep -qE "^\s*-\s*\"?${p}:${p}\"?\s*$" "$f"
}

test_web_ports_are_loopback_only() {
    _assert_loopback elk/docker-compose.yaml 9200
    _assert_loopback elk/docker-compose.yaml 5601
    _assert_loopback portainer/docker-compose.yaml 9443
    _assert_loopback iris/docker-compose.yaml 8443
    _assert_loopback timesketch/docker-compose.yaml 5000
}

# Kibana sits at the root of its own nginx port (its own browser origin), so
# no basePath: a /kibana/ prefix would 404 every asset through nginx. The
# container healthcheck still probes the root on 5601.
test_kibana_has_no_base_path() {
    local f="${M}/elk/docker-compose.yaml"
    assert_false grep -qE '^\s+- SERVER_(BASEPATH|REWRITEBASEPATH)=' "$f"
    assert_true grep -q 'https://localhost:5601/api/status' "$f"
}

# The public ports are per module in config.yaml, but only the HOST side: nginx
# listens on fixed container ports so nginx.conf never changes per box, and the
# defaults are the old ports so an upgraded box without the keys is unchanged.
test_public_ports_host_side_configurable() {
    local n v
    n="$(cat "${M}/nginx/docker-compose.yaml")"
    for m in KIBANA_PORT:-5602:5602 PORTAINER_PORT:-9444:9444 IRIS_PORT:-8444:8444 \
             TIMESKETCH_PORT:-5443:5443 VOLWEB_PORT:-8002:8002; do
        assert_contains "$n" "\"\${${m%:*}}:${m##*:}\"" "nginx publishes ${m}"
    done
    v="$(cat "${M}/velociraptor/docker-compose.yaml")"
    assert_contains "$v" '"${VELOX_AGENT_PORT:-8000}:8000"' "velociraptor agent port"
}

test_portainer_has_no_base_url() {
    assert_false grep -qE -- '^\s+--base-url' "${M}/portainer/docker-compose.yaml"
}

# New installs get an https public_url (browsers reach the GUI only through
# nginx on 443). Existing configs are deliberately NOT rewritten: server.config.yaml
# holds the Velociraptor CA, and a cosmetic link protocol is not worth editing it
# on every box at start-up.
test_velociraptor_public_url_https_only_for_new_configs() {
    local ep="${M}/velociraptor/entrypoint.sh"
    assert_true grep -q '"public_url": "https://' "$ep"
    assert_false grep -qE 'sed -i.*public_url' "$ep"
}

run_all_tests
