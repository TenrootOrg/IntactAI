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

# nginx serves Kibana at /kibana/ and strips the prefix; rewriteBasePath must be
# false or Kibana stops answering at its root, which the host-side probes and
# the container healthcheck (https://localhost:5601/api/status) rely on.
test_kibana_base_path_without_rewrite() {
    local f="${M}/elk/docker-compose.yaml"
    assert_true grep -qE '^\s+- SERVER_BASEPATH=/kibana$' "$f"
    assert_true grep -qE '^\s+- SERVER_REWRITEBASEPATH=false$' "$f"
    assert_true grep -q 'https://localhost:5601/api/status' "$f"
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
