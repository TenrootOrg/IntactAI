#!/bin/bash
# nginx.conf is the one file that takes the whole dashboard down if it is wrong,
# and an upgrade cannot repair it (it reverts nginx's image version, not its
# config). So: both configs must pass nginx's own check in the real image, and a
# broken nginx.conf must make nginx start on nginx-safe.conf instead of dying.
#
# The docker parts need a docker daemon and the pinned nginx image; they skip
# (not fail) where neither is available, e.g. a laptop without docker.

set -u
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./helpers.sh

NGX_DIR="$(cd ../modules/nginx && pwd)"
COMPOSE="${NGX_DIR}/docker-compose.yaml"
# The version installs and upgrades actually run: config.yaml versions.nginx
# (lib/config.sh stamps it into the module .env).
IMAGE="nginx:$(grep -oP "^\s+nginx:\s+'\K[^']+" ../config.yaml 2>/dev/null \
    || grep -oP 'image: nginx:\$\{NGINX_VERSION:-\K[^}]+' "$COMPOSE")"

_docker_ready() {
    docker info >/dev/null 2>&1 || return 1
    docker image inspect "$IMAGE" >/dev/null 2>&1 && return 0
    timeout 120 docker pull -q "$IMAGE" >/dev/null 2>&1
}

CERTS=""
_certs() {
    [[ -n "$CERTS" ]] && return 0
    CERTS="$(mktemp -d)"
    openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=t" \
        -keyout "${CERTS}/k" -out "${CERTS}/c" >/dev/null 2>&1
    chmod 644 "${CERTS}/k"
}

# nginx -t on one config file, mounted where the real container mounts it.
_nginx_t() {
    _certs
    docker run --rm -v "$1:/etc/nginx/nginx.conf:ro" \
        -v "${CERTS}/c:/etc/nginx/cert.crt:ro" -v "${CERTS}/k:/etc/nginx/cert.key:ro" \
        "$IMAGE" nginx -t >/dev/null 2>&1
}

test_compose_checks_the_config_and_falls_back() {
    local c; c="$(cat "$COMPOSE")"
    assert_contains "$c" "nginx -t -q" "startup checks nginx.conf first"
    assert_contains "$c" "nginx -c /etc/nginx/nginx-safe.conf" "falls back to the safe config"
    assert_contains "$c" "./config/nginx-safe.conf:/etc/nginx/nginx-safe.conf:ro" "safe config is mounted"
    assert_true test -s "${NGX_DIR}/config/nginx-safe.conf"
}

test_safe_config_keeps_the_essentials() {
    local s; s="$(cat "${NGX_DIR}/config/nginx-safe.conf")"
    local loc
    for loc in "location = /api/auth/verify" "location /api/" "location /velociraptor/" \
               "location /api/uploads/" "listen 443 ssl" "listen 80"; do
        assert_contains "$s" "$loc" "safe config has: $loc"
    done
}

# One top-level server block of nginx.conf, picked by its listen line.
_server_block() {
    python3 - "$1" "${NGX_DIR}/config/nginx.conf" <<'EOF'
import sys
needle, path = sys.argv[1], sys.argv[2]
for block in open(path).read().split("\n    server {")[1:]:
    if needle in block:
        print(block)
EOF
}

# Every web tool is reached through this nginx, on its own port (its own
# browser origin) and only behind the Intact login.
test_every_proxied_tool_is_gated() {
    local main
    main="$(_server_block "listen 443 ssl")"
    # Path-mounted tools would share the dashboard's origin (cookies, storage).
    assert_not_contains "$main" "location /kibana/" "no /kibana/ path on 443"
    assert_not_contains "$main" "location /portainer/" "no /portainer/ path on 443"

    local port blk
    for port in 5602 9444 8444 5443 8002; do
        blk="$(_server_block "listen ${port} ssl")"
        assert_contains "$blk" "location = /__intact_auth_verify" "${port} has its own verify location"
        assert_contains "$blk" "internal;" "${port} verify location is internal"
        assert_contains "$blk" "auth_request /__intact_auth_verify;" "${port} is gated"
        assert_contains "$blk" 'return 302 https://$host/login.html?reason=expired;' "${port} redirects to the 443 login"
    done
    for port in 5602 9444 8444 5443; do
        blk="$(_server_block "listen ${port} ssl")"
        assert_contains "$blk" "Strict-Transport-Security" "${port} sends HSTS"
        assert_contains "$blk" 'proxy_set_header Host $http_host;' "${port} passes Host with the port"
    done
    for port in 9444 8444 5443; do
        assert_contains "$(_server_block "listen ${port} ssl")" 'proxy_set_header Upgrade $http_upgrade;' "${port} passes WebSocket upgrades"
    done
    assert_contains "$(_server_block "listen 5602 ssl")" 'proxy_pass https://$kibana_upstream$request_uri;' "5602 proxies Kibana at its root"
    assert_contains "$(_server_block "listen 5602 ssl")" '"intact_kibana:5601"' "5602 proxies to Kibana"
    assert_contains "$(_server_block "listen 9444 ssl")" 'proxy_pass https://$portainer_upstream$request_uri;' "9444 proxies Portainer at its root"
    assert_contains "$(_server_block "listen 9444 ssl")" '"intact_portainer:9443"' "9444 proxies to Portainer"
    assert_contains "$(_server_block "listen 8444 ssl")" '"intact_iris_nginx:8443"' "8444 proxies to IRIS"
    assert_contains "$(_server_block "listen 5443 ssl")" '"intact_timesketch_nginx:5000"' "5443 proxies to Timesketch"

    # A literal hostname or upstream block would stop nginx starting when the
    # module is not installed.
    assert_false grep -qE '^\s*upstream\s' "${NGX_DIR}/config/nginx.conf"
}

# Kibana is back at its root: a leftover base path would make it write
# /kibana/ links that nothing serves any more.
test_kibana_has_no_base_path() {
    assert_false grep -qE -- "- SERVER_(REWRITE)?BASEPATH=" ../modules/elk/docker-compose.yaml
    assert_contains "$(cat ../modules/elk/docker-compose.yaml)" '"127.0.0.1:5601:5601"' "Kibana's own port stays box-only"
}

# Only the host side of each publish is configurable, defaulting to the
# built-in port, so a box with no port keys in config.yaml or .env is unchanged.
test_compose_publishes_configurable_host_ports() {
    local c pub
    c="$(cat "$COMPOSE")"
    for pub in '"${KIBANA_PORT:-5602}:5602"' '"${PORTAINER_PORT:-9444}:9444"' \
               '"${IRIS_PORT:-8444}:8444"' '"${TIMESKETCH_PORT:-5443}:5443"' \
               '"${VOLWEB_PORT:-8002}:8002"' '"80:80"' '"8080:8080"' '"443:443"'; do
        assert_contains "$c" "$pub" "compose publishes $pub"
    done
}

test_both_configs_pass_nginx_t() {
    _docker_ready || { echo "  (skipped: no docker or no ${IMAGE})"; return 0; }
    assert_true _nginx_t "${NGX_DIR}/config/nginx.conf"
    assert_true _nginx_t "${NGX_DIR}/config/nginx-safe.conf"
}

test_broken_config_starts_on_the_safe_one() {
    _docker_ready || { echo "  (skipped: no docker or no ${IMAGE})"; return 0; }
    _certs
    local w name cmd up="" logs
    w="$(mktemp -d)"; name="intact-nginx-test-$$"
    printf 'events {}\nhttp { this_is_not_a_directive; }\n' > "${w}/broken.conf"
    # The real startup command, read from the compose file, not a copy of it.
    cmd="$(python3 -c 'import sys,yaml; print(yaml.safe_load(open(sys.argv[1]))["services"]["nginx"]["command"][2])' "$COMPOSE")"
    docker run -d --name "$name" -v "${w}/broken.conf:/etc/nginx/nginx.conf:ro" \
        -v "${NGX_DIR}/config/nginx-safe.conf:/etc/nginx/nginx-safe.conf:ro" \
        -v "${CERTS}/c:/etc/nginx/cert.crt:ro" -v "${CERTS}/k:/etc/nginx/cert.key:ro" \
        "$IMAGE" /bin/sh -c "$cmd" >/dev/null 2>&1
    for _ in $(seq 1 20); do
        up="$(docker exec "$name" sh -c 'wget -qS -O /dev/null http://127.0.0.1:80/ 2>&1 | head -1' 2>/dev/null)"
        [[ -n "$up" ]] && break; sleep 0.5
    done
    logs="$(docker logs "$name" 2>&1)"
    docker rm -f "$name" >/dev/null 2>&1; rm -rf "$w"
    assert_contains "$logs" "starting the SAFE config" "says it fell back"
    assert_contains "$up" "301" "safe nginx answers (port 80 redirects to https)"
}

run_all_tests; _rc=$?
[[ -n "$CERTS" ]] && rm -rf "$CERTS"
exit $_rc
