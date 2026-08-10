#!/bin/bash
# Intact.AI upgrade — per-module probes. Each echoes "up|degraded|down
# <detail>" for one attempt; health/core.sh's u_probe_module calls
# "_u_probe_${module}" in a loop until one says up or the timeout expires.

_u_probe_intact() {
    local code; code="$(_u_http_code "http://127.0.0.1:5001/api/health" 5)"
    [[ "$code" == "200" ]] && { echo "up backend /api/health 200"; return; }
    _u_is_running intact_backend && { echo "degraded backend running, /api/health returned ${code}"; return; }
    echo "down backend not running"
}

# ELK's verdict is Elasticsearch's cluster status, with Kibana checked by
# container state rather than HTTP -- Kibana's own healthcheck passes while it
# declines to answer on 5601, so an HTTP probe there would report a false
# outage. This mirrors what the Python probe did, for the same reason.
#
# YELLOW IS NOT AUTOMATICALLY DEGRADED. A single-node cluster with any
# replicated index sits yellow permanently and can never go green, so calling
# yellow 'degraded' would mark every single ELK upgrade degraded and train the
# operator to ignore the word. Instead it is compared against the status
# recorded BEFORE the upgrade: yellow->yellow is unchanged and therefore fine,
# green->yellow is a real regression.
_u_probe_elk() {
    local envf="${SCRIPT_DIR}/modules/elk/.env"
    local user pass status
    user="$(read_env_var "$envf" ELASTIC_USER 2>/dev/null || echo elastic)"
    pass="$(read_env_var "$envf" ELASTIC_PASSWORD 2>/dev/null || echo '')"

    status="$(curl -s --max-time 6 -u "${user}:${pass}" \
                "http://127.0.0.1:9200/_cluster/health" 2>/dev/null \
              | grep -o '"status"[[:space:]]*:[[:space:]]*"[a-z]*"' \
              | grep -o '[a-z]*"$' | tr -d '"')"

    if [[ -z "$status" ]]; then
        _u_is_running intact_elasticsearch \
            && { echo "degraded elasticsearch running but _cluster/health did not answer"; return; }
        echo "down elasticsearch not answering"; return
    fi

    case "$status" in
        green)
            _u_is_running intact_kibana && { echo "up cluster green"; return; }
            echo "degraded cluster green but kibana is not running"; return ;;
        yellow)
            if [[ "${U_ELK_BASELINE_STATUS:-}" == "yellow" ]]; then
                _u_is_running intact_kibana && { echo "up cluster yellow (unchanged from before the upgrade)"; return; }
                echo "degraded cluster yellow (as before) but kibana is not running"; return
            fi
            echo "degraded cluster yellow (was '${U_ELK_BASELINE_STATUS:-unknown}' before the upgrade)"; return ;;
        *)
            echo "down cluster status is ${status}"; return ;;
    esac
}

# timesketch-web publishes no host port and its image has no curl -- wget and
# python3 only.
_u_probe_timesketch() {
    local code; code="$(_u_http_code_in intact_timesketch_web "http://localhost:5000/" 6)"
    if [[ "$code" =~ ^(200|30[0-9]|401|403)$ ]]; then
        echo "up timesketch-web HTTP ${code}"; return
    fi
    if "${DOCKER_BIN:-docker}" exec intact_timesketch_web pgrep -f gunicorn >/dev/null 2>&1; then
        echo "degraded gunicorn is alive but HTTP returned ${code}"; return
    fi
    echo "down timesketch-web not serving (HTTP ${code})"
}

# 302 is the normal answer at / (redirect to the login page); 401 means the app
# is up and demanding auth. Both are 'serving'.
_u_probe_iris() {
    local code; code="$(_u_http_code "https://127.0.0.1:8443/" 6)"
    if [[ "$code" =~ ^(200|30[0-9]|401|403)$ ]]; then
        echo "up iris-nginx HTTP ${code}"; return
    fi
    _u_is_running intact_iris_app && { echo "degraded iris-app running, nginx returned ${code}"; return; }
    echo "down iris not serving (HTTP ${code})"
}

# The GUI answers plain HTTP on 8889 and returns 404 at / -- which still proves
# the server is up, so any completed response counts. 8001 is the gRPC frontend
# and speaks no HTTP at all, hence the raw TCP check.
_u_probe_velociraptor() {
    local code; code="$(_u_http_code "http://127.0.0.1:8889/" 6)"
    if [[ "$code" != "000" ]]; then
        if _u_tcp_open 127.0.0.1 8001 3; then
            echo "up GUI HTTP ${code}, gRPC 8001 open"; return
        fi
        echo "degraded GUI answering (HTTP ${code}) but gRPC 8001 is closed"; return
    fi
    _u_is_running intact_velociraptor && { echo "degraded container running but GUI 8889 is not answering"; return; }
    echo "down velociraptor not running"
}

# volweb-backend publishes no host port. 404 at / is normal (the SPA is served
# by the frontend container); anything below 500 means Django is answering.
_u_probe_volweb() {
    local code; code="$(_u_http_code_in intact_volweb_backend "http://localhost:8000/" 6)"
    if [[ "$code" =~ ^[1-4][0-9][0-9]$ ]]; then
        echo "up volweb-backend HTTP ${code}"; return
    fi
    _u_is_running intact_volweb_backend && { echo "degraded container running, HTTP returned ${code}"; return; }
    echo "down volweb-backend not running"
}

# Distroless: no shell to exec into, so the published port is the only probe.
_u_probe_portainer() {
    local code; code="$(_u_http_code "https://127.0.0.1:9443/" 6)"
    if [[ "$code" =~ ^(200|30[0-9])$ ]]; then
        # Portainer's agent is a root-privileged Docker API proxy; a server
        # that is up while its agent is down is a half-working install worth
        # naming rather than passing silently.
        _u_is_running intact_portainer_agent && { echo "up portainer HTTP ${code}"; return; }
        echo "degraded portainer up (HTTP ${code}) but the agent is not running"; return
    fi
    _u_is_running intact_portainer && { echo "degraded container running, HTTP returned ${code}"; return; }
    echo "down portainer not serving (HTTP ${code})"
}

# Modules with nothing to probe run under policy 'none' and never reach here,
# but define them so a typo'd policy fails loudly instead of silently passing.
_u_probe_plaso()     { echo "down plaso has no service to probe"; }
_u_probe_aws_sigma() { echo "down aws_sigma has no service to probe"; }
_u_probe_o365rc()    { echo "down o365rc has no service to probe"; }
