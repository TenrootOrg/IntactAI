#!/bin/bash
# Intact.AI upgrade — the honest health gate.
#
# u_probe_module <module> <timeout>  ->  echoes "up|degraded|down <detail>"
#
# Three verdicts, because two is a lie. "Healthy / not healthy" forces every
# normal-but-imperfect state (a single-node Elasticsearch sitting yellow
# forever, a web tier answering while a sidecar is still warming) into one
# bucket or the other, and whichever way you choose you get either false
# rollbacks or false successes. 'degraded' is the honest middle: applied,
# running, worth telling the operator about, not worth reverting.
#
# WHERE THE PROBE RUNS. Preferring the host over `docker exec` is not a
# style choice, it is forced by the images:
#
#   intact_velociraptor has no curl, no wget and no python3
#   intact_portainer has no shell at all (distroless)
#
# Both publish their port on the host, so the host probe is the only one that
# works for them -- and it is also closer to what a user experiences. Where a
# container publishes nothing (timesketch-web, volweb-backend) we exec in with
# whichever tool that image actually ships. Verified per-container rather than
# assumed; the Python probes worked around the same constraints by running
# urllib from inside the backend process.
#
# Every probe polls until <timeout>, because a module that comes up in 90s is
# not a failure. The poll is the only reason these take a timeout at all.

# Containers whose logs get captured when a gate does not return 'up'.
u_containers_of() {
    case "$1" in
        intact)       echo "intact_backend intact_nginx intact_tusd" ;;
        elk)          echo "intact_elasticsearch intact_kibana intact_logstash" ;;
        timesketch)   echo "intact_timesketch_web intact_timesketch_worker intact_timesketch_postgres intact_timesketch_opensearch" ;;
        iris)         echo "intact_iris_app intact_iris_nginx intact_iris_db intact_iris_worker" ;;
        velociraptor) echo "intact_velociraptor" ;;
        volweb)       echo "intact_volweb_backend intact_volweb_frontend intact_volweb_postgresdb" ;;
        portainer)    echo "intact_portainer intact_portainer_agent" ;;
        *)            echo "" ;;
    esac
}

# The container whose absence means "this module is not installed".
u_primary_container_of() {
    case "$1" in
        intact)       echo "intact_backend" ;;
        elk)          echo "intact_elasticsearch" ;;
        timesketch)   echo "intact_timesketch_web" ;;
        iris)         echo "intact_iris_app" ;;
        velociraptor) echo "intact_velociraptor" ;;
        volweb)       echo "intact_volweb_backend" ;;
        portainer)    echo "intact_portainer" ;;
        *)            echo "" ;;
    esac
}

# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------

# running | restarting | exited | created | absent
_u_container_state() {
    local st
    st="$("${DOCKER_BIN:-docker}" inspect -f '{{.State.Status}}' "$1" 2>/dev/null)" || { echo absent; return; }
    [[ -n "$st" ]] && echo "$st" || echo absent
}

_u_is_running() { [[ "$(_u_container_state "$1")" == "running" ]]; }

# HTTP status code from the host, or 000 if the connection never completed.
# -k because every internal listener is self-signed.
#
# NOT `curl ... || echo 000`. With -w '%{http_code}' curl PRINTS 000 on a
# failed connection AND exits non-zero, so the fallback appends a second one
# and the caller sees "000000" -- which is not equal to "000", so a dead
# service scores as reachable. Exactly that turned a Velociraptor GUI that was
# not answering into a green health verdict.
_u_http_code() {
    local out
    out="$(curl -sk -o /dev/null -w '%{http_code}' --max-time "${2:-6}" "$1" 2>/dev/null)"
    # Take only the first 3 digits, so any residual duplication cannot ever
    # masquerade as a different code.
    out="${out:0:3}"
    [[ "$out" =~ ^[0-9]{3}$ ]] && echo "$out" || echo 000
}

# Same, but from inside a container, using whichever client that image ships.
_u_http_code_in() {
    local c="$1" url="$2" t="${3:-6}"
    "${DOCKER_BIN:-docker}" exec "$c" sh -c '
        if command -v curl >/dev/null 2>&1; then
            curl -sk -o /dev/null -w "%{http_code}" --max-time '"$t"' "'"$url"'" 2>/dev/null
        elif command -v python3 >/dev/null 2>&1; then
            python3 -c "
import sys,urllib.request,ssl
ctx=ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
try:
    print(urllib.request.urlopen(sys.argv[1],timeout='"$t"',context=ctx).status)
except Exception as e:
    print(getattr(e,\"code\",0) or 0)
" "'"$url"'" 2>/dev/null
        elif command -v wget >/dev/null 2>&1; then
            wget -q --no-check-certificate --timeout='"$t"' -O /dev/null "'"$url"'" 2>/dev/null && echo 200 || echo 000
        else
            echo 000
        fi' 2>/dev/null || echo 000
}

# Bash-only TCP reachability, for a port that speaks no HTTP (velociraptor's
# gRPC frontend). Same technique as lib/common.sh:_tcp_reachable.
_u_tcp_open() {
    timeout "${3:-3}" bash -c "exec 3<>/dev/tcp/${1}/${2}" 2>/dev/null
}

# ---------------------------------------------------------------------------
# u_probe_module <module> <timeout>
# ---------------------------------------------------------------------------
u_probe_module() {
    local module="$1" timeout="${2:-150}"
    local primary deadline=$((SECONDS + timeout))
    primary="$(u_primary_container_of "$module")"

    # Fast-fail. A container that is restarting or has exited is not going to
    # become healthy by waiting out a 150s poll, and burning the full timeout
    # on a crash-loop just delays the rollback.
    if [[ -n "$primary" ]]; then
        local st; st="$(_u_container_state "$primary")"
        case "$st" in
            restarting) echo "down ${primary} is crash-looping"; return 0 ;;
            exited)     echo "down ${primary} has exited"; return 0 ;;
            absent)     echo "down ${primary} does not exist"; return 0 ;;
        esac
    fi

    local last="no probe result"
    while (( SECONDS < deadline )); do
        local out
        out="$("_u_probe_${module}" 2>/dev/null)" || out="down probe error"
        case "$out" in
            up*) echo "$out"; return 0 ;;
            *)   last="$out" ;;
        esac
        # Tunable only so the unit tests can drive the timeout path without
        # paying five real seconds per case; nothing in the product sets it.
        sleep "${U_PROBE_INTERVAL:-5}"
    done

    # Timed out. Whatever the last non-'up' verdict was, that is the answer --
    # and if it was 'degraded' it stays 'degraded'. What must NOT happen here
    # is a fall-through to success; see the honesty invariant on u_end.
    echo "$last"
    return 0
}

# ---------------------------------------------------------------------------
# Per-module probes. Each echoes "up|degraded|down <detail>" for one attempt.
# ---------------------------------------------------------------------------

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

# ---------------------------------------------------------------------------
# u_post_upgrade_gate — observe whether the platform is ACTUALLY serving,
# after every module has already committed via u_end.
#
# u_end's own probe checks its module in isolation, right after that
# module's own swap. It cannot see a container a LATER step leaves in
# `created` (compose recreated it but the start never happened), nor a
# crash-loop that starts moments after u_end's probe window already closed.
# Both are real failure shapes the Python engine this replaced was written
# to catch after shipping a run that reported "completed, 0 errors" while
# intact_tusd sat in `created` and uploads were dead until an operator ran
# `docker start` by hand.
#
# STRICTLY OBSERVATIONAL. Never fails a run, never rolls anything back, never
# touches UPGRADE_OK/UPGRADE_DEGRADED -- u_end is still the only thing that
# may commit those. The worst this does is add a line to
# INSTALL_WARNINGS/INSTALL_ERRORS, which print_final_issues_report already
# prints; today those arrays are never populated on the upgrade path at all.
#
# Scoped to containers of modules THIS RUN attempted (upgrade or install
# action) rather than every intact_* container on the box: a module nobody
# touched crash-looping for an unrelated reason is a real fact worth an
# operator's attention, but it is not evidence about THIS upgrade, and
# blaming it here would be exactly the false attribution this exists to
# avoid, not commit.
# ---------------------------------------------------------------------------
u_post_upgrade_gate() {
    local touched=() m c state
    for m in "${UPGRADE_ORDER[@]}"; do
        case "${PLAN_ACTION[$m]:-}" in
            upgrade|install) touched+=("$m") ;;
        esac
    done
    (( ${#touched[@]} )) || return 0

    log_info ""
    log_info "Post-upgrade check..."
    local checked=0
    for m in "${touched[@]}"; do
        for c in $(u_containers_of "$m"); do
            state="$(_u_container_state "$c")"
            [[ "$state" == "absent" ]] && continue
            checked=$((checked + 1))
            case "$state" in
                created)
                    log_warn "  ${c} is created but was never started — starting it now"
                    "${DOCKER_BIN:-docker}" start "$c" >/dev/null 2>&1
                    sleep 2
                    state="$(_u_container_state "$c")"
                    if [[ "$state" == "running" ]]; then
                        log_success "  ${c} is now running"
                    else
                        INSTALL_ERRORS+=("${c} was left in 'created' after the upgrade and would not start (now ${state})")
                    fi
                    ;;
                restarting)
                    INSTALL_ERRORS+=("${c} is crash-looping after the upgrade")
                    ;;
                exited)
                    local rc
                    rc="$("${DOCKER_BIN:-docker}" inspect -f '{{.State.ExitCode}}' "$c" 2>/dev/null)"
                    [[ -n "$rc" && "$rc" != "0" ]] && \
                        INSTALL_WARNINGS+=("${c} exited with code ${rc} after the upgrade")
                    ;;
            esac
        done
    done
    log_info "  ${checked} container(s) checked"

    # The backend image tag: config.yaml's versions.backend / the stamped
    # VERSION file is what every later boot resolves its image from (see
    # scripts/ci/build_release_package.py's self-check for the same class of
    # bug on the BUILD side -- a bundled image baked under the wrong tag is
    # invisible to the box that is supposed to load it). If the running
    # container is on a different tag than the plan says it upgraded to,
    # every per-step claim the intact module made about itself was true and
    # the platform is still wrong underneath them.
    local committed=0 e
    for e in "${UPGRADE_OK[@]}" "${UPGRADE_DEGRADED[@]}"; do
        [[ "$e" == "intact "* ]] && { committed=1; break; }
    done
    if (( committed )) && [[ -n "${PLAN_TARGET[intact]:-}" ]]; then
        local running_image want_image
        running_image="$("${DOCKER_BIN:-docker}" inspect -f '{{.Config.Image}}' intact_backend 2>/dev/null)"
        want_image="intact-backend:${PLAN_TARGET[intact]}"
        if [[ -n "$running_image" && "$running_image" != "$want_image" ]]; then
            INSTALL_ERRORS+=("intact_backend is running ${running_image}, expected ${want_image} — the backend did not actually swap")
        fi
    fi
    return 0
}
