#!/bin/bash
# Intact.AI upgrade — the honest health gate: container attribution, the
# low-level probe primitives, and the polling loop that turns a per-module
# probe function into a verdict.
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
#
# Sibling files: probes.sh (the actual per-module up/degraded/down logic this
# file's u_probe_module dispatches to), gate.sh (the post-upgrade sweep).

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

# Containers in <module>'s compose project that are stuck in a restart loop.
#
# Deliberately NOT built from u_containers_of: that list is hand-maintained and
# incomplete, which is exactly how this was missed. timesketch lists four
# containers and omits intact_timesketch_nginx, so an install whose nginx was
# crash-looping on a bad certificate still reported
#
#   health: timesketch is UP (timesketch-web HTTP 200)
#   install completed with 0 error(s)
#
# with the module's own front door down. Docker's compose-project label is
# authoritative and covers containers nobody remembered to add to the list.
#
# Unknown or unlabelled projects yield nothing, so a module whose containers are
# not compose-managed simply keeps its previous verdict rather than failing.
u_crashlooping_of() {
    local module="$1" d="${DOCKER_BIN:-docker}"
    $d ps -a --filter "label=com.docker.compose.project=${module}" \
           --filter "status=restarting" --format '{{.Names}}' 2>/dev/null | tr '\n' ' '
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
# u_module_is_present <module>  -- 0 present, 1 absent, 2 cannot tell.
#
# "Is this module on the box?", answered by looking at the box rather than by
# consulting a declared flag. Seven of the ten modules run a container, and for
# those the container's existence IS the answer -- `docker inspect` succeeds for
# a stopped or crashed one and fails only when it was never created or has been
# removed, which is exactly the distinction wanted.
#
# The other three are not services and have no container to look at:
#
#   plaso      an image pulled per job
#   o365rc     an image the backend runs on demand
#   aws_sigma  a rule pack on disk, no image at all
#
# For those the .env pin cannot stand in: a full package seeds pins for every
# module it carries, including ones the operator never installed, so a pin
# proves only that a package went past -- which is the case the comment in
# plan_current_versions already warns about.
#
# 2 = CANNOT TELL is a real answer, not a failure. aws_sigma's rules live at
# /opt/sigma-rules on the HOST, and the dashboard runs this engine in a helper
# container that mounts only the docker socket and the appliance checkout -- so
# a path probe there would report "absent" from the UI and "present" from a
# shell, for the same box. That is the trap preflight_host_check's systemd probe
# already documents. Better to say the question was not answerable than to
# answer it differently depending on who asked.
# ---------------------------------------------------------------------------
u_module_is_present() {
    local m="$1" primary
    primary="$(u_primary_container_of "$m")"
    if [[ -n "$primary" ]]; then
        "${DOCKER_BIN:-docker}" inspect "$primary" >/dev/null 2>&1 && return 0
        return 1
    fi

    # Image-backed modules. `docker images -q <repo>` is tag-agnostic on
    # purpose: during an upgrade the tag on disk is the OLD one, and the
    # question is whether the module is here at all, not whether it is current.
    # Answered over the docker socket, which the helper container does mount --
    # so this reads the same from a shell and from the dashboard.
    local repo=""
    case "$m" in
        plaso)  repo="log2timeline/plaso" ;;
        o365rc) repo="anssi/dfir-o365rc" ;;
    esac
    if [[ -n "$repo" ]]; then
        [[ -n "$("${DOCKER_BIN:-docker}" images -q "$repo" 2>/dev/null)" ]] && return 0
        return 1
    fi

    # aws_sigma: host filesystem only.
    if [[ "$m" == "aws_sigma" ]]; then
        if [[ -f /.dockerenv ]] || grep -qa 'docker\|containerd' /proc/1/cgroup 2>/dev/null; then
            return 2
        fi
        compgen -G "/opt/sigma-rules/rules/cloud/aws/*.yml" >/dev/null 2>&1 && return 0
        return 1
    fi
    return 2
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
