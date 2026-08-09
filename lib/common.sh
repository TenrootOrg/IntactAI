#!/bin/bash
# Intact.AI Platform Installer - Common Functions
# Logging, tracking, and utility functions

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# ---------------------------------------------------------------------------
# Supported-platform matrix (host layer). IntactAI does NOT upgrade Docker or
# the host OS from inside the product (restarting dockerd mid-upgrade would
# kill the upgrader itself) — host patching is the operator's responsibility.
# Instead we PREFLIGHT the host and warn loudly with remediation, so a too-old
# Docker surfaces as a clear early message instead of a cryptic failure later.
# These checks are advisory (warn-only) — they never block install/upgrade;
# the functional checks (daemon reachable, compose v2 present) do the blocking.
# Keep in sync with the Python copy in
# modules/backend/services/upgrade/config_validate.py and docs/SUPPORTED_PLATFORMS.md.
# ---------------------------------------------------------------------------
INTACT_MIN_DOCKER_VERSION="${INTACT_MIN_DOCKER_VERSION:-20.10}"   # hard floor: compose v2 plugin era
INTACT_REC_DOCKER_VERSION="${INTACT_REC_DOCKER_VERSION:-24.0}"    # recommended
INTACT_SUPPORTED_UBUNTU="${INTACT_SUPPORTED_UBUNTU:-20.04 22.04 24.04}"

# Module tracking arrays
FAILED_MODULES=()
SUCCEEDED_MODULES=()
# Modules whose containers came up but failed end-to-end health probes after
# deploy. Populated by verify_installation() in lib/health.sh. Distinct from
# FAILED_MODULES because the deploy step succeeded — only the runtime check
# didn't. Lets the final summary distinguish "compose up failed" from
# "compose up succeeded but the service isn't actually serving requests".
UNHEALTHY_MODULES=()

# Process-wide warning / error tracking. Every log_warn / log_error call
# appends a timestamped entry here so the final installer summary can
# print a loud "ATTENTION" report listing every issue that surfaced
# anywhere during the install — without changing any function's exit
# code. Operators currently miss yellow [WARN] lines that scroll past;
# this surfaces them at the end where they can't be missed.
INSTALL_WARNINGS=()
INSTALL_ERRORS=()
declare -A INSTALL_ISSUE_SEEN=()

# Neutral end-of-install notes. Deliberately NOT warnings: these never feed
# INSTALL_WARNINGS, never reach print_final_issues_report's ATTENTION block,
# and never change print_summary's banner colour. They exist so that an
# operator — or an engineer reading install.log a year from now — learns about
# deliberate, expected behaviour that is otherwise invisible, e.g. that we
# modify a vendor container's site-packages on every start. Nothing here is a
# problem, so nothing here should look like one.
INSTALL_NOTES=()

record_install_note() {
    local message="${1:-}"
    [[ -z "$message" ]] && return 0
    INSTALL_NOTES+=("$message")
    # [NOTE], never [WARN]/[ERROR]: record_child_output_issue() strips leading
    # bracket groups and then substring-matches those two tokens, so anything
    # tagged [NOTE] is inert to that scraper by construction.
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [NOTE] ${message}" >> "$LOG_FILE"
    return 0
}

record_install_issue() {
    local severity="$1"
    local source="${2:-?}"
    local message="${3:-}"

    [[ -z "$message" ]] && return 0

    local key="${severity}|${source}|${message}"
    if [[ -n "${INSTALL_ISSUE_SEEN[$key]:-}" ]]; then
        return 0
    fi
    INSTALL_ISSUE_SEEN["$key"]=1

    case "$severity" in
        error)
            INSTALL_ERRORS+=("$(date '+%H:%M:%S') ${source}: ${message}")
            ;;
        warn|warning)
            INSTALL_WARNINGS+=("$(date '+%H:%M:%S') ${source}: ${message}")
            ;;
    esac
}

record_child_output_issue() {
    local source="${1:-child-process}"
    local line="${2:-}"
    [[ -z "$line" ]] && return 0

    local clean message
    clean=$(printf '%s\n' "$line" | sed -E 's/\x1b\[[0-9;]*m//g; s/\r$//; s/^[[:space:]]+//')
    message=$(printf '%s\n' "$clean" | sed -E 's/^([[:space:]]*\[[^]]+\][[:space:]]*)+//; s/^[[:space:]]+//')
    [[ -z "$message" ]] && return 0

    if [[ "$clean" == *"[ERROR]"* ]] \
        || [[ "$message" == *"✗ Error:"* ]] \
        || [[ "$message" == *"No such container:"* ]] \
        || [[ "$message" == *"Failed to copy config:"* ]] \
        || [[ "$message" == *"Failed to connect to Velociraptor"* ]]; then
        record_install_issue "error" "$source" "$message"
    elif [[ "$clean" == *"[WARN]"* ]] \
        || [[ "$message" == *"WARNING:"* ]] \
        || [[ "$message" == *"Connection failed"* ]] \
        || [[ "$message" == *"Max retries exceeded"* ]] \
        || [[ "$message" =~ Download[[:space:]]complete:.*[[:space:]][1-9][0-9]*[[:space:]]failed ]] \
        || [[ "$message" =~ Tools:.*[[:space:]][1-9][0-9]*[[:space:]]failed ]]; then
        record_install_issue "warn" "$source" "$message"
    fi
}

scan_child_output_for_issues() {
    local source="${1:-child-process}"
    local output_file="${2:-}"
    [[ -n "$output_file" && -s "$output_file" ]] || return 0

    local line
    while IFS= read -r line; do
        record_child_output_issue "$source" "$line"
    done < "$output_file"
}

# ============================================================================
# Logging Functions
# ============================================================================

log_info() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] $1"
    echo -e "${BLUE}[INFO]${NC} $1"
    echo "$msg" >> "$LOG_FILE"
}

log_success() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] [SUCCESS] $1"
    echo -e "${GREEN}[SUCCESS]${NC} $1"
    echo "$msg" >> "$LOG_FILE"
}

log_warn() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] [WARN] $1"
    echo -e "${YELLOW}[WARN]${NC} $1"
    echo "$msg" >> "$LOG_FILE"
    # Track for end-of-install ATTENTION report. Caller ${FUNCNAME[1]}
    # tells the operator which install step produced the warning.
    record_install_issue "warn" "${FUNCNAME[1]:-?}" "$1"
}

log_error() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] $1"
    echo -e "${RED}[ERROR]${NC} $1"
    echo "$msg" >> "$LOG_FILE"
    record_install_issue "error" "${FUNCNAME[1]:-?}" "$1"
}

# Append a tail of each named container's logs to INSTALL_ERRORS so the
# end-of-install ATTENTION report points the operator at the actual
# failure symptom — not just "X timed out". Skips silently for any
# container that doesn't exist (some modules have optional containers).
# Defined here in common.sh (sourced first) so both modules.sh deploy
# steps AND health.sh post-install probes can call it.
capture_diagnostic_logs() {
    local label="$1"
    shift
    INSTALL_ERRORS+=("--- ${label} diagnostic; container tails follow ---")
    local container
    for container in "$@"; do
        if docker ps -a --filter "name=^${container}$" --format '{{.Names}}' 2>/dev/null | grep -q .; then
            INSTALL_ERRORS+=("[$container] last 20 log lines:")
            local line
            while IFS= read -r line; do
                INSTALL_ERRORS+=("  $line")
            done < <(docker logs --tail 20 "$container" 2>&1)
        fi
    done
}

# verify_postgres_row — confirm a state-creation step actually wrote
# what it claimed. Generic across modules so any install step that
# creates a DB row can verify the row landed before logging SUCCESS.
#
# Why this exists: `tsctl create-user` can return exit code 0 while
# silently dropping the DB write — caught us when a fresh install
# reported "[SUCCESS] TimeSketch user 'tenroot' ready" but the
# postgres "user" table was empty hours later. Trust-but-verify on
# every state-write that other steps depend on.
#
# Usage:
#   verify_postgres_row intact_timesketch_postgres timesketch user "username='tenroot'"
#   verify_postgres_row intact_iris_db iris_db user "name='administrator' AND api_key IS NOT NULL"
#
# Returns 0 iff the count query yields ≥ 1. Silent — caller logs the
# outcome. pg_user defaults to the database name (timesketch/iris
# convention); pass a 5th arg if your container differs.
verify_postgres_row() {
    local container="$1"
    local db="$2"
    local table="$3"
    local where="$4"
    local pg_user="${5:-${db}}"

    local count
    count=$(docker exec "$container" psql -U "$pg_user" -d "$db" -tAc \
        "SELECT count(*) FROM \"${table}\" WHERE ${where};" 2>/dev/null \
        | tr -d '[:space:]')
    [[ "$count" =~ ^[0-9]+$ ]] && (( count >= 1 ))
}

# ============================================================================
# Module Tracking Functions
# ============================================================================

track_module_success() {
    SUCCEEDED_MODULES+=("$1")
    log_success "$1 deployed successfully"
}

track_module_failure() {
    FAILED_MODULES+=("$1")
    log_error "$1 deployment FAILED"
}

# ============================================================================
# Utility Functions
# ============================================================================

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

# Check if a value is truthy (handles yaml boolean variations)
# Usage: if is_enabled "$value"; then ...
is_enabled() {
    local val="${1,,}"  # Convert to lowercase
    [[ "$val" == "true" || "$val" == "yes" || "$val" == "1" ]]
}

# Wait for a condition with timeout (replaces fixed sleep)
# Usage: wait_for_condition "description" timeout_seconds "command to check"
wait_for_condition() {
    local description="$1"
    local timeout="$2"
    local check_cmd="$3"
    local interval="${4:-2}"  # Default 2 second interval
    local waited=0

    log_info "Waiting for ${description}..."

    while ! eval "$check_cmd" > /dev/null 2>&1; do
        if [[ $waited -ge $timeout ]]; then
            log_warn "${description} not ready after ${timeout}s"
            return 1
        fi
        sleep "$interval"
        waited=$((waited + interval))
    done

    log_success "${description} is ready (${waited}s)"
    return 0
}

# Wait for container to be running
# Usage: wait_for_container "container_name" timeout_seconds
wait_for_container() {
    local container="$1"
    local timeout="${2:-60}"

    wait_for_condition "container ${container}" "$timeout" \
        "docker ps --filter 'name=${container}' --filter 'status=running' --format '{{.Names}}' | grep -q '${container}'"
}

# Wait for the dpkg / apt lock to free before running apt commands.
# Ubuntu fresh-boot VMs run `unattended-upgrades` automatically in the
# background to install security patches — it can hold the dpkg lock
# for several minutes, racing against install.sh's apt-get calls. The
# 2026-06-16 09:18 install hit this race and aborted at "Failed to
# install Docker packages" because of:
#
#   E: Could not get lock /var/lib/dpkg/lock-frontend.
#      It is held by process 5682 (unattended-upgr)
#
# This helper polls every 5s for up to 10 min, then fails cleanly with
# a clear remediation hint. Call it BEFORE any apt-get install /
# apt-get update step. Idempotent — no-ops when the lock is already
# free (the common case).
#
# Usage: wait_for_dpkg_lock [timeout_seconds]
wait_for_dpkg_lock() {
    local max_wait="${1:-600}"
    local start=$SECONDS
    local notified=0

    while true; do
        # Check all four apt/dpkg lock files. fuser -s exits 0 when
        # ANY process holds the file open. We need all four to be
        # unheld.
        local held=0
        for lock in /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock \
                    /var/lib/apt/lists/lock /var/cache/apt/archives/lock; do
            if [[ -e "$lock" ]] && fuser -s "$lock" 2>/dev/null; then
                held=1
                break
            fi
        done

        if [[ $held -eq 0 ]]; then
            if [[ $notified -eq 1 ]]; then
                log_success "  dpkg lock free after $((SECONDS - start))s — proceeding"
            fi
            return 0
        fi

        local elapsed=$((SECONDS - start))
        if (( elapsed >= max_wait )); then
            local holder_pid=$(fuser /var/lib/dpkg/lock-frontend 2>/dev/null | tr -dc '0-9 ' | awk '{print $1}')
            local holder_cmd="unknown"
            [[ -n "$holder_pid" ]] && holder_cmd=$(ps -o comm= -p "$holder_pid" 2>/dev/null || echo unknown)
            log_error "  dpkg lock still held after ${max_wait}s — giving up"
            log_error "  Process holding lock: $holder_cmd (pid $holder_pid)"
            log_error "  Remediation: sudo systemctl stop unattended-upgrades; "
            log_error "               sudo killall apt apt-get 2>/dev/null;"
            log_error "               then re-run install.sh"
            return 1
        fi

        if [[ $notified -eq 0 ]]; then
            local holder_pid=$(fuser /var/lib/dpkg/lock-frontend 2>/dev/null | tr -dc '0-9 ' | awk '{print $1}')
            local holder_cmd="unknown"
            [[ -n "$holder_pid" ]] && holder_cmd=$(ps -o comm= -p "$holder_pid" 2>/dev/null || echo unknown)
            log_info "  Waiting for dpkg lock (held by $holder_cmd, pid $holder_pid; up to ${max_wait}s)..."
            notified=1
        elif (( elapsed > 0 && elapsed % 30 == 0 )); then
            log_info "  ...still waiting on dpkg lock (${elapsed}s elapsed)"
        fi
        sleep 5
    done
}

# Wait for HTTP endpoint to respond
# Usage: wait_for_http "url" timeout_seconds
wait_for_http() {
    local url="$1"
    local timeout="${2:-60}"

    wait_for_condition "HTTP endpoint ${url}" "$timeout" \
        "curl -sf --max-time 5 '${url}'"
}

# Run a command (e.g. `docker compose build`) with heartbeat logging and a
# hard timeout. Catches the failure mode we hit on 2026-04-29 where install.sh
# stopped writing to the log mid-Backend-build at 08:39 with no error and no
# timeout — operator had no visibility into whether the build was alive.
#
# Usage: run_with_heartbeat <description> <timeout_seconds> <command...>
# Behavior:
#   - Runs <command...> in the foreground; output streams to the log as normal.
#   - Spawns a background heartbeat that emits "[INFO] still <description>
#     (<elapsed>s elapsed)" every 60s, so silence in the build output doesn't
#     look like the script froze.
#   - If the command runs longer than <timeout_seconds>, kills it (and its
#     process group) and returns 124, matching the convention in coreutils
#     `timeout(1)`.
#   - Otherwise returns the command's own exit code.
run_with_heartbeat() {
    local description="$1"
    local timeout_secs="$2"
    shift 2

    local start_ts=$SECONDS
    local heartbeat_interval=60

    # Background heartbeat loop. Exits when its parent (the wrapping shell
    # function) goes away, but we also explicitly kill it on completion.
    (
        while sleep "$heartbeat_interval"; do
            local elapsed=$((SECONDS - start_ts))
            log_info "  ... still ${description} (${elapsed}s elapsed)"
        done
    ) &
    local heartbeat_pid=$!
    # Make sure the heartbeat dies even if we're killed/interrupted.
    # shellcheck disable=SC2064
    trap "kill ${heartbeat_pid} 2>/dev/null; trap - RETURN INT TERM" RETURN INT TERM

    # `timeout` from coreutils handles the hard kill cleanly, including the
    # process group via --foreground when invoked from a non-tty context.
    timeout --foreground "${timeout_secs}" "$@"
    local rc=$?

    kill "${heartbeat_pid}" 2>/dev/null
    wait "${heartbeat_pid}" 2>/dev/null

    local total_elapsed=$(( SECONDS - start_ts ))

    # Published for callers that print their own completion line, so the
    # duration is not lost when the one below is suppressed.
    RUN_HEARTBEAT_ELAPSED="$total_elapsed"

    if [[ $rc -eq 124 ]]; then
        log_error "  ${description} exceeded ${timeout_secs}s timeout — killed (ran ${total_elapsed}s)"
    elif [[ $rc -eq 0 ]]; then
        # Concrete finish-time + budget headroom: helps the operator see
        # how close they ran to the timeout and decide whether the cap
        # needs to be raised again next release.
        #
        # RUN_HEARTBEAT_QUIET exists because this is a GENERIC wrapper whose
        # callers often announce completion themselves. In the image-load loop
        # that produced THREE "done" lines per image -- this one, the caller's
        # log_success, and docker's own "Loaded image:" echoed from the load
        # log -- i.e. 92 lines for 23 images where 46 say the same thing. A
        # caller that reports its own success sets QUIET and folds
        # RUN_HEARTBEAT_ELAPSED into that line. Failures are never suppressed.
        if [[ "${RUN_HEARTBEAT_QUIET:-0}" != "1" ]]; then
            local pct=$(( total_elapsed * 100 / timeout_secs ))
            log_info "  ${description} completed in ${total_elapsed}s (${pct}% of ${timeout_secs}s budget)"
        fi
    else
        log_info "  ${description} exited rc=$rc after ${total_elapsed}s"
    fi
    return $rc
}

# ============================================================================
# Network Connectivity Check
# ============================================================================

# Return 0 if version $1 >= version $2 (dotted numeric compare via sort -V).
_ver_ge() {
    [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1)" = "$2" ]
}

# Advisory Docker Engine version preflight. Warns (never blocks) when the
# running daemon is below the supported floor / recommended version, with a
# clear remediation hint. Call AFTER docker is present (post-install_docker on
# the fresh path; the already-installed branch has it too). No-op if the docker
# CLI or daemon is unavailable — install_docker / the functional checks own that.
check_docker_min_version() {
    command -v docker &> /dev/null || return 0
    local ver
    ver=$(docker version --format '{{.Server.Version}}' 2>/dev/null)
    [[ -z "$ver" ]] && return 0   # daemon not responding — not this check's job
    local core="${ver%%-*}"       # strip any -ce/-ee suffix
    if ! _ver_ge "$core" "$INTACT_MIN_DOCKER_VERSION"; then
        log_warn "Docker $ver is below the supported floor ($INTACT_MIN_DOCKER_VERSION+)."
        log_warn "  IntactAI drives everything through Docker Compose v2 — upgrade Docker:"
        log_warn "  https://docs.docker.com/engine/install/ubuntu/  (see docs/SUPPORTED_PLATFORMS.md)"
    elif ! _ver_ge "$core" "$INTACT_REC_DOCKER_VERSION"; then
        log_warn "Docker $ver works but $INTACT_REC_DOCKER_VERSION+ is recommended (see docs/SUPPORTED_PLATFORMS.md)."
    else
        log_success "Docker version: $ver (>= $INTACT_REC_DOCKER_VERSION recommended)"
    fi
    return 0
}

check_network_connectivity() {
    log_info "Checking network connectivity..."
    local has_issues=false

    # Test 1: Can we reach the internet at all? (IP connectivity)
    if ! ping -c 1 -W 3 8.8.8.8 &> /dev/null; then
        log_error "No internet connectivity (cannot ping 8.8.8.8)"
        log_error "Please check your network configuration"
        return 1
    fi
    log_success "Internet connectivity: OK"

    # Test 2: Does DNS resolution work?
    if ! ping -c 1 -W 3 google.com &> /dev/null; then
        log_error "DNS resolution not working (cannot resolve google.com)"
        log_error "Please configure DNS in /etc/resolv.conf"
        log_error "Quick fix: echo 'nameserver 8.8.8.8' | sudo tee /etc/resolv.conf"
        has_issues=true
    else
        log_success "DNS resolution: OK"
    fi

    # Test 3: Can we reach Docker's download server?
    if ! curl -sf --max-time 5 -o /dev/null https://download.docker.com 2>/dev/null; then
        log_error "Cannot reach download.docker.com"
        if command -v docker &> /dev/null; then
            log_warn "Docker is already installed, continuing..."
        else
            log_error "Docker installation will fail without access to download.docker.com"
            has_issues=true
        fi
    else
        log_success "Docker download server: Reachable"
    fi

    if [[ "$has_issues" == "true" ]]; then
        log_error "Network issues detected - installation may fail"
        return 1
    fi

    return 0
}

# ============================================================================
# Installation Marker Functions
# ============================================================================

check_initialization_marker() {
    local marker="/etc/intact-initialized"
    if [[ -f "$marker" ]]; then
        log_warn "Intact.AI was previously initialized on this system"
        cat "$marker"
        echo ""
        read -p "Re-initialize? This will reconfigure services. (y/N): " confirm
        if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
            log_info "Installation cancelled by user"
            exit 0
        fi
    fi
}

create_initialization_marker() {
    local marker="/etc/intact-initialized"
    local domain=$(read_config "['domain']")
    echo "Intact.AI Platform initialized on $(date)" > "$marker"
    echo "Domain: $domain" >> "$marker"
    log_info "Created initialization marker: $marker"
}

# ============================================================================
# Config Template Rendering
# ============================================================================
#
# render_config_from_template — copy <template> -> <out> on first install,
# substituting __PLACEHOLDER__ tokens with values pulled from the env. Used
# for tracked config files that need to hold a secret at runtime but must
# not have the secret committed to git.
#
# Idempotent: skips render when <out> already exists. The operator can
# hand-edit <out> after install — re-running the script will not clobber
# their changes.
#
# Args:
#   $1 — template path (must end in .template)
#   $2 — output path (the runtime config the container reads)
#   $3 — placeholder token (e.g. __TIMESKETCH_GOOGLE_AI_STUDIO_KEY__)
#   $4 — env var to substitute in (the value), defaulting to empty if unset
#
# Empty substitution is intentional: a missing API key disables that
# specific provider in timesketch but everything else still works.
render_config_from_template() {
    local template="$1"
    local out="$2"
    local placeholder="$3"
    local env_var="$4"

    if [[ ! -f "$template" ]]; then
        log_warn "Config template missing: $template — skipping render"
        return 1
    fi

    if [[ -f "$out" ]]; then
        log_info "  Config already rendered: $out (skipping; edit by hand to update)"
        return 0
    fi

    local value="${!env_var:-}"
    cp "$template" "$out"
    sed -i "s|${placeholder}|${value}|g" "$out"
    if [[ -n "$value" ]]; then
        log_success "  Rendered $out from template (with ${env_var})"
    else
        log_info "  Rendered $out from template (placeholder for ${env_var} left empty — provider disabled)"
    fi
}

