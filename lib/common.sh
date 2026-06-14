#!/bin/bash
# Intact.AI Platform Installer - Common Functions
# Logging, tracking, and utility functions

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

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
    if [[ $rc -eq 124 ]]; then
        log_error "  ${description} exceeded ${timeout_secs}s timeout — killed (ran ${total_elapsed}s)"
    elif [[ $rc -eq 0 ]]; then
        # Concrete finish-time + budget headroom: helps the operator see
        # how close they ran to the timeout and decide whether the cap
        # needs to be raised again next release.
        local pct=$(( total_elapsed * 100 / timeout_secs ))
        log_info "  ${description} completed in ${total_elapsed}s (${pct}% of ${timeout_secs}s budget)"
    else
        log_info "  ${description} exited rc=$rc after ${total_elapsed}s"
    fi
    return $rc
}

# ============================================================================
# Network Connectivity Check
# ============================================================================

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

# Pre-flight GitHub REST API quota check used by install.sh + lib/upgrade_check.sh.
#
# Args:
#   $1 — needed: how many api.github.com calls this action will burn (int)
#   $2 — action: human-readable label for the log/error message
#
# Returns 0 if quota is sufficient (or fail-open when the rate_limit
# endpoint itself is unreachable — don't block on the check failing).
# Returns 1 only when GitHub reports remaining < needed, with the
# operator-actionable error printed via log_error.
#
# Honors GITHUB_TOKEN env var to authenticate the check (and to raise
# the cap from 60 to 5000/hour). The check call itself does NOT count
# against the rate limit (api.github.com/rate_limit is explicitly
# excluded by GitHub).
#
# Mirrors services/upgrade/resolver.py:check_quota_or_raise.
check_github_quota() {
    local needed=${1:-1}
    local action=${2:-"github operation"}
    local auth_header=()
    if [[ -n "${GITHUB_TOKEN:-}" ]]; then
        auth_header=(-H "Authorization: token $GITHUB_TOKEN")
    fi
    local json
    json=$(curl -sf -H "Accept: application/vnd.github.v3+json" \
        "${auth_header[@]}" --max-time 10 \
        https://api.github.com/rate_limit 2>/dev/null) || {
        log_warn "[GH-QUOTA] $action: rate-limit endpoint unreachable; proceeding without pre-flight check"
        return 0
    }
    local remaining reset
    remaining=$(echo "$json" | python3 -c \
        "import sys, json; print(json.load(sys.stdin)['resources']['core']['remaining'])" 2>/dev/null) || {
        log_warn "[GH-QUOTA] $action: rate_limit response unparseable; proceeding"
        return 0
    }
    reset=$(echo "$json" | python3 -c \
        "import sys, json; print(json.load(sys.stdin)['resources']['core']['reset'])" 2>/dev/null)
    local limit=60
    [[ -n "${GITHUB_TOKEN:-}" ]] && limit=5000
    local reset_hm reset_min
    reset_hm=$(date -d "@$reset" +%H:%M 2>/dev/null || echo "unknown")
    reset_min=$(( (reset - $(date +%s)) / 60 ))
    if [[ "$remaining" -lt "$needed" ]]; then
        log_error "GitHub rate limit too low for $action: need $needed, have $remaining/$limit."
        log_error "  Quota resets at $reset_hm (in ${reset_min} minutes)."
        if [[ -z "${GITHUB_TOKEN:-}" ]]; then
            log_error "  Set GITHUB_TOKEN env var to lift the cap from 60 → 5000/hr."
        fi
        return 1
    fi
    log_info "[GH-QUOTA] $action: needs $needed, have $remaining/$limit remaining (resets $reset_hm)"
    return 0
}
