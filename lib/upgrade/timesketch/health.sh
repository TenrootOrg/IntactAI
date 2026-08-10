#!/bin/bash
# Intact.AI upgrade — Timesketch readiness wait + the data-loss sanity check.

_ts_wait_gunicorn() {
    local i
    for i in $(seq 1 60); do
        if "${DOCKER_BIN:-docker}" exec intact_timesketch_web pgrep -f gunicorn >/dev/null 2>&1; then
            return 0
        fi
        # A crash-looping stack will not settle; stop waiting the full ten
        # minutes for it.
        case "$(_u_container_state intact_timesketch_web)" in
            restarting|exited) log_error "  timesketch-web is ${_LAST:-not running}"; return 1 ;;
        esac
        sleep 5
    done
    log_error "  gunicorn did not appear in timesketch-web"
    return 1
}

# ---------------------------------------------------------------------------
# The cheap sanity check.
#
# Four numbers: users, sketches, timelines (Postgres) and total OpenSearch
# documents. The Python counted 18 tables in 19 separate psql round-trips; the
# question being answered is "did evidence disappear", and a vanished sketch or
# timeline is what that looks like. Two round-trips instead of nineteen.
# ---------------------------------------------------------------------------
_ts_counts() {
    local d="${DOCKER_BIN:-docker}" pg os
    pg="$($d exec intact_timesketch_postgres psql -U timesketch -d timesketch -tAc \
        'SELECT (SELECT count(*) FROM "user"),(SELECT count(*) FROM sketch),(SELECT count(*) FROM timeline)' \
        2>/dev/null | tr -d '[:space:]')"
    # Non-system indices only: the leading-dot ones are OpenSearch's own.
    os="$($d exec intact_timesketch_opensearch \
        curl -s --max-time 10 'localhost:9200/_cat/indices?h=index,docs.count' 2>/dev/null \
        | awk '$1 !~ /^\./ {s += $2} END {print s + 0}')"
    echo "users/sketches/timelines=${pg:-?} opensearch_docs=${os:-?}"
}

# Not-lower rather than equal: an upgrade may legitimately add rows (a
# migration backfilling a table, the app writing a login record), but nothing
# should ever DISAPPEAR.
_ts_counts_not_lower() {
    local before="$1" after="$2"
    local b_pg a_pg b_os a_os
    b_pg="${before#*=}"; b_pg="${b_pg%% *}"
    a_pg="${after#*=}";  a_pg="${a_pg%% *}"
    b_os="${before##*=}"; a_os="${after##*=}"

    if [[ "$b_pg" == "?" || "$a_pg" == "?" ]]; then
        log_warn "  could not compare Postgres counts (before='${b_pg}' after='${a_pg}')"
    else
        local i
        local -a bs as
        IFS='|' read -ra bs <<< "$b_pg"
        IFS='|' read -ra as <<< "$a_pg"
        local names=(users sketches timelines)
        for i in 0 1 2; do
            if [[ -n "${bs[i]:-}" && -n "${as[i]:-}" ]] && (( ${as[i]} < ${bs[i]} )); then
                log_error "  ${names[i]}: ${bs[i]} -> ${as[i]} (LOST ROWS)"
                return 1
            fi
        done
    fi

    if [[ "$b_os" =~ ^[0-9]+$ && "$a_os" =~ ^[0-9]+$ ]] && (( a_os < b_os )); then
        log_error "  OpenSearch documents: ${b_os} -> ${a_os} (LOST EVENTS)"
        # Worth stating rather than implying: the dump does not cover this.
        log_error "  NOTE: OpenSearch is not dumped by this upgrade. The Postgres backup"
        log_error "  cannot restore timeline events — this is detectable, not recoverable."
        return 1
    fi
    return 0
}
