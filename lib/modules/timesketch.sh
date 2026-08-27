#!/bin/bash
# Intact.AI Platform Installer — TimeSketch module.

# We modify a vendor container. Say so, once, where someone will find it.
#
# TimeSketch ships as an image we do not build, so the only way to add an LLM
# provider is to write into the running container's site-packages. That is a
# legitimate thing to do and it is fully automatic, but it is exactly the kind
# of invisible behaviour that costs somebody a day of debugging after an
# upstream change. This is that day's head start.
#
# Recorded as a NOTE, never a warning: record_install_note() does not feed
# INSTALL_WARNINGS, so this cannot colour the summary banner or land in the
# ATTENTION block. Nothing is wrong. The wording also deliberately avoids
# every token record_child_output_issue() scrapes for ("WARNING:", "[WARN]",
# "[ERROR]", ...) so it stays inert even if that scanner gains call sites.
record_timesketch_llm_provider_note() {
    record_install_note "\
${YELLOW}TimeSketch container modification — expected, by design${NC}

  IntactAI adds two LLM provider modules to the vendor TimeSketch image:
    openrouter, litellm_proxy

  On every container start, a prologue in
  modules/timesketch/docker-compose.yaml copies them into the container's
  Python site-packages under
    timesketch/lib/llms/providers/contrib/
  and appends two guarded import lines to that package's __init__.py.

  Source of truth: modules/timesketch/llm_providers/ (bind-mounted read-only)
  Scope:           the container's writable layer only. Nothing on this host
                   is changed, and the edit is re-applied automatically on
                   every up / recreate / restart.
  Fail-safe:       if anything goes wrong the prologue logs it and TimeSketch
                   starts unmodified. To see what it decided:
                     docker exec intact_timesketch_web \\
                       cat /var/log/timesketch/intact_llm_providers.log

  This is recorded so that a future TimeSketch upgrade which changes
  timesketch/lib/llms/providers/ is understood rather than debugged from
  scratch. CI checks upstream for exactly that change on every release build
  (scripts/ci/check_timesketch_provider_drift.py). No action is needed now."
}

# Create (or confirm) the TimeSketch admin user from config.yaml's
# modules.timesketch.id/password. Idempotent -- tsctl's "already exists" is
# treated the same as a fresh create, so this is safe to call on every
# deploy, not only the first.
#
# Extracted out of deploy_timesketch so scripts/upgrade.sh's install case (a
# module enabled but never before deployed) can call the SAME user-creation
# instead of shipping a running TimeSketch with no way to log into it --
# nothing in the upgrade path has ever created a user; only this did.
#
# Returns 0 once the user row is verified in postgres, 1 if creation never
# succeeded after retrying -- matching deploy_timesketch's own original
# behaviour, where a failed user-creation does not fail the deploy, it just
# skips the DFIQ/timeout niceties that used to be gated on it.
create_timesketch_admin_user() {
    local ts_user=$(read_config "['modules']['timesketch']['id']")
    local ts_pass=$(read_config "['modules']['timesketch']['password']")

    # STEP A — Wait until the postgres "user" table actually exists.
    # The Timesketch container image doesn't ship Alembic migrations
    # (no /migrations directory), so `tsctl db upgrade` is a no-op that
    # prints a misleading ERROR. The schema is auto-created by the web
    # container's own startup (SQLAlchemy create_all), so we just poll
    # until the user table is visible before attempting create-user.
    log_info "  Waiting for TimeSketch postgres 'user' table to materialize..."
    local table_wait=0
    local table_ready=false
    while (( table_wait < 60 )); do
        local has_table
        has_table=$(docker exec intact_timesketch_postgres psql -U timesketch -d timesketch -tAc \
            "SELECT to_regclass('public.\"user\"');" 2>/dev/null | tr -d '[:space:]')
        # to_regclass returns "user" when the table exists, empty/NULL when it doesn't.
        if [[ -n "$has_table" && "$has_table" != "NULL" ]]; then
            table_ready=true
            log_success "  TimeSketch 'user' table is present (${table_wait}s)"
            break
        fi
        sleep 2
        ((table_wait+=2))
    done
    if [[ "$table_ready" != "true" ]]; then
        log_error "  TimeSketch postgres 'user' table did not appear after 60s — schema auto-create may have failed"
        log_error "  Manual diagnosis: docker exec intact_timesketch_postgres psql -U timesketch -d timesketch -c \"SELECT to_regclass('public.\\\"user\\\"');\""
        capture_diagnostic_logs "TimeSketch schema bring-up" \
            intact_timesketch_web intact_timesketch_postgres
    fi

    log_info "  Creating TimeSketch user: ${ts_user}"

    # STEP C — Now create the user. With migrations already applied
    # this is no longer racing the schema. We still verify the row
    # actually persisted before trusting tsctl's exit code (belt-and-
    # suspenders — tsctl has been observed exiting 0 even when the
    # write was rolled back by a transient).
    local ts_user_created=false
    local ts_retry=0
    local ts_max_retry=5
    local ts_error=""

    while [[ $ts_retry -lt $ts_max_retry ]]; do
        ts_error=$(docker exec intact_timesketch_web tsctl create-user "${ts_user}" --password "${ts_pass}" 2>&1)
        local ts_exit_code=$?

        # tsctl said it worked OR said the user already exists — either
        # way, only believe it if the DB actually has the row.
        if [[ $ts_exit_code -eq 0 ]] || echo "$ts_error" | grep -qi "already exists"; then
            if verify_postgres_row intact_timesketch_postgres timesketch user "username='${ts_user}'"; then
                ts_user_created=true
                break
            fi
            log_info "  tsctl reported success but '${ts_user}' is not in postgres yet — retrying"
        fi

        ((ts_retry++))
        if [[ $ts_retry -lt $ts_max_retry ]]; then
            log_info "  Retrying user creation... (attempt ${ts_retry}/${ts_max_retry})"
            sleep 10
        fi
    done

    if [[ "$ts_user_created" != "true" ]]; then
        return 1
    fi

    # STEP D — Enable + verify enable. enable-user can also silently
    # no-op when the row was just written and the cache is stale.
    docker exec intact_timesketch_web tsctl enable-user "${ts_user}" >/dev/null 2>&1 || true
    if verify_postgres_row intact_timesketch_postgres timesketch user "username='${ts_user}' AND active=true"; then
        log_success "  TimeSketch user '${ts_user}' ready (verified active in DB)"
    else
        log_warn "  TimeSketch user '${ts_user}' exists but is not marked active — sketches/uploads may be denied"
        log_warn "  Manual fix: docker exec intact_timesketch_web tsctl enable-user ${ts_user}"
    fi
    return 0
}

# Render timesketch.conf / timesketch_legacy.conf from their .template
# files, if they are not already present. Idempotent: an existing conf is
# left untouched (post-install edits, manual or via the Settings UI,
# survive), so this is a no-op on every deploy past the first.
#
# Reads the postgres password FROM secrets/postgres.env rather than
# generating one itself -- that file's generation is the caller's job
# (deploy_timesketch's own inline block; _ts_ensure_postgres_password in
# lib/upgrade/timesketch.sh for the upgrade path), and duplicating it here
# would risk the two falling out of sync.
#
# Extracted out of deploy_timesketch for the same reason as
# create_timesketch_admin_user above: a module enabled but never before
# deployed has neither conf file (both are gitignored), and compose
# bind-mounts them -- without this, "start timesketch" would hit the same
# Docker-fabricates-an-empty-directory failure the intact module's own
# mount-asset delivery already guards against for OTHER files.
render_timesketch_conf_templates() {
    local dir="${SCRIPT_DIR}/modules/timesketch"
    local pgenv="${dir}/secrets/postgres.env"
    local ts_pg_pass=""
    [[ -f "$pgenv" ]] && ts_pg_pass="$(sed -n 's/^POSTGRES_PASSWORD=//p' "$pgenv" | head -1)"

    local base
    for base in timesketch.conf timesketch_legacy.conf; do
        local ts_template="${dir}/config/${base}.template"
        local ts_out="${dir}/config/${base}"
        if [[ -f "$ts_out" ]]; then
            log_info "  ${base} already present (skip)"
            continue
        fi
        if [[ ! -f "$ts_template" ]]; then
            log_warn "  Template missing: $ts_template"
            continue
        fi
        cp "$ts_template" "$ts_out"
        # SECRET_KEY signs Timesketch's Flask session cookies and CSRF
        # tokens — anyone with the value can forge any user's session,
        # so it must be unique per install. Templates ship with a
        # __SECRET_KEY__ placeholder; we replace it with 32 random
        # bytes here, mirroring the IRIS_SECRET_KEY pattern.
        local random_key
        random_key=$(openssl rand -hex 32)
        sed -i "s|^SECRET_KEY = '[^']*'|SECRET_KEY = '${random_key}'|" "$ts_out"
        # The template ships the DB URI with the literal timesketch:timesketch
        # credential. Point it at the generated password, or the app cannot
        # authenticate to its own database now that the default is gone.
        if [[ -n "$ts_pg_pass" ]]; then
            sed -i "s|postgresql://timesketch:[^@]*@|postgresql://timesketch:${ts_pg_pass}@|" "$ts_out"
        fi
        log_success "  ${base} created from template (api_key empty — set via Settings → Timesketch; SECRET_KEY + DB password randomized)"
    done
    return 0
}

# Remove the flood/heavyweight analyzers from an EXISTING timesketch.conf's
# AUTO_SKETCH_ANALYZERS list. The template already ships the curated set, but
# render_timesketch_conf_templates deliberately never touches an existing conf
# (post-install edits survive) -- so without this, every appliance installed
# before the curation keeps the old 15-analyzer list forever. Same idempotent
# sed-on-live-conf pattern as the DFIQ_ENABLED enable below: deleting a line
# that is not there is a no-op, so re-running on every deploy is safe.
#
# Why these four (measured 2026-08-27 on a real 380k-event import):
#   chain / similarity_scorer / sessionizer -- session & similarity tag floods
#     with no detection value for fusion.
#   sigma -- cannot fire at all. plaso's EVTX parser emits no named Windows
#     fields (Image, CommandLine, ParentImage), which is what sigma rules match
#     on. Measured against 79,019 real attack events with 53 stable SigmaHQ
#     rules loaded: 53 sessions DONE, ZERO tags, 0/53 rules satisfiable. It also
#     costs one session PER RULE per timeline. Sigma detection lives in the
#     Velociraptor/Hayabusa path, which parses EVTX properly.
#   feature_extraction -- writes attributes rather than detection tags. Note it
#     returns anyway as a declared DEPENDENCY of `domain` and `account_finder`
#     (analyzers/manager.py:_build_dependencies), so this removes 3 sessions,
#     not 47. Keeping `domain` is still right: `rare-domain` is a real
#     detection and one of only four tags a Windows timeline produced.
# Fusion selects TimeSketch events BY TAG, and the workflow now waits for the
# analyzer set to finish before the run completes -- so every extra analyzer
# here is both noise in the case graph and minutes on the pipeline's tail.
curate_timesketch_analyzers() {
    local conf
    for conf in "${SCRIPT_DIR}/modules/timesketch/config/timesketch.conf" \
                "${SCRIPT_DIR}/modules/timesketch/config/timesketch_legacy.conf"; do
        [[ -f "$conf" ]] || continue
        local dropped
        dropped=$(grep -cE "^\s*'[a-z_]+',?\s*$" "$conf" || true)
        if [[ "${dropped:-0}" -gt 0 ]]; then
            sed -i -E "/^\s*'[a-z_]+',?\s*$/d" "$conf"
            log_success "  Curated AUTO_SKETCH_ANALYZERS in $(basename "$conf") (emptied AUTO_SKETCH_ANALYZERS: ${dropped} entr(y/ies) removed; the appliance schedules per-timeline instead)"
        fi
    done
    return 0
}

deploy_timesketch() {
    local ts_enabled=$(read_config "['modules']['timesketch']['enabled']")
    if ! is_enabled "$ts_enabled"; then
        log_info "[2/8] TimeSketch: SKIPPED (disabled in config)"
        return
    fi

    # Recorded before the skip-already-installed return below, so a re-run of
    # install.sh still surfaces it. Printed at the end by print_install_notes.
    record_timesketch_llm_provider_note

    # Skip-already-installed: install.sh re-runs after a partial failure
    # should reuse what's healthy instead of re-pulling + re-creating
    # everything from scratch (which sometimes makes the original
    # transient worse). intact_timesketch_web is the canary because it
    # comes up LAST among timesketch's containers; if it's running, the
    # whole stack is healthy.
    if is_module_installed intact_timesketch_web; then
        log_info "[2/8] TimeSketch: already installed + running (skipping)"
        return 0
    fi

    log_info "[2/8] Starting TimeSketch..."
    log_info "  Directory: ${SCRIPT_DIR}/modules/timesketch"
    cd "${SCRIPT_DIR}/modules/timesketch"

    # Pre-flight: if the host is in a broken state, fail fast instead of
    # burning 90 s on image pulls only to crash at compose-up time.
    if ! preflight_host_check "TimeSketch"; then
        log_error "TimeSketch: host pre-flight FAILED — see warnings above"
        track_module_failure "TimeSketch"
        return 1
    fi

    local ts_version=$(read_config "['versions']['timesketch']")
    log_info "  TimeSketch version: ${ts_version:-latest}"

    # Stamp transitive container pins from config.yaml into
    # modules/timesketch/.env BEFORE compose up. The compose file's
    # `${POSTGRES_VERSION:?...}` references will fail loudly without
    # this. 2026-06-14 refactor: pins moved from a live upstream scrape
    # into config.yaml's `versions.timesketch_<dep>` entries — same
    # source the apply-side stamper reads from the bundled manifest.
    _stamp_transitive_env_from_config "timesketch" \
        "OPENSEARCH_VERSION:timesketch_opensearch" \
        "POSTGRES_VERSION:timesketch_postgres" \
        "REDIS_VERSION:timesketch_redis" \
        "NGINX_VERSION:timesketch_nginx"

    # Copy timesketch.conf / timesketch_legacy.conf from templates BEFORE
    # docker compose up — the conf files are bind-mounted into the
    # containers, so they must exist by the time the containers come up.
    # Templates ship with empty api_key fields; the operator fills them in
    # via the dashboard Settings → Timesketch tab (no env var, no secret
    # baked into install). Idempotent: existing conf is preserved so
    # post-install edits (manual or via the Settings UI) survive re-runs.
    # Timesketch's Postgres password. The compose file used to read
    # `${POSTGRES_PASSWORD:-timesketch}` and the fallback was LIVE — nothing set
    # the variable, so every install ran the timeline database on
    # timesketch/timesketch. Generated once here and reused; rotating it on a
    # re-run would leave the existing database unreachable (the credential is
    # baked into the DB at initdb time).
    #
    # secrets/, not modules/timesketch/.env: that .env is git-tracked.
    local ts_secrets="${SCRIPT_DIR}/modules/timesketch/secrets"
    local ts_pg_env="$ts_secrets/postgres.env"
    mkdir -p "$ts_secrets"
    if [[ ! -s "$ts_pg_env" ]]; then
        printf 'POSTGRES_PASSWORD=%s\n' "$(openssl rand -hex 32)" > "$ts_pg_env"
        chmod 600 "$ts_pg_env"
        sync
        log_info "  Generated Timesketch Postgres password"
    fi

    render_timesketch_conf_templates

    if ! pull_compose_with_retry "TimeSketch"; then
        track_module_failure "TimeSketch"
        return 1
    fi
    if ! run_compose_up_with_retry "TimeSketch"; then
        log_error "  Docker compose failed!"
        track_module_failure "TimeSketch"
        return 1
    fi

    # Show container status
    show_container_status "intact_timesketch_web"
    show_container_status "intact_timesketch_worker"
    show_container_status "intact_timesketch_postgres"
    show_container_status "intact_timesketch_redis"
    show_container_status "intact_timesketch_opensearch"

    # Wait for TimeSketch web container to be ready
    log_info "  Waiting for TimeSketch container..."
    if ! wait_for_container "intact_timesketch_web" 60; then
        log_error "  TimeSketch web container failed to start"
        capture_diagnostic_logs "TimeSketch web (container start timeout)" \
            intact_timesketch_web intact_timesketch_postgres intact_timesketch_opensearch
        track_module_failure "TimeSketch"
        return 1
    fi

    # Wait for TimeSketch API to be ready (check from host, not container - no curl in container)
    log_info "  Waiting for TimeSketch API (https://localhost:5000)..."
    local ts_ready=false
    local ts_wait=0
    local ts_max_wait=90

    while [[ $ts_wait -lt $ts_max_wait ]]; do
        local http_code=$(curl -sk --max-time 5 "https://localhost:5000/" -o /dev/null -w "%{http_code}" 2>/dev/null)
        if [[ "$http_code" =~ ^(200|301|302|303|307|308)$ ]]; then
            ts_ready=true
            log_success "  TimeSketch API is ready! (HTTP $http_code, ${ts_wait}s)"
            break
        fi
        sleep 5
        ((ts_wait+=5))
        log_info "  Waiting for TimeSketch API... (${ts_wait}/${ts_max_wait}s)"
    done

    if [[ "$ts_ready" != "true" ]]; then
        log_warn "  TimeSketch API not responding after ${ts_max_wait}s"
        log_info "  Check logs: docker logs intact_timesketch_web"
        capture_diagnostic_logs "TimeSketch API (deploy timeout)" \
            intact_timesketch_nginx intact_timesketch_web intact_timesketch_worker
    fi

    if create_timesketch_admin_user; then
        # Enable DFIQ after successful deployment.
        # (Historically also ran `tsctl db upgrade` here; the current
        # Timesketch image doesn't ship Alembic migrations, so the call
        # was a no-op and produced misleading errors. Removed.)
        log_info "  Enabling DFIQ..."
        sed -i 's/DFIQ_ENABLED = False/DFIQ_ENABLED = True/' "${SCRIPT_DIR}/modules/timesketch/config/timesketch.conf"
        log_success "  DFIQ enabled"

        # Keep the analyzer list curated on appliances whose conf predates the
        # curation (the renderer never rewrites an existing conf).
        curate_timesketch_analyzers

        # Populate /etc/timesketch/dfiq/ with the upstream Google DFIQ
        # YAML files. The Timesketch image does NOT ship these — the
        # DFIQ_ENABLED flag alone is useless without the 126 question /
        # facet / scenario YAMLs at DFIQ_PATH. Wiping the volume (e.g.
        # docker compose down -v) clears the rendered conf but the
        # bind-mounted config dir survives, so this only really runs on
        # first install or when /modules/timesketch/config/dfiq/ is empty.
        local dfiq_dir="${SCRIPT_DIR}/modules/timesketch/config/dfiq"
        if [[ ! -f "${dfiq_dir}/scenarios/$(ls "${dfiq_dir}/scenarios" 2>/dev/null | head -1)" || -z "$(ls "${dfiq_dir}/scenarios" 2>/dev/null)" ]]; then
            # Unlike Velociraptor binaries / SIGMA rules, this had NO air-gap
            # gate at all -- an air-gapped install unconditionally tried to
            # reach GitHub here, wasting a timeout before falling through to
            # the same "DFIQ UI will be empty" outcome the gate below reaches
            # immediately. _airgap_asset_check() only ever returns 0 (skip)
            # when INTACT_AIRGAP=1; online it always returns 1 so the clone
            # below runs exactly as before.
            if ! _airgap_asset_check "Timesketch DFIQ data" "${dfiq_dir}/scenarios/*" \
                    "DFIQ UI will be empty until populated manually"; then
                log_info "  Fetching DFIQ data from google/dfiq..."
                local _tmp
                _tmp="$(mktemp -d)"
                if git clone --depth 1 --quiet https://github.com/google/dfiq.git "${_tmp}/repo" 2>/dev/null; then
                    rm -rf "${dfiq_dir}"
                    mkdir -p "${dfiq_dir}"
                    mv "${_tmp}/repo/dfiq/data"/* "${dfiq_dir}/"
                    rm -rf "${_tmp}"
                    local _yaml_count
                    _yaml_count="$(find "${dfiq_dir}" -name '*.yaml' | wc -l)"
                    log_success "  DFIQ data installed (${_yaml_count} YAML files in ${dfiq_dir})"
                else
                    log_warn "  Could not clone google/dfiq (network?); DFIQ UI will be empty until you populate ${dfiq_dir} manually."
                fi
            fi
        else
            local _yaml_count
            _yaml_count="$(find "${dfiq_dir}" -name '*.yaml' | wc -l)"
            log_info "  DFIQ data already present (${_yaml_count} YAML files) — skipping clone."
        fi

        # Raise OpenSearch / import timeouts so large .plaso imports don't false-fail
        # (upstream defaults are 10s and 180s — too aggressive under disk/memory pressure)
        log_info "  Raising Timesketch OpenSearch/import timeouts..."
        local ts_conf="${SCRIPT_DIR}/modules/timesketch/config/timesketch.conf"
        sed -i 's/^OPENSEARCH_TIMEOUT = 10$/OPENSEARCH_TIMEOUT = 300/'                    "$ts_conf"
        sed -i 's/^OPENSEARCH_FLUSH_INTERVAL = 5000$/OPENSEARCH_FLUSH_INTERVAL = 10000/'  "$ts_conf"
        sed -i 's/^OPENSEARCH_INDEX_WAIT_TIMEOUT = 10$/OPENSEARCH_INDEX_WAIT_TIMEOUT = 300/' "$ts_conf"
        sed -i 's/^TIMEOUT_FOR_EVENT_IMPORT = 180$/TIMEOUT_FOR_EVENT_IMPORT = 600/'       "$ts_conf"
        log_success "  Timeouts raised (OpenSearch 10->300s, event import 180->600s)"

        # Restart the Timesketch containers that bind-mount timesketch.conf so both
        # DFIQ and the timeout bumps take effect. Worker + web_legacy matter too —
        # without this, indexing runs with the old timeouts until next reboot.
        docker restart intact_timesketch_web intact_timesketch_worker intact_timesketch_web_legacy >/dev/null 2>&1

        track_module_success "TimeSketch"
    else
        # create_timesketch_admin_user has already logged the specific
        # retry/tsctl detail (extracted out of this function -- see its own
        # definition); ts_user is re-read here rather than carried in a
        # variable from before the extraction, since that variable no
        # longer exists in this scope.
        local ts_user_for_msg; ts_user_for_msg=$(read_config "['modules']['timesketch']['id']")
        log_error "  TimeSketch user '${ts_user_for_msg}' creation FAILED"
        log_error "  Manual fix: docker exec intact_timesketch_web tsctl create-user ${ts_user_for_msg} --password '<from config.yaml>'"
        log_error "  Then verify:  docker exec intact_timesketch_postgres psql -U timesketch -d timesketch -c 'SELECT id, username FROM \"user\";'"
        capture_diagnostic_logs "TimeSketch user creation" \
            intact_timesketch_web intact_timesketch_postgres
        track_module_failure "TimeSketch"
        return 1
    fi
}
