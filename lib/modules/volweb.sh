#!/bin/bash
# Intact.AI Platform Installer — VolWeb module (memory-forensics analysis stack).

# ============================================================================
# VolWeb Module (memory-forensics analysis stack)
# ============================================================================

# Render modules/volweb/.env from the template + config.yaml pins. Idempotent:
# an existing .env is preserved (its rotated DJANGO_SECRET + postgres password
# are the actual credentials the running database already has, not just
# defaults) so this is safe to call on every deploy, not only the first.
#
# Extracted out of deploy_volweb so scripts/upgrade.sh's install case (a
# module enabled but never before deployed, reached by enabling it in
# config.yaml and then running an upgrade rather than install.sh) can call
# the SAME rendering instead of failing at the pin-stamping step with no
# .env to stamp into -- modules/volweb/.env is gitignored (only .env.template
# is tracked), so a genuinely fresh box has no file here at all until this
# runs once.
render_volweb_env_template() {
    local env_out="${SCRIPT_DIR}/modules/volweb/.env"
    local env_tmpl="${SCRIPT_DIR}/modules/volweb/.env.template"

    if [[ -f "$env_out" ]]; then
        log_info "  modules/volweb/.env already present (skip render — secrets preserved)"
        return 0
    fi
    if [[ ! -f "$env_tmpl" ]]; then
        log_warn "  modules/volweb/.env.template missing — skipping VolWeb"
        return 1
    fi

    # Single `versions.volweb` pin drives both backend + frontend
    # (forensicxlab releases them in lockstep). Postgres + Redis
    # are transitive deps — pulled from config.yaml's
    # `versions.volweb_postgres` + `versions.volweb_redis` via
    # the stamping helper the caller runs AFTER this (which also
    # covers the upgrade case where .env already exists — operator
    # pin bumps propagate on the next deploy without touching the
    # .env by hand).
    local volweb_ver=$(read_config "['versions']['volweb']")
    local domain=$(read_config "['domain']")
    # Per-install random secrets. Mirrors the IRIS_SECRET_KEY +
    # Timesketch SECRET_KEY pattern shipped earlier this session.
    local django_secret=$(openssl rand -hex 32)
    local pg_password=$(openssl rand -hex 24)
    # CSRF: the IntactAI dashboard hits VolWeb through intact_nginx
    # AND from the backend container. Cover both shapes.
    local csrf="https://${domain},http://intact_nginx,http://intact_backend:5001,http://intact_volweb_backend:8000"

    cp "$env_tmpl" "$env_out"
    sed -i \
        -e "s|__VOLWEB_BACKEND_VERSION__|${volweb_ver:-latest}|g" \
        -e "s|__VOLWEB_FRONTEND_VERSION__|${volweb_ver:-latest}|g" \
        -e "s|__VOLWEB_DJANGO_SECRET__|${django_secret}|g" \
        -e "s|__VOLWEB_POSTGRES_PASSWORD__|${pg_password}|g" \
        -e "s|__VOLWEB_CSRF_TRUSTED_ORIGINS__|${csrf}|g" \
        "$env_out"
    # Drop the old __VOLWEB_POSTGRES_VERSION__ / __VOLWEB_REDIS_VERSION__
    # placeholder lines — the stamping helper below writes the
    # real values from config.yaml. Tolerant if the template
    # doesn't ship those placeholders any more.
    sed -i \
        -e "s|^VOLWEB_POSTGRES_VERSION=__VOLWEB_POSTGRES_VERSION__||g" \
        -e "s|^VOLWEB_REDIS_VERSION=__VOLWEB_REDIS_VERSION__||g" \
        "$env_out"
    log_success "  modules/volweb/.env rendered (per-install secrets generated)"
    return 0
}

deploy_volweb() {
    # Gate on the dedicated `modules.volweb.enabled` key (added in
    # commit 96b8a8f). Previously read `modules.memory.enabled`, which
    # silently coupled the backend Memory feature flag to the VolWeb
    # docker stack. Operators who want Memory without VolWeb (e.g.
    # using an external Volatility installation) had no way to express
    # that.
    local volweb_enabled
    volweb_enabled=$(read_config "['modules']['volweb']['enabled']")
    if ! is_enabled "$volweb_enabled"; then
        log_info "[6/8] VolWeb: SKIPPED (volweb disabled in config)"
        return
    fi

    if is_module_installed intact_volweb_backend; then
        log_info "[6/8] VolWeb: already installed + running (skipping)"
        return 0
    fi

    log_info "[6/8] Starting VolWeb (memory-forensics)..."
    log_info "  Directory: ${SCRIPT_DIR}/modules/volweb"
    cd "${SCRIPT_DIR}/modules/volweb"

    if ! preflight_host_check "VolWeb"; then
        log_error "VolWeb: host pre-flight FAILED — see warnings above"
        track_module_failure "VolWeb"
        return 1
    fi

    render_volweb_env_template || return 1

    # Stamp transitive container pins from config.yaml — always runs,
    # so an operator pin edit in config.yaml propagates on the next
    # deploy without manual .env surgery. Compose's
    # `${VOLWEB_POSTGRES_VERSION:?...}` would fail loudly otherwise.
    _stamp_transitive_env_from_config "volweb" \
        "VOLWEB_POSTGRES_VERSION:volweb_postgres" \
        "VOLWEB_REDIS_VERSION:volweb_redis"

    if ! pull_compose_with_retry "VolWeb"; then
        track_module_failure "VolWeb"
        return 1
    fi

    if ! run_compose_up_with_retry "VolWeb"; then
        log_error "  Docker compose failed!"
        track_module_failure "VolWeb"
        return 1
    fi

    # Wait for the backend's healthcheck endpoint. Daphne takes a few
    # seconds to bind after the container starts.
    log_info "  Waiting for VolWeb backend to be ready..."
    local volweb_wait=0
    while [[ $volweb_wait -lt 90 ]]; do
        if docker exec intact_volweb_backend curl -sf -o /dev/null \
            http://localhost:8000/api/health 2>/dev/null \
            || docker exec intact_volweb_backend curl -sI -o /dev/null \
            -w "%{http_code}" http://localhost:8000/ 2>/dev/null | grep -qE "^(200|301|302|404)$"; then
            log_success "  VolWeb backend ready (${volweb_wait}s)"
            break
        fi
        sleep 5
        ((volweb_wait+=5))
    done
    if [[ $volweb_wait -ge 90 ]]; then
        log_warn "  VolWeb backend not responding after 90s"
        capture_diagnostic_logs "VolWeb (backend start timeout)" intact_volweb_backend
    fi

    # Seed VolWeb admin user with the platform's tenroot credentials so
    # the IntactAI backend can auth without baking a second password
    # into ops. Idempotent — re-runs harmlessly skip.
    if ! seed_volweb_admin; then
        log_warn "  VolWeb admin seeding had issues — operator may need to do it manually"
    fi

    # YARA seeding does NOT run here. Its bundled-package path needs
    # intact_backend (see seed_yara_rulesets), which does not exist yet at
    # this point in start_services() -- deploy_backend runs AFTER
    # deploy_volweb. Called separately, post-backend; see main sequence.

    track_module_success "VolWeb"
}


# Ensures modules/volweb/secrets/ADMIN_PASSWORD exists and returns its
# content on stdout. Uses the operator's modules.volweb.password from
# config.yaml when set; otherwise generates a random per-install password
# instead of falling back to a fixed, publicly-documented string (same
# pattern as generate_iris_secrets' IRIS_ADM_PASSWORD / the Portainer admin
# password). Persisted so seed_volweb_admin() and seed_yara_rulesets()
# (which authenticates as the same user) always agree, and re-runs stay
# idempotent. Callers capture this via `$(get_volweb_admin_password)`, so
# any log output MUST go to stderr — only the password itself goes to
# stdout.
get_volweb_admin_password() {
    local secrets_dir="${SCRIPT_DIR}/modules/volweb/secrets"
    mkdir -p "$secrets_dir"
    local pass_file="$secrets_dir/ADMIN_PASSWORD"

    if [[ ! -s "$pass_file" ]]; then
        local volweb_pass
        volweb_pass=$(read_config "['modules']['volweb']['password']")
        if [[ -z "$volweb_pass" || "$volweb_pass" == "None" ]]; then
            volweb_pass=$(openssl rand -hex 16)
            {
                log_warn "  No VolWeb password set in config.yaml; generated a random one instead"
                log_warn "  Retrieve it with: cat ${pass_file}"
            } >&2
        fi
        printf '%s' "$volweb_pass" > "$pass_file"
        chmod 600 "$pass_file"
    fi
    cat "$pass_file"
}


seed_volweb_admin() {
    # Use the platform's VolWeb admin creds from config.yaml. Reads
    # ``modules.volweb.id`` for the username, and the persisted
    # admin password from get_volweb_admin_password() (config.yaml's
    # password when the operator set one, otherwise a random per-install
    # value generated on first run).
    local tenroot_user=$(read_config "['modules']['volweb']['id']")
    [[ -z "$tenroot_user" ]] && tenroot_user="tenroot"
    local tenroot_pass
    tenroot_pass=$(get_volweb_admin_password)

    log_info "  Seeding VolWeb admin user (${tenroot_user})..."
    docker exec --user app -w /home/app/web -i intact_volweb_backend python3 manage.py shell <<EOF 2>&1 | tail -3
from django.contrib.auth import get_user_model
U = get_user_model()
u, created = U.objects.get_or_create(username='${tenroot_user}', defaults={'is_superuser': True, 'is_staff': True})
u.is_superuser = True
u.is_staff = True
u.set_password('${tenroot_pass}')
u.save()
print('CREATED' if created else 'UPDATED', 'admin', u.username)
EOF
    return $?
}


seed_yara_rulesets() {
    # BUNDLED FIRST. The release ships these rule zips inside the volweb asset
    # (package.py bundles them precisely "so apply can seed VolWeb's
    # yararulesets table without needing internet at apply time"), and
    # load_images_from_package() stages them to data/yara-seed/. Going to
    # github.com anyway meant every install re-downloaded ~5.4 MB it already
    # had, spent ~3 minutes doing it, and -- the part that actually broke --
    # an air-gapped install could not seed YARA at all. The clone happens
    # INSIDE the volweb container, so INTACT_AIRGAP could never have stopped
    # it from out here; it just failed slowly against an unreachable host.
    #
    # Delegates to services/upgrade/volweb.py:_seed_yara_from_bundle, the same
    # importer the upgrade path uses, rather than reimplementing ORM ingest in
    # bash. It reads <dir>/manifest.json + <dir>/yara_rulesets/*.zip, which is
    # the shape install.sh staged.
    #
    # SELF-GUARDED, same reasoning as bootstrap_iris_api_key: this is no
    # longer called from inside deploy_volweb (which already knew volweb was
    # enabled and up), but from the main sequence after deploy_backend --
    # the bundled path needs intact_backend, which deploy_volweb runs before.
    # So the checks deploy_volweb used to guarantee for free now have to be
    # made explicit here.
    local volweb_enabled
    volweb_enabled=$(read_config "['modules']['volweb']['enabled']")
    if ! is_enabled "$volweb_enabled"; then
        log_info "  VolWeb disabled — skipping YARA ruleset seeding"
        return 0
    fi
    if ! is_module_installed intact_volweb_backend; then
        log_warn "  intact_volweb_backend not running — skipping YARA ruleset seeding"
        return 1
    fi

    local _seed_dir="${SCRIPT_DIR}/data/yara-seed"
    if [[ -f "${_seed_dir}/manifest.json" ]] \
            && ls "${_seed_dir}"/yara_rulesets/*.zip >/dev/null 2>&1; then
        log_info "  Seeding YARA rulesets from the release package (no download)..."
        # Capture THEN print. `docker exec ... | sed` would report sed's exit
        # status, so the success branch would be taken even when the seed
        # failed -- the failure would be invisible and the online fallback
        # would never run.
        local _yout _yrc
        _yout="$(docker exec intact_backend python3 -c "
import sys
sys.path.insert(0, '/app')
from services.upgrade.volweb import _seed_yara_from_bundle
r = _seed_yara_from_bundle('${_seed_dir}', lambda m, l='info': print(m))
sys.exit(0 if r.get('success') else 1)
" 2>&1)"
        _yrc=$?
        [[ -n "$_yout" ]] && printf '%s\n' "$_yout" | sed 's/^/    /'
        if (( _yrc == 0 )); then
            log_success "  YARA seeded from the bundled rule sets"
            return 0
        fi
        # Fall through to the online path: a bundled seed that fails on a box
        # WITH internet should still end up with rules.
        log_warn "    Bundled YARA seed failed — falling back to online import"
    fi

    # No bundled copy. On an air-gapped install there is nothing to fall back
    # to, and the operator needs to know the corpus is empty rather than
    # discover it during an investigation.
    if [[ "${INTACT_AIRGAP:-0}" == "1" ]]; then
        log_warn "  No bundled YARA rule sets in this package — VolWeb starts with an empty"
        log_warn "  rule corpus. Seed later from Maintenance → Refresh YARA Rulesets"
        log_warn "  once this box has internet access."
        return 0
    fi

    # Two sources for the curated YARA corpus. Each is POSTed to
    # /api/yararulesets/import/github/ which clones the repo +
    # ingests every .yar / .yara file recursively.
    local volweb_user=$(read_config "['modules']['volweb']['id']")
    [[ -z "$volweb_user" ]] && volweb_user="tenroot"
    local volweb_pass
    volweb_pass=$(get_volweb_admin_password)

    log_info "  Seeding YARA rulesets (~3 min)..."

    # Get a JWT for the admin user we just seeded.
    local token=$(docker exec intact_volweb_backend curl -s -X POST \
        -H 'Content-Type: application/json' \
        -d "{\"username\":\"${volweb_user}\",\"password\":\"${volweb_pass}\"}" \
        http://localhost:8000/core/token/ \
        | python3 -c 'import sys,json; print(json.load(sys.stdin).get("access",""))' 2>/dev/null)
    if [[ -z "$token" ]]; then
        log_warn "    Could not get VolWeb JWT — skipping YARA seed"
        return 1
    fi

    # Tuples: name | github url | description
    local rulesets=(
        "Neo23x0 signature-base|https://github.com/Neo23x0/signature-base|Florian Roth's curated YARA rules (~749 active)"
        "Elastic protections|https://github.com/elastic/protections-artifacts|Elastic security YARA detection rules (~695 active)"
    )
    # NOTE: YARA-Forge was dropped here — its rules ship only as release
    # assets (the repo has zero .yar files), so import-from-github seeded
    # a single useless rule. The two curated repos above ship .yar files
    # in-tree and import natively. See routes/maintenance_routes.py +
    # upgrade/package.py.

    for entry in "${rulesets[@]}"; do
        local name="${entry%%|*}"
        local rest="${entry#*|}"
        local url="${rest%%|*}"
        local desc="${rest#*|}"

        log_info "    - ${name}..."
        local resp=$(docker exec intact_volweb_backend curl -s -X POST \
            -H "Authorization: Bearer ${token}" \
            -H 'Content-Type: application/json' \
            -d "{\"name\":\"${name}\",\"github_url\":\"${url}\",\"description\":\"${desc}\"}" \
            http://localhost:8000/api/yararulesets/import/github/)
        log_info "      ${resp:0:200}"
    done

    log_success "  YARA seeding dispatched (rule validation runs async in workers-yarascan)"
    return 0
}
