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
    # PIPESTATUS[0], NOT $?. `$?` after a pipeline is TAIL's status, and tail
    # succeeds whatever docker exec did -- so this function returned 0
    # unconditionally and both callers' guards were unreachable dead code:
    #   lib/modules/volweb.sh          `if ! seed_volweb_admin; then log_warn`
    #   lib/upgrade/modules/volweb.sh  `seed_volweb_admin || log_warn`
    # A container that is absent (exec 125/126/127) or a Django exception both
    # looked identical to success. Must be read on the line immediately after
    # EOF -- any command in between overwrites it.
    local rc=${PIPESTATUS[0]}
    return "$rc"
}


# ---------------------------------------------------------------------------
# _seed_yara_from_bundle <seed-dir>
#
# Imports the bundled YARA rule zips (<seed-dir>/yara_rulesets/*.zip, named by
# <seed-dir>/manifest.json's contents.yara_rulesets[] -- name/filename/
# description/source_url per entry, written by scripts/ci/packager/package.py)
# into VolWeb's own yararulesets table, entirely inside intact_volweb_backend
# via its own Django ORM. Mirrors what routes/maintenance_routes.py's GitHub
# importer does internally, minus the clone step.
#
# Ported from services/upgrade/volweb.py:_seed_yara_from_bundle, deleted by
# f4ab33a ("upgrade: delete the in-container engine"). That commit relocated
# five symbols with "live callers outside the upgrade engine" before deleting
# the package -- this bash function was the sixth, so seed_yara_rulesets()
# below has been calling a module that no longer exists in the backend image
# since 2026-08-09, unconditionally falling through to the online path (and,
# on an air-gapped box, to an empty YARA corpus) on every single install.
# Confirmed live on an intact-20260813 install, 2026-08-15.
#
# Idempotent: YaraRuleSet is get_or_create'd by name, YaraRule by etag (a hash
# of name+content+source_url), so a re-run just updates metadata.
# ---------------------------------------------------------------------------
_seed_yara_from_bundle() {
    local seed_dir="$1" manifest="${1}/manifest.json"

    # Same race the deleted code's docstring documents (confirmed live
    # 2026-08-06): Django apps migrate independently, so intact_volweb_backend
    # answering HTTP health checks (deploy_volweb's own wait, well before this
    # runs) does not mean the yararulesets app has finished migrating.
    local _yr_wait=0
    while [[ $_yr_wait -lt 60 ]]; do
        if docker exec --user app -w /home/app/web -i intact_volweb_backend \
                python3 manage.py shell <<'EOF' >/dev/null 2>&1
from yararulesets.models import YaraRuleSet
YaraRuleSet.objects.exists()
EOF
        then
            break
        fi
        sleep 5
        ((_yr_wait += 5))
    done
    if (( _yr_wait >= 60 )); then
        log_warn "    YARA seed: intact_volweb_backend not ready for ORM queries after 60s"
        return 1
    fi

    local specs_list; specs_list="$(mktemp)"
    python3 -c "
import json, sys
m = json.load(open(sys.argv[1]))
for e in ((m.get('contents') or {}).get('yara_rulesets')) or []:
    fn, name = e.get('filename'), e.get('name')
    if fn and name:
        print('\t'.join([name, fn, e.get('description', ''), e.get('source_url', 'bundled')]))
" "$manifest" > "$specs_list" 2>/dev/null
    if [[ ! -s "$specs_list" ]]; then
        log_warn "    YARA seed: no rulesets described in the bundled manifest"
        rm -f "$specs_list"; return 1
    fi

    # Copy each zip into the container and build the in-container spec list --
    # docker cp, not a bind mount, so this works whether or not
    # intact_volweb_backend shares a filesystem with the host.
    local jsonl; jsonl="$(mktemp)"
    local name fname desc url src dst
    while IFS=$'\t' read -r name fname desc url; do
        src="${seed_dir}/yara_rulesets/${fname}"
        if [[ ! -f "$src" ]]; then
            log_warn "    ✗ ${name}: bundled zip missing on disk (${src})"
            continue
        fi
        dst="/tmp/intact-yara-${fname}"
        if ! docker cp "$src" "intact_volweb_backend:${dst}" >/dev/null 2>&1; then
            log_warn "    ✗ ${name}: docker cp into intact_volweb_backend failed"
            continue
        fi
        python3 -c "
import json, sys
print(json.dumps({'name': sys.argv[1], 'zip_path': sys.argv[2],
                   'description': sys.argv[3], 'source_url': sys.argv[4]}))
" "$name" "$dst" "$desc" "$url" >> "$jsonl"
    done < "$specs_list"
    rm -f "$specs_list"

    if [[ ! -s "$jsonl" ]]; then
        log_warn "    YARA seed: no zips successfully copied"
        rm -f "$jsonl"; return 1
    fi
    local specs_json
    specs_json="$(python3 -c "
import json, sys
print(json.dumps([json.loads(l) for l in open(sys.argv[1])]))
" "$jsonl")"
    rm -f "$jsonl"

    # The ingest script runs INSIDE intact_volweb_backend via manage.py shell
    # (same mechanism seed_volweb_admin() already uses), reading the spec list
    # from an env var rather than inlining JSON into the script -- sidesteps
    # the shell-quoting nightmare of embedding untrusted names/URLs in source.
    local result rc
    result="$(INTACT_YARA_SPECS="$specs_json" docker exec --user app -w /home/app/web \
            -i -e INTACT_YARA_SPECS intact_volweb_backend python3 manage.py shell <<'PYEOF' 2>&1
import os, re, zipfile, hashlib, tempfile, shutil, json
from yararulesets.models import YaraRuleSet
from yararules.models import YaraRule
try:
    from yararules.utils import BatchUploadManager
except Exception:
    BatchUploadManager = None

# COMPILE PROBE. VolWeb validates each rule with a bare
# `yara.compile(source=...)` (volatility_engine/engine.py:555) -- no external
# variables declared -- so any rule referencing `filepath`, `filename` or
# `extension` fails to compile and is silently unusable at scan time:
#
#   ERROR/ForkPoolWorker-17 Syntax error in rule 'webshell_php_by_string_obfuscation':
#                           line 97: undefined identifier "filepath"
#
# 13 of the 1743 rules seeded on 2026-08-16 were in that state, and the
# install reported a flat "imported 1743 new rule(s)" with no hint of it.
# Counting them here does NOT change which rules are stored -- dropping rules
# from the corpus on the strength of a heuristic would be the riskier change,
# and the underlying fix belongs upstream in how VolWeb calls yara.compile.
# This only makes the number the installer prints an honest one.
try:
    import yara as _yara
except Exception:
    _yara = None

specs = json.loads(os.environ['INTACT_YARA_SPECS'])
out = {'total': 0, 'rulesets': [], 'compile_probe': _yara is not None}
for spec in specs:
    name = spec['name']
    zip_path = spec['zip_path']
    description = spec.get('description', '')
    source_url = spec.get('source_url', 'bundled')
    if not os.path.exists(zip_path):
        out['rulesets'].append({'name': name, 'error': 'zip missing on container'})
        continue
    ruleset, _ = YaraRuleSet.objects.get_or_create(name=name, defaults={'description': description})
    created = 0
    skipped = 0
    uncompilable = 0
    uncompilable_names = []
    yara_files = []
    extract_dir = tempfile.mkdtemp(prefix='intact-yara-')
    try:
        with zipfile.ZipFile(zip_path) as zf:
            zf.extractall(extract_dir)
        for root, _dirs, files in os.walk(extract_dir):
            for fn in files:
                if fn.lower().endswith(('.yar', '.yara')):
                    yara_files.append(os.path.join(root, fn))
        ctx = BatchUploadManager(ruleset_id=ruleset.id).batch_context() if BatchUploadManager else None
        if ctx is not None:
            ctx.__enter__()
        try:
            for path in yara_files:
                try:
                    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    rule_name = os.path.splitext(os.path.basename(path))[0]
                    mo = re.search(r'rule\s+(\w+)', content)
                    if mo:
                        rule_name = mo.group(1)
                    # Same call VolWeb's own validator makes, so this predicts
                    # exactly what it will decide at scan time.
                    if _yara is not None:
                        try:
                            _yara.compile(source=content)
                        except Exception as _ce:
                            uncompilable += 1
                            if len(uncompilable_names) < 5:
                                uncompilable_names.append(
                                    '%s (%s)' % (rule_name, str(_ce)[:70]))
                    etag = hashlib.md5(f"{rule_name}_{content}_{source_url}".encode()).hexdigest()
                    obj, was_created = YaraRule.objects.get_or_create(
                        etag=etag,
                        defaults={
                            'name': rule_name,
                            'rule_content': content,
                            'description': description or f"Imported from bundled package: {os.path.basename(path)}",
                            'linked_yararuleset': ruleset,
                            'source': 'bundled',
                            'url': source_url,
                            'is_active': True,
                        },
                    )
                    if was_created:
                        created += 1
                    else:
                        skipped += 1
                except Exception:
                    continue
        finally:
            if ctx is not None:
                ctx.__exit__(None, None, None)
    finally:
        shutil.rmtree(extract_dir, ignore_errors=True)
    out['total'] += created
    out['rulesets'].append({
        'name': name,
        'files_found': len(yara_files),
        'created': created,
        'skipped_duplicates': skipped,
        'uncompilable': uncompilable,
        'uncompilable_names': uncompilable_names,
    })
print('INTACT_YARA_RESULT=' + json.dumps(out))
PYEOF
)"
    rc=$?

    # Best-effort cleanup of the copied zips regardless of outcome.
    printf '%s' "$specs_json" | python3 -c "
import json, sys
for e in json.load(sys.stdin):
    print(e['zip_path'])
" 2>/dev/null | while read -r p; do
        docker exec intact_volweb_backend rm -f "$p" >/dev/null 2>&1
    done

    if (( rc != 0 )); then
        log_warn "    YARA seed: ingest failed: $(printf '%s' "$result" | tail -c 500)"
        return 1
    fi
    local result_line
    result_line="$(printf '%s\n' "$result" | grep '^INTACT_YARA_RESULT=' | tail -1)"
    if [[ -z "$result_line" ]]; then
        log_warn "    YARA seed: ingest ran but produced no result line ($(printf '%s' "$result" | tail -c 300))"
        return 1
    fi
    printf '%s' "${result_line#INTACT_YARA_RESULT=}" | python3 -c "
import json, sys
r = json.load(sys.stdin)
bad = sum(rs.get('uncompilable', 0) for rs in r.get('rulesets', []))
print(f\"  imported {r.get('total', 0)} new rule(s) across {len(r.get('rulesets', []))} ruleset(s)\")
for rs in r.get('rulesets', []):
    if 'error' in rs:
        print(f\"    x {rs['name']}: {rs['error']}\")
    else:
        line = (f\"    - {rs['name']}: {rs.get('files_found', 0)} files -> \"
                f\"{rs.get('created', 0)} new, {rs.get('skipped_duplicates', 0)} already present\")
        if rs.get('uncompilable'):
            line += f\", {rs['uncompilable']} will not compile\"
        print(line)
# Said only when it happened, and with the reason -- 'N rules imported' on its
# own reads as 'N rules usable', which is what made this invisible.
if bad:
    print(f\"  NOTE: {bad} imported rule(s) do not compile and will be skipped at scan time.\")
    print(f\"        These reference YARA external variables (filepath / filename / extension)\")
    print(f\"        that VolWeb's scanner does not declare. Examples:\")
    for rs in r.get('rulesets', []):
        for nm in (rs.get('uncompilable_names') or [])[:3]:
            print(f\"          - {nm}\")
elif not r.get('compile_probe', False):
    print(f\"  (rule compilation was not verified — the yara module was not importable here)\")
" | while IFS= read -r _line; do log_info "$_line"; done
    return 0
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
    # Delegates to _seed_yara_from_bundle() above -- a bash-native port, run
    # entirely against intact_volweb_backend's own Django ORM. It reads
    # <dir>/manifest.json + <dir>/yara_rulesets/*.zip, which is the shape
    # install.sh staged.
    #
    # SELF-GUARDED, same reasoning as bootstrap_iris_api_key: this is no
    # longer called from inside deploy_volweb (which already knew volweb was
    # enabled and up), but from the main sequence after deploy_backend.
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
        if _seed_yara_from_bundle "$_seed_dir"; then
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

    # A FAILED IMPORT IS A WARNING, NOT AN [INFO] LINE.
    #
    # Every response used to be logged at INFO whatever it said, and the step
    # then announced "YARA seeding dispatched" and returned 0 regardless -- so
    # an import that failed outright was invisible in the final report and the
    # module was ticked as upgraded. Measured on a real run 2026-08-25: BOTH
    # rulesets failed with "Max retries exceeded ... NameResolutionError" and
    # the run still reported `1 error(s), 11 warning(s)` with neither of these
    # among them. The box ended up with an empty rule corpus and nothing said
    # so -- the operator finds out during an investigation, which is the worst
    # possible time.
    #
    # The response is JSON on both paths, so the check is "does it carry an
    # error key", not a status code (curl -s already swallowed that).
    local seeded=0 failed_names=()
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
        if [[ -z "$resp" || "$resp" == *'"error"'* ]]; then
            failed_names+=("$name")
            log_warn "      ${name}: import FAILED — ${resp:0:300}"
        else
            seeded=$((seeded + 1))
            log_info "      ${resp:0:200}"
        fi
    done

    if (( ${#failed_names[@]} )); then
        log_warn "  YARA seeding: ${seeded}/${#rulesets[@]} ruleset(s) imported;"
        log_warn "    failed: ${failed_names[*]}"
        log_warn "    VolWeb's rule corpus is incomplete. Re-run from"
        log_warn "    Maintenance -> Refresh YARA Rulesets once the cause is fixed."
        # Still 0: the caller treats this as advisory and the module is
        # otherwise healthy. The point is that it is now SAID, not that it
        # should fail the run.
        return 0
    fi

    log_success "  YARA seeding dispatched (rule validation runs async in workers-yarascan)"
    return 0
}
