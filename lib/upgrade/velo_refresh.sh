#!/bin/bash
# Intact.AI upgrade — Velociraptor artifact/tool/downloads refresh.
#
# These ~300 lines replace ~1,400 in velociraptor.py, and more importantly
# they are no longer part of the upgrade. Velocidex's upgrade docs say nothing
# about re-importing artifacts, registering tools or rebuilding client
# installers, because those are not upgrade steps -- they are things this
# platform needs doing because it bakes a curated artifact bundle into the
# image and runs a self-service downloads page Velociraptor has no equivalent
# of. Bolting them onto the version swap meant an artifact-import hiccup could
# roll back a perfectly healthy server.
#
# So: separate step, runs automatically after a successful velociraptor swap,
# policy 'report'. A failure here is named loudly with the exact command to
# re-run, and never reverts a working Velociraptor.
#
# gRPC/pyvelociraptor is gone. The container's own binary speaks VQL over
# docker exec, which the Python already used for its artifact export -- it
# simply never used it for the other half.

velo_refresh() {
    local pkg="${1:-}"
    local failures=0

    log_info ""
    log_info "=================================================================="
    log_info "Velociraptor refresh (artifacts, tools, downloads)"
    log_info "=================================================================="

    if ! "${DOCKER_BIN:-docker}" inspect intact_velociraptor >/dev/null 2>&1; then
        log_warn "  intact_velociraptor is not present; skipping the refresh"
        return 0
    fi
    if ! velo_vql_ready 180; then
        log_error "  Velociraptor's query engine did not become ready; skipping the refresh"
        _velo_refresh_remediation "$pkg"
        UPGRADE_DEGRADED+=("velociraptor refresh — server never became queryable")
        return 1
    fi

    _velo_refresh_artifacts "$pkg" || failures=$((failures + 1))
    _velo_refresh_tools "$pkg"     || failures=$((failures + 1))
    _velo_refresh_downloads "$pkg" || failures=$((failures + 1))
    _velo_refresh_installers       || failures=$((failures + 1))

    if (( failures )); then
        log_warn "  ${failures} refresh step(s) had problems — Velociraptor itself is fine"
        _velo_refresh_remediation "$pkg"
        UPGRADE_DEGRADED+=("velociraptor refresh — ${failures} step(s) incomplete")
        return 1
    fi
    log_success "Velociraptor refresh complete"
    return 0
}

_velo_refresh_remediation() {
    log_warn "  Re-run just this step with:"
    log_warn "    sudo bash upgrade.sh --velo-refresh${1:+ --package-dir $1}"
}

# ---------------------------------------------------------------------------
# Artifacts
#
# THE SKIP IS NOT AN OPTIMISATION. The curated bundle is loaded from
# /opt/velociraptor_artifacts at every boot via --definitions, so the registry
# is already populated by the time this runs. Re-importing each one costs
# several seconds, and doing that for ~400 artifacts is a ~45-minute silent
# stall that looks like a hang. Only genuinely absent definitions are imported.
# ---------------------------------------------------------------------------
_velo_refresh_artifacts() {
    local pkg="${1:-}"
    local present tmp
    tmp="$(mktemp)"

    velo_vql 'SELECT name FROM artifact_definitions()' \
        | python3 -c "
import json,sys
for l in sys.stdin:
    l=l.strip()
    if not l: continue
    try: print(json.loads(l).get('name',''))
    except Exception: pass
" > "$tmp" 2>/dev/null
    present="$(grep -c . "$tmp" || true)"
    log_info "  registry currently holds ${present} artifact definition(s)"

    if [[ "${present:-0}" -eq 0 ]]; then
        log_error "  the artifact registry is EMPTY — the bundled definitions did not load"
        log_error "  Blueprint hunts (Quick Wins, KapeTriage) will fail with 'artifact not found'."
        rm -f "$tmp"
        return 1
    fi

    # Import anything the package carries that is not already registered.
    local imported=0 skipped=0 failed=0 src f name b64
    for src in "${pkg}/artifacts/velociraptor" "${SCRIPT_DIR}/data/custom_artifacts"; do
        [[ -n "$pkg" || "$src" != "/artifacts/velociraptor" ]] || continue
        [[ -d "$src" ]] || continue
        while IFS= read -r f; do
            name="$(grep -m1 -E '^name:[[:space:]]*' "$f" 2>/dev/null | sed 's/^name:[[:space:]]*//' | tr -d '"'"'"' \r')"
            [[ -n "$name" ]] || continue
            if grep -qxF "$name" "$tmp"; then skipped=$((skipped + 1)); continue; fi
            # base64 on the host so the only characters inside the VQL string
            # literal are [A-Za-z0-9+/=]. No shell escaping, no VQL escaping,
            # and the whole query is one argv element to docker exec.
            b64="$(base64 -w0 < "$f")"
            if velo_vql "SELECT artifact_set(definition=base64decode(string='${b64}')) AS r FROM scope()" \
                 | grep -q '"r"'; then
                imported=$((imported + 1))
            else
                failed=$((failed + 1))
                log_warn "    could not import ${name}"
            fi
        done < <(find "$src" -maxdepth 3 \( -name '*.yaml' -o -name '*.yml' \) 2>/dev/null)
    done
    rm -f "$tmp"

    log_info "  artifacts: ${imported} imported, ${skipped} already present, ${failed} failed"
    (( failed )) && return 1
    return 0
}

# ---------------------------------------------------------------------------
# Tools
#
# serve_locally=TRUE is what makes an air-gapped collection work: the endpoint
# fetches the tool from this server instead of the internet.
# ---------------------------------------------------------------------------
_velo_refresh_tools() {
    local pkg="${1:-}"
    local tools_dir="${SCRIPT_DIR}/data/tools"
    [[ -d "$tools_dir" ]] || { log_info "  no data/tools directory; nothing to register"; return 0; }

    local registered=0 failed=0 f base
    while IFS= read -r f; do
        base="$(basename "$f")"
        case "$base" in *.txt|*.md|*.yaml|*.yml) continue ;; esac
        if velo_vql "SELECT inventory_add(tool='${base}', serve_locally=TRUE, file='/tools/${base}', accessor='file') AS r FROM scope()" \
             | grep -q '"r"'; then
            registered=$((registered + 1))
        else
            failed=$((failed + 1))
            log_warn "    could not register tool ${base}"
        fi
    done < <(find "$tools_dir" -maxdepth 1 -type f 2>/dev/null)

    log_info "  tools: ${registered} registered, ${failed} failed"
    (( failed )) && return 1
    return 0
}

# ---------------------------------------------------------------------------
# Downloads page
#
# Keeps BOTH the current pin and versions.velociraptor_legacy: some customers
# still deploy the legacy agent, and pruning by "anything that is not the
# current version" deletes the one they actually need.
# ---------------------------------------------------------------------------
_velo_refresh_downloads() {
    local pkg="${1:-}"
    local dl="${SCRIPT_DIR}/modules/nginx/html/downloads"
    mkdir -p "$dl" 2>/dev/null

    local current legacy
    current="$(read_env_var "${SCRIPT_DIR}/modules/velociraptor/.env" VELOCIRAPTOR_VERSION 2>/dev/null || echo '')"
    legacy="$(read_config "['versions']['velociraptor_legacy']" 2>/dev/null || echo '')"
    [[ "$legacy" == "None" ]] && legacy=""

    local pruned=0 f v
    while IFS= read -r f; do
        v="$(sed -n 's/.*velociraptor-v\([0-9.]*\)-.*/\1/p' <<< "$(basename "$f")")"
        [[ -n "$v" ]] || continue
        [[ "$v" == "$current" || ( -n "$legacy" && "$v" == "$legacy" ) ]] && continue
        rm -f "$f" && pruned=$((pruned + 1))
    done < <(find "$dl" -maxdepth 1 -name 'velociraptor-v*' -type f 2>/dev/null)

    local placed=0
    if [[ -n "$pkg" && -d "${pkg}/binaries" ]]; then
        while IFS= read -r f; do
            cp -f "$f" "${dl}/$(basename "$f")" 2>/dev/null || continue
            case "$f" in *.msi) chmod 644 "${dl}/$(basename "$f")" ;;
                         *)     chmod 755 "${dl}/$(basename "$f")" ;; esac
            placed=$((placed + 1))
        done < <(find "${pkg}/binaries" -maxdepth 2 -type f -name 'velociraptor*' 2>/dev/null)
    fi

    log_info "  downloads: ${placed} placed, ${pruned} stale pruned (keeping ${current}${legacy:+ and legacy ${legacy}})"
    return 0
}

# scripts/generate_clients.sh is already bash and already does this; the
# installers bake in the server URL and CA, so they have to be rebuilt
# whenever the agent version moves.
_velo_refresh_installers() {
    local s="${SCRIPT_DIR}/scripts/generate_clients.sh"
    [[ -f "$s" ]] || { log_info "  no scripts/generate_clients.sh; skipping installer rebuild"; return 0; }
    if RUN_HEARTBEAT_QUIET=1 run_with_heartbeat "rebuilding client installers" 900 \
         bash -c 'cd "$1" && bash scripts/generate_clients.sh >>"$2" 2>&1' _ "$SCRIPT_DIR" "${LOG_FILE:-/dev/null}"; then
        log_info "  client installers rebuilt"
        return 0
    fi
    log_warn "  could not rebuild the client installers"
    return 1
}
