#!/bin/bash
# Intact.AI upgrade — Velociraptor.
#
# Velocidex's own upgrade guidance is short and has one absolute rule:
#
#     "When upgrading to a new version, you must re-use your existing config
#      file to preserve the key material and maintain client communication."
#
# That is the whole module. server.config.yaml carries the CA private key; if
# it is regenerated, every enrolled endpoint silently stops reporting. Nothing
# errors, nothing goes red, the GUI comes up looking perfect and the fleet is
# simply gone. So the CA fingerprint is captured before the swap and verified
# after, and a verified change fails the transaction.
#
# THE GAP THIS FIXES. The Python rollback (velociraptor.py:2220-2260) restores
# .env and the binary but NOT the config files. So a Velociraptor that failed
# its CA check and "rolled back successfully" could be left running with a
# freshly generated CA -- the operator is told the rollback worked, and the
# fleet is still gone. Here the configs are part of the snapshot and part of
# the undo stack.
#
# The ~1,400 lines of artifact-catalog, tool-inventory, offline-collector and
# downloads-page work that the Python did inside the upgrade live in
# velo_refresh.sh instead. They are platform features that happen to need
# doing after a version change, not part of the version change.

_VELO_DIR() { echo "${SCRIPT_DIR}/modules/velociraptor"; }
_VELO_DATA() { echo "${SCRIPT_DIR}/data/velociraptor"; }

# sha256[:16] of the CA private key. Falls back to the client's copy of the CA
# certificate, which changes in lockstep. Empty output means "could not read",
# which is deliberately different from "changed".
velo_ca_fp() {
    python3 - "$(_VELO_DATA)/server.config.yaml" <<'PY' 2>/dev/null
import hashlib, sys
try:
    import yaml
    d = yaml.safe_load(open(sys.argv[1], encoding="utf-8")) or {}
except Exception:
    print(""); raise SystemExit(0)
ca = (d.get("CA") or {}).get("private_key") \
     or (d.get("Client") or {}).get("ca_certificate") or ""
print(hashlib.sha256(ca.encode()).hexdigest()[:16] if ca else "")
PY
}

# One VQL entry point. The container's own binary speaks VQL, so nothing here
# needs gRPC or pyvelociraptor -- which is what let the artifact work move out
# of the backend entirely.
velo_vql() {
    "${DOCKER_BIN:-docker}" exec intact_velociraptor \
        /velociraptor/velociraptor --config /velociraptor/server.config.yaml \
        query "$1" --format jsonl 2>/dev/null
}

velo_vql_ready() {
    local timeout="${1:-120}" i
    for (( i = 0; i < timeout; i += 5 )); do
        [[ "$(velo_vql 'SELECT 1 AS ok FROM scope()' | head -1)" == '{"ok":1}' ]] && return 0
        sleep 5
    done
    return 1
}

upgrade_module_velociraptor() {
    local target="$1"
    local dir; dir="$(_VELO_DIR)"
    local data; data="$(_VELO_DATA)"
    local envf="${dir}/.env"
    local bak="" snap="" ca_before=""

    u_begin velociraptor

    ca_before="$(velo_ca_fp)"
    if [[ -z "$ca_before" ]]; then
        log_warn "  could not read the CA fingerprint before the upgrade;"
        log_warn "  the post-upgrade check will not be able to prove it is unchanged"
    else
        log_info "  CA fingerprint before: ${ca_before}"
    fi

    # Snapshot BEFORE anything stops. All three configs, not just .env --
    # this is the gap the Python left open.
    snap="${SCRIPT_DIR}/data/tmp/velo-upgrade-$(date +%Y%m%d_%H%M%S)"
    u_do "snapshot configs and binary" -- _velo_snapshot "$snap"

    bak="$(backup_file_for_rollback "$envf")" || bak=""
    u_undo "_u_compose_up_old velociraptor"
    u_undo "_velo_restore '${snap}'"
    [[ -n "$bak" ]] && u_undo "restore_file_from_backup '${envf}' '${bak}'"

    # Best-effort: hand-written artifacts the operator added through the GUI.
    # Wrapped so a failure here never colours the run -- there may be none, as
    # on a stock box where all 437 artifacts are built-in.
    _velo_export_custom_artifacts "$snap" || true

    u_do --timeout 300 "stop velociraptor" -- _u_compose "$dir" down --remove-orphans
    u_do "stamp velociraptor pins" -- _velo_stamp_env "$envf" "$target"
    u_do --timeout 600 "stage client binaries" -- _velo_stage_binaries "$target"
    u_do --timeout 1200 "resolve velociraptor-server:${target}" -- _velo_resolve_image "$target"
    u_do --timeout 600 "start velociraptor" -- _u_compose "$dir" up -d --no-build --pull never

    # THE CHECK. Give the server a moment to write anything it is going to
    # write, then compare.
    u_do "verify the CA is unchanged" -- _velo_verify_ca "$ca_before"

    u_end velociraptor rollback 240
    local rc=$?
    if (( rc == 0 )); then
        discard_backup "$bak"
        rm -rf "$snap"
    else
        log_warn "  the pre-upgrade snapshot is kept at ${snap}"
    fi
    return $rc
}

_velo_snapshot() {
    local snap="$1" data; data="$(_VELO_DATA)"
    mkdir -p "${snap}/config" || return 1
    local f found=0
    for f in server.config.yaml client.config.yaml api.config.yaml; do
        if [[ -f "${data}/${f}" ]]; then
            cp -p "${data}/${f}" "${snap}/config/${f}" || return 1
            found=1
        fi
    done
    if (( ! found )); then
        # NOT an error: a module enabled but never before deployed (turned
        # on in config.yaml, then upgraded rather than installed) has an
        # empty data/velociraptor/ by design -- entrypoint.sh generates
        # server.config.yaml into it on first start, the same as a fresh
        # install.sh run. Nothing exists yet to snapshot, so there is
        # nothing for a rollback to need either.
        log_info "  no existing velociraptor config -- nothing to snapshot (first deploy)"
        return 0
    fi
    [[ -f "${data}/velociraptor" ]] && cp -p "${data}/velociraptor" "${snap}/velociraptor"
    log_info "  snapshotted configs to ${snap}"
    return 0
}

_velo_restore() {
    local snap="$1" data; data="$(_VELO_DATA)"
    [[ -d "${snap}/config" ]] || return 1
    local f
    for f in "${snap}/config/"*; do
        [[ -f "$f" ]] || continue
        # cp onto the existing path, preserving the inode: these are
        # bind-mounted into a container that may already be running.
        cp -p "$f" "${data}/$(basename "$f")" || return 1
        chmod 0600 "${data}/$(basename "$f")" 2>/dev/null
    done
    [[ -f "${snap}/velociraptor" ]] && { cp -p "${snap}/velociraptor" "${data}/velociraptor"; chmod 755 "${data}/velociraptor"; }
    return 0
}

# VELOCIRAPTOR_TAG is the major.minor the Dockerfile's download URL uses;
# VELOCIRAPTOR_VERSION is the full pin.
_velo_stamp_env() {
    local envf="$1" target="$2"
    local tag; tag="$(sed 's/^\([0-9]*\.[0-9]*\).*/\1/' <<< "$target")"
    _u_stamp "$envf" "VELOCIRAPTOR_VERSION=${target}" "VELOCIRAPTOR_TAG=${tag}" || return 1
    return 0
}

# The Dockerfile COPYs four client binaries unconditionally, so all four paths
# must exist or the build fails on a missing COPY source. Only linux is
# genuinely required -- it is the server binary too. mac and windows get
# zero-byte placeholders when unavailable, which is what the Python did and
# for the same reason.
_velo_stage_binaries() {
    local target="$1" dir; dir="$(_VELO_DIR)"
    local pkgbin="${UPKG_DIR}/binaries"
    mkdir -p "${dir}/clients/linux" "${dir}/clients/mac" "${dir}/clients/windows"

    local linux_dst="${dir}/clients/linux/velociraptor"
    if [[ -d "$pkgbin" ]]; then
        local f
        f="$(find "$pkgbin" -maxdepth 2 -name "*linux-amd64*" -type f 2>/dev/null | head -1)"
        [[ -n "$f" ]] && { cp -f "$f" "$linux_dst"; log_info "  staged the linux binary from the package"; }
        f="$(find "$pkgbin" -maxdepth 2 -name "*darwin*" -o -name "*mac*" -type f 2>/dev/null | head -1)"
        [[ -n "$f" ]] && cp -f "$f" "${dir}/clients/mac/velociraptor_client"
        f="$(find "$pkgbin" -maxdepth 2 -name "*windows-amd64.exe" -type f 2>/dev/null | head -1)"
        [[ -n "$f" ]] && cp -f "$f" "${dir}/clients/windows/velociraptor_client.exe"
        f="$(find "$pkgbin" -maxdepth 2 -name "*.msi" -type f 2>/dev/null | head -1)"
        [[ -n "$f" ]] && cp -f "$f" "${dir}/clients/windows/velociraptor_client.msi"
    fi

    if [[ ! -s "$linux_dst" ]]; then
        # If the image already exists we never build, so a missing binary is
        # harmless; only fail when a build is actually going to happen.
        if _u_image_present "velociraptor-server:${target}"; then
            log_info "  no linux binary staged, but velociraptor-server:${target} already exists"
        else
            log_error "  no linux velociraptor binary in the package and no prebuilt image"
            return 1
        fi
    fi

    # chmod 755 explicitly, not chmod +x: umask can mask the group/other bits
    # and the container runs as a different uid than the one staging these.
    [[ -s "$linux_dst" ]] && chmod 755 "$linux_dst"
    local p
    for p in "${dir}/clients/mac/velociraptor_client" \
             "${dir}/clients/windows/velociraptor_client.exe" \
             "${dir}/clients/windows/velociraptor_client.msi"; do
        [[ -e "$p" ]] || { : > "$p"; log_info "  placeholder for $(basename "$p") (not in this package)"; }
    done
    return 0
}

# Present -> load the tar -> build. Building is last and loudly flagged: it
# runs apt-get and cannot work air-gapped.
_velo_resolve_image() {
    local target="$1" dir; dir="$(_VELO_DIR)"
    local ref="velociraptor-server:${target}"

    _u_image_present "$ref" && { log_info "  ${ref} already present"; return 0; }

    local tar="${UPKG_DIR}/images/velociraptor-${target}.tar"
    if [[ -f "$tar" ]]; then
        log_info "  loading ${ref} from the package"
        "${DOCKER_BIN:-docker}" load -i "$tar" >>"${LOG_FILE:-/dev/null}" 2>&1 \
            && _u_image_present "$ref" && return 0
        log_warn "  the bundled tar did not yield ${ref}"
    fi

    if [[ "${INTACT_UPGRADE_OFFLINE:-0}" == "1" ]]; then
        log_error "  ${ref} is absent and building it needs network access"
        return 1
    fi
    log_warn "  ${ref} is not present and the package does not carry it — building."
    log_warn "  This runs apt-get and WILL fail on an air-gapped host."
    ( cd "$dir" && "${DOCKER_BIN:-docker}" compose build >>"${LOG_FILE:-/dev/null}" 2>&1 ) || {
        log_error "  velociraptor image build failed"; return 1; }
    _u_image_present "$ref"
}

_velo_verify_ca() {
    local before="$1"
    # The server writes its config on first start; give it a moment rather
    # than racing it and reporting a false change.
    sleep 5
    local after; after="$(velo_ca_fp)"

    if [[ -z "$before" ]]; then
        log_warn "  no pre-upgrade CA fingerprint to compare against"
        return 0
    fi
    if [[ -z "$after" ]]; then
        # Unreadable is NOT the same as changed. Failing here would roll back
        # a perfectly good upgrade over a transient read.
        log_warn "  could not read the CA fingerprint after the upgrade; not treating this as a change"
        return 0
    fi
    if [[ "$before" != "$after" ]]; then
        if [[ "${INTACT_ALLOW_VELO_CA_CHANGE:-0}" == "1" ]]; then
            log_warn "  CA CHANGED ${before} -> ${after}, allowed by INTACT_ALLOW_VELO_CA_CHANGE"
            return 0
        fi
        log_error "  THE VELOCIRAPTOR CA CHANGED: ${before} -> ${after}"
        log_error "  Every enrolled endpoint authenticates against this CA. A new one means"
        log_error "  the entire fleet silently stops reporting — nothing errors, the GUI comes"
        log_error "  up looking fine, and the endpoints are simply gone. Rolling back."
        return 1
    fi
    log_success "  CA unchanged (${after}) — enrolled endpoints keep working"
    return 0
}

_velo_export_custom_artifacts() {
    local snap="$1"
    local out="${snap}/exported_artifacts"
    velo_vql_ready 30 || return 1
    mkdir -p "$out" 2>/dev/null
    local n
    n="$(velo_vql "SELECT name, raw FROM artifact_definitions() WHERE built_in = false AND raw != ''" \
         | python3 -c "
import json, os, sys
out = sys.argv[1]; n = 0
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    try: row = json.loads(line)
    except Exception: continue
    name = (row.get('name') or '').replace('.', '__').replace('/', '__')
    raw = row.get('raw') or ''
    if not name or not raw: continue
    open(os.path.join(out, name + '.yaml'), 'w', encoding='utf-8').write(raw)
    n += 1
print(n)
" "$out" 2>/dev/null)"
    if [[ "${n:-0}" -gt 0 ]]; then
        log_info "  exported ${n} custom artifact(s) before the upgrade"
    else
        log_info "  no custom artifacts to export (all definitions are built-in)"
    fi
    return 0
}
