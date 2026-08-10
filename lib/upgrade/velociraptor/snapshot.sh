#!/bin/bash
# Intact.AI upgrade — Velociraptor's CA fingerprint, config snapshot/restore,
# and the custom-artifact export.
#
# THE GAP THIS FIXES. The Python rollback (velociraptor.py:2220-2260) restores
# .env and the binary but NOT the config files. So a Velociraptor that failed
# its CA check and "rolled back successfully" could be left running with a
# freshly generated CA -- the operator is told the rollback worked, and the
# fleet is still gone. Here the configs are part of the snapshot and part of
# the undo stack.

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
