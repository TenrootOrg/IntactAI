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

# ---------------------------------------------------------------------------
# Legacy config volume -> host bind-mount.
#
# THE GAP THIS FIXES. Up to 0726 Velociraptor kept /velociraptor -- including
# server.config.yaml, i.e. THE CA -- in a named volume (`velociraptor_data`,
# compose-namespaced to `velociraptor_velociraptor_data`). The host-mount
# conversion replaced that with `data/velociraptor` and DELETED the volume from
# the compose file, pointing at a
# `services/upgrade/velociraptor.migrate_velociraptor_config_to_host()` that has
# never existed anywhere in this tree: it went with the Python engine and was
# never rewritten here. So on any 0615/0726 box the new compose simply stops
# mounting the volume that holds the CA, the bind-mount is empty, entrypoint.sh
# generates a BRAND NEW CA, and every enrolled client is silently orphaned --
# reported only as a yellow "first deploy" line.
#
# Reading the volume by its Mountpoint rather than through a helper container is
# deliberate: this runs air-gapped, and there is no image guaranteed to be on the
# box to `docker run` for the copy. `docker volume inspect` is a public API and
# gives the real path even when Docker's data-root has been moved.
_velo_legacy_volume() {
    local v
    while IFS= read -r v; do
        [[ "$v" == *velociraptor_data ]] && { printf '%s\n' "$v"; return 0; }
    done < <("${DOCKER_BIN:-docker}" volume ls --format '{{.Name}}' 2>/dev/null)
    return 1
}

# Sets _VELO_VOL_MP to the readable host path of <volume>'s content.
#
# AN OUT-VARIABLE, NOT STDOUT, so this runs in the CALLER'S shell.
#
# It used to `printf` the path and be invoked as `mp="$(_velo_volume_path …)"`.
# That command substitution forks, and log_warn does two things (lib/common.sh):
# it writes the line for the operator AND appends to INSTALL_WARNINGS, which
# print_final_issues_report reads at the end of the run. In a fork the append
# dies with the subshell and the console line is swallowed into `mp` -- so both
# warnings below reached $LOG_FILE and nothing else. Measured on a real
# air-gapped upgrade 2026-08-25: "legacy volume velociraptor_velociraptor_data
# has no readable mountpoint" was in the log file, absent from the ATTENTION
# summary, and the summary's own count was one short.
#
# That matters here more than most places: _velo_require_ca tells the operator
# to "see the warnings it printed", and on this path there were none to see.
# Given the standing rule that an upgrade must never lose the Velociraptor CA,
# a warning about the Velociraptor data volume is the last one that should be
# silently dropped.
_velo_volume_path() {
    local vol="$1" driver mp
    _VELO_VOL_MP=""
    driver="$("${DOCKER_BIN:-docker}" volume inspect -f '{{.Driver}}' "$vol" 2>/dev/null)"
    [[ "$driver" == "local" ]] || { log_warn "  legacy volume ${vol} uses the '${driver:-unknown}' driver; cannot read it directly"; return 1; }
    mp="$("${DOCKER_BIN:-docker}" volume inspect -f '{{.Mountpoint}}' "$vol" 2>/dev/null)"
    [[ -n "$mp" && -d "$mp" ]] || { log_warn "  legacy volume ${vol} has no readable mountpoint"; return 1; }
    _VELO_VOL_MP="$mp"
}

# Fingerprint a server.config.yaml at an arbitrary path (velo_ca_fp is fixed to
# the live one).
_velo_ca_fp_of() {
    python3 - "$1" <<'PY' 2>/dev/null
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

# Run BEFORE velo_ca_fp/_velo_snapshot/bring-up. Never destructive: it only ever
# fills an EMPTY host dir. A box that already has a config keeps it.
_velo_migrate_legacy_config() {
    local data; data="$(_VELO_DATA)"
    local host_cfg="${data}/server.config.yaml"
    local vol mp f n=0

    vol="$(_velo_legacy_volume)" || return 0        # nothing legacy -> nothing to do
    _velo_volume_path "$vol" || return 0            # warns in THIS shell, so it is reported
    mp="$_VELO_VOL_MP"

    if [[ ! -f "${mp}/server.config.yaml" ]]; then
        return 0                                    # volume exists but holds no config
    fi

    # Case 1 -- the box already has a live config. Do NOT overwrite it: clients
    # enrolled since would be cut off. But if the CAs differ, this box was
    # upgraded WITHOUT this migration and its original CA is still sitting in the
    # volume, so say so loudly instead of leaving it to be discovered by a fleet
    # that stopped reporting.
    if [[ -f "$host_cfg" ]]; then
        local now old
        now="$(_velo_ca_fp_of "$host_cfg")"
        old="$(_velo_ca_fp_of "${mp}/server.config.yaml")"
        if [[ -n "$now" && -n "$old" && "$now" != "$old" ]]; then
            log_warn "  this box has a DIFFERENT Velociraptor CA than the legacy volume:"
            log_warn "    in use now:    ${now}"
            log_warn "    legacy volume: ${old}  (${vol})"
            log_warn "  It was upgraded before this migration existed, so a new CA was"
            log_warn "  generated and clients enrolled against ${old} can no longer connect."
            log_warn "  The original is intact in ${mp} — restoring it is a deliberate"
            log_warn "  operation (it cuts off anything enrolled since), so it is not done"
            log_warn "  automatically here."
        fi
        return 0
    fi

    # Case 2 -- the host dir is empty and the volume has the CA. This is the
    # 0615/0726 upgrade path: migrate, or the next line of code generates a new CA.
    mkdir -p "$data" || return 1
    for f in server.config.yaml client.config.yaml api.config.yaml velociraptor; do
        if [[ -f "${mp}/${f}" ]]; then
            cp -p "${mp}/${f}" "${data}/${f}" || {
                log_error "  could not copy ${f} out of ${vol}"
                return 1
            }
            n=$((n + 1))
        fi
    done
    (( n )) || return 0
    log_success "  migrated ${n} Velociraptor config file(s) from the legacy volume ${vol}"
    log_info "  CA preserved: $(_velo_ca_fp_of "$host_cfg")  (the volume is left untouched)"
    return 0
}

# A missing CA is only acceptable when the module has genuinely never been
# deployed. If a legacy config volume exists, a CA existed and we failed to
# bring it across -- starting Velociraptor then REPLACES it with a new one and
# every enrolled client is orphaned, unrecoverably from the client side. On the
# real 0615 -> 0813 run that path was taken silently behind a yellow
# "first deploy" line, which is exactly why this is now a hard failure.
_velo_require_ca() {
    [[ -n "$(velo_ca_fp)" ]] && return 0

    local vol
    if ! vol="$(_velo_legacy_volume)"; then
        log_info "  no CA and no legacy volume — genuine first deploy, continuing"
        return 0
    fi
    log_error "  no CA on the host, but the legacy config volume ${vol} exists."
    log_error "  Starting Velociraptor now would generate a NEW CA and orphan every"
    log_error "  enrolled client. Refusing. The migration step above should have"
    log_error "  recovered it — see the warnings it printed; the volume itself is"
    log_error "  untouched, so the original CA is still recoverable."
    return 1
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
