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
# The ~1,400 lines of artifact-catalog, tool-inventory, offline-collector and
# downloads-page work that the Python did inside the upgrade live in
# velo_refresh.sh instead. They are platform features that happen to need
# doing after a version change, not part of the version change.
#
# Sibling files: snapshot.sh (CA fingerprint, config snapshot/restore/verify,
# custom-artifact export -- see its own header for the rollback gap it
# fixes), image.sh (env pin, client binaries, the server image).

_VELO_DIR() { echo "${SCRIPT_DIR}/modules/velociraptor"; }
_VELO_DATA() { echo "${SCRIPT_DIR}/data/velociraptor"; }

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

# The server address the CLIENTS are told to call home to.
#
# modules/velociraptor/.env ships in the repo with a developer's address baked
# in (VELOX_SERVER_URL=https://192.168.120.11:8000/). update_env_files rewrites
# it from config.yaml's `domain` — but that is the INSTALL path, and nothing
# under lib/upgrade/ ever did. On a normal upgrade it does not matter, because
# install.sh already corrected it. It matters enormously when Velociraptor is
# installed BY AN UPGRADE: an operator enabling it in config.yaml and
# upgrading rather than re-running install.sh gets a server that starts, passes
# every health probe, and hands out clients pointing at 192.168.120.11.
#
# Measured on a backend-only box that adopted all nine modules through the
# dashboard: the client installed, started, and spent ten minutes logging
# `While getting https://192.168.120.11:8000/ ... Waiting for a reachable
# server` before the enrolment timed out.
#
# Idempotent: on any box install.sh has touched these already equal `domain`,
# so this rewrites nothing.
_velo_stamp_domain() {
    local envf="$1" domain
    [[ -f "$envf" ]] || return 0
    domain="$(read_config "['domain']" 2>/dev/null || echo '')"
    if [[ -z "$domain" || "$domain" == "None" ]]; then
        log_warn "  config.yaml has no domain; leaving the Velociraptor URLs alone"
        return 0
    fi
    update_env_var "$envf" "VELOX_FRONTEND_HOSTNAME" "$domain"
    update_env_var "$envf" "VELOX_PUBLIC_IP"         "$domain"
    update_env_var "$envf" "VELOX_SERVER_URL"        "https://${domain}:8000/"
    return 0
}

upgrade_module_velociraptor() {
    local target="$1"
    local dir; dir="$(_VELO_DIR)"
    local data; data="$(_VELO_DATA)"
    local envf="${dir}/.env"
    local bak="" snap="" ca_before=""

    u_begin velociraptor

    # Up to 0726 the CA lived in the velociraptor_data VOLUME, not on the host.
    # Recover it before anything reads, snapshots or starts against an empty
    # data dir -- otherwise entrypoint.sh mints a new CA and orphans the fleet.
    u_do "migrate legacy config volume" -- _velo_migrate_legacy_config

    # Nothing has been changed at this point (the migration only ever fills an
    # EMPTY data dir), so failing here is free -- and far cheaper than starting
    # a server that mints a new CA.
    u_do "confirm a CA survived the migration" -- _velo_require_ca

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
    # config.yaml too, not just the .env. `--only elk` is supported and skips
    # the intact module that would normally merge the package pins in, so
    # config.yaml keeps the OLD version while the module moves. That is not
    # cosmetic: update_env_files (install.sh, change_ip.sh) re-derives every
    # module .env FROM config.yaml, so the next repair silently REGRESSES the
    # pin -- and for Elasticsearch a regressed pin means the node refuses to
    # start at all against a data directory a newer version wrote. Observed on
    # this box 2026-08-13. plaso and aws_sigma already did this.
    # Registered BEFORE the pin, so the undo stack holds the pre-upgrade value.
    # This module pinned config.yaml with no undo at all, so a velociraptor
    # rollback restored its .env and left config.yaml naming the version it had
    # just rolled back from -- and update_env_files re-derives .env FROM
    # config.yaml, so the next repair pushed it forward again unattended.
    u_undo_pin velociraptor
    u_do "pin velociraptor in config.yaml" -- _pin_module_version velociraptor "$target"
    u_do "point velociraptor at this appliance" -- _velo_stamp_domain "$envf"
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
