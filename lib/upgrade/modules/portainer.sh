#!/bin/bash
# Intact.AI upgrade — Portainer.
#
# Docs: stop -> rm -> pull -> run against the SAME portainer_data volume.
# "Always match the agent version to the Portainer Server version", which is
# why one pin stamps both and the two are asserted equal.

upgrade_module_portainer() {
    local target="$1"
    local dir; dir="$(_u_module_dir portainer)"
    local envf; envf="$(_u_env_file portainer)"
    local bak=""

    u_begin portainer

    u_do "shared TLS cert" -- _u_ensure_nginx_cert
    u_do "portainer admin secret" -- _u_ensure_portainer_admin_secret
    u_do "portainer agent secret" -- _u_ensure_agent_secret

    bak="$(backup_file_for_rollback "$envf")" || bak=""
    u_undo "_u_compose_up_old portainer"
    [[ -n "$bak" ]] && u_undo "restore_file_from_backup '${envf}' '${bak}'"

    u_do --timeout 600 "load portainer images" -- _u_load_module_images portainer "portainer-"
    u_do "ensure portainer-ce:${target}" -- \
        _u_ensure_image "portainer/portainer-ce:${target}" "portainer-ce-${target}.tar"
    u_do "ensure portainer agent:${target}" -- \
        _u_ensure_image "portainer/agent:${target}" "portainer-agent-${target}.tar"

    u_do --timeout 180 "stop portainer" -- _u_compose "$dir" down --remove-orphans
    u_do "stamp portainer pins" -- _u_stamp "$envf" \
        "PORTAINER_VERSION=${target}" "PORTAINER_AGENT_VERSION=${target}"
    # config.yaml too, not just the .env. `--only elk` is supported and skips
    # the intact module that would normally merge the package pins in, so
    # config.yaml keeps the OLD version while the module moves. That is not
    # cosmetic: update_env_files (install.sh, change_ip.sh) re-derives every
    # module .env FROM config.yaml, so the next repair silently REGRESSES the
    # pin -- and for Elasticsearch a regressed pin means the node refuses to
    # start at all against a data directory a newer version wrote. Observed on
    # this box 2026-08-13. plaso and aws_sigma already did this.
    u_undo_pin portainer
    u_do "pin portainer in config.yaml" -- _pin_module_version portainer "$target"
    u_do "assert server and agent versions match" -- _u_portainer_versions_match
    u_do --timeout 600 "start portainer" -- _u_compose "$dir" up -d --no-build --pull never

    # Promoted from the Python's policy of none. Portainer is a root-privileged
    # Docker API proxy; leaving it silently broken is worse than reverting it,
    # and we now have a working .env-restore rollback to revert WITH.
    u_end portainer rollback 150
    local rc=$?
    if (( rc == 0 )); then
        discard_backup "$bak"
        _u_creds_after portainer
    fi
    return $rc
}

_u_portainer_versions_match() {
    local envf; envf="$(_u_env_file portainer)"
    local s a
    s="$(read_env_var "$envf" PORTAINER_VERSION)"
    a="$(read_env_var "$envf" PORTAINER_AGENT_VERSION)"
    if [[ "$s" != "$a" ]]; then
        log_error "  server (${s}) and agent (${a}) versions differ; Portainer requires them equal"
        return 1
    fi
    return 0
}

# The ONLY thing authenticating callers to portainer-agent, which is a full
# Docker API proxy running as root with docker.sock mounted. It was previously
# never set at all. Generated once and NEVER rotated -- rotating unpairs a
# working server/agent. The compose declares `env_file: ./secrets/agent.env`
# for both services, so a box upgraded without this fails `up` outright.
_u_ensure_agent_secret() {
    local d="${SCRIPT_DIR}/modules/portainer/secrets"
    local f="${d}/agent.env"
    mkdir -p "$d" 2>/dev/null
    if [[ -s "$f" ]] && grep -q '^AGENT_SECRET=..' "$f"; then
        return 0
    fi
    printf 'AGENT_SECRET=%s\n' "$(openssl rand -hex 32)" > "$f" || return 1
    chmod 600 "$f"
    chown --reference="$d" "$f" 2>/dev/null
    log_info "  generated modules/portainer/secrets/agent.env"
    return 0
}

# secrets/admin_password: config.yaml's value or a generated one for a Portainer
# with no data yet (Portainer silently never creates the admin on a value under
# 12 characters, and the shipped ones are public -- secret_check refuses both).
# With data, the value it was created from is kept (_u_creds_migrate).
_u_ensure_portainer_admin_secret() {
    _u_creds_migrate portainer || return 1
    cred_get portainer >/dev/null 2>&1 && return 0
    # Data, and no password anywhere. Portainer reads the file at its FIRST
    # start only, so a random one changes nothing it holds -- but compose needs
    # the file (a missing bind source becomes a directory and the container
    # dies). The .placeholder marker says it is not the login: cred_get then
    # reports "unknown", show-credentials says so, and neither the rotation
    # nor apply-passwords.sh ever sends it to Portainer.
    _cred_put portainer "$(secret_generate)" || return 1
    ( umask 077; : > "$(_cred_placeholder portainer)" ) || return 1
    log_warn "  portainer: wrote a placeholder admin_password; the admin keeps the password Portainer already has"
    return 0
}
