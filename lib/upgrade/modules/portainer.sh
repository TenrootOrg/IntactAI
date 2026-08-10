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

    u_do "portainer admin secret" -- _u_ensure_portainer_admin_secret
    u_do "portainer agent secret" -- _u_ensure_agent_secret

    bak="$(backup_file_for_rollback "$envf")" || bak=""
    u_undo "_u_compose_up_old portainer"
    [[ -n "$bak" ]] && u_undo "restore_file_from_backup '${envf}' '${bak}'"

    u_do --timeout 600 "load portainer images" -- _u_load_tars_matching "portainer-"
    u_do "ensure portainer-ce:${target}" -- \
        _u_ensure_image "portainer/portainer-ce:${target}" "portainer-ce-${target}.tar"
    u_do "ensure portainer agent:${target}" -- \
        _u_ensure_image "portainer/agent:${target}" "portainer-agent-${target}.tar"

    u_do --timeout 180 "stop portainer" -- _u_compose "$dir" down --remove-orphans
    u_do "stamp portainer pins" -- _u_stamp "$envf" \
        "PORTAINER_VERSION=${target}" "PORTAINER_AGENT_VERSION=${target}"
    u_do "assert server and agent versions match" -- _u_portainer_versions_match
    u_do --timeout 600 "start portainer" -- _u_compose "$dir" up -d --no-build --pull never

    # Promoted from the Python's policy of none. Portainer is a root-privileged
    # Docker API proxy; leaving it silently broken is worse than reverting it,
    # and we now have a working .env-restore rollback to revert WITH.
    u_end portainer rollback 150
    local rc=$?
    (( rc == 0 )) && discard_backup "$bak"
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

# Portainer enforces a 12-character minimum even via --admin-password-file and
# SILENTLY never creates the admin account on a shorter value. The shipped
# default is exactly 12 characters, so the length check alone lets it through
# and it has to be denied by name.
_u_ensure_portainer_admin_secret() {
    local d="${SCRIPT_DIR}/modules/portainer/secrets"
    local f="${d}/admin_password"
    local known_default='1234qwer!@#$'
    mkdir -p "$d" 2>/dev/null
    [[ -s "$f" ]] && return 0

    local pw
    pw="$(read_config "['modules']['portainer']['password']" 2>/dev/null || echo '')"
    [[ "$pw" == "None" ]] && pw=""
    if [[ -z "$pw" || ${#pw} -lt 12 || "$pw" == "$known_default" ]]; then
        [[ "$pw" == "$known_default" ]] && \
            log_warn "  config.yaml still has the shipped default Portainer password; generating a random one"
        pw="$(openssl rand -hex 16)"
    fi
    printf '%s' "$pw" > "$f" || return 1
    chmod 600 "$f"
    log_info "  wrote modules/portainer/secrets/admin_password"
    return 0
}
