#!/bin/bash
# Intact.AI Platform Installer — ELK Stack module.

# Kibana's three encryption keys.
#
# Without them Kibana invents a random key for each on every single boot, and
# says so itself — this is Kibana's own log from the 2026-08-16 install, not a
# diagnosis of ours:
#
#   [WARN][plugins.encryptedSavedObjects] Saved objects encryption key is not
#            set. This will severely limit Kibana functionality.
#   [WARN][plugins.actions]  APIs are disabled because the Encrypted Saved
#            Objects plugin is missing encryption key.
#   [WARN][plugins.alerting] APIs are disabled because the Encrypted Saved
#            Objects plugin is missing encryption key.
#   [WARN][plugins.fleet] Fleet setup attempt 8 failed, will retry after
#            backoff FleetEncryptedSavedObjectEncryptionKeyRequired
#
# Alerting and Actions off, Fleet stuck in a retry loop that was still going
# when the support bundle was captured, and every Kibana session invalidated on
# every restart. None of it surfaced in the install log, which reported ELK
# "deployed successfully".
#
# WHY NOT modules/elk/.env: that file is TRACKED (`git ls-files` lists it), and
# .gitignore's own comment at :57 spells out the hazard — "that file is
# tracked, so a credential written there gets staged". So these follow the
# per-module secrets convention that iris / portainer / volweb / timesketch /
# nginx already use: modules/<mod>/secrets/, gitignored, generated on the box.
#
# NEVER ROTATES, for the same reason ensure_elk_credentials never rotates the
# elastic password: the key is what decrypts every saved object already
# written. A new key on an existing cluster orphans them silently. Seeds only
# when genuinely absent — same shape as render_volweb_env_template's
# "already present (skip render — secrets preserved)" guard.
generate_elk_secrets() {
    local elk_enabled
    elk_enabled=$(read_config "['modules']['elk']['enabled']")
    if ! is_enabled "$elk_enabled"; then
        log_info "Generating Kibana encryption keys: SKIPPED (disabled in config)"
        return 0
    fi

    local secrets_dir="${SCRIPT_DIR}/modules/elk/secrets"
    local keyfile="${secrets_dir}/kibana-keys.env"
    mkdir -p "$secrets_dir"

    if [[ -s "$keyfile" ]]; then
        log_info "Kibana encryption keys already present — not rotating"
        chmod 600 "$keyfile" 2>/dev/null || true
        return 0
    fi

    log_info "Generating Kibana encryption keys..."
    # Subshell so the umask cannot leak into the rest of the installer, and so
    # the file is never briefly world-readable between creation and chmod.
    # Kibana needs >= 32 chars; `rand -hex 32` gives 64.
    if ! ( umask 077
           {
               echo "XPACK_ENCRYPTEDSAVEDOBJECTS_ENCRYPTIONKEY=$(openssl rand -hex 32)"
               echo "XPACK_SECURITY_ENCRYPTIONKEY=$(openssl rand -hex 32)"
               echo "XPACK_REPORTING_ENCRYPTIONKEY=$(openssl rand -hex 32)"
           } > "$keyfile" ); then
        log_error "  Could not write ${keyfile}"
        return 1
    fi
    # Read by the docker daemon on the HOST when compose expands env_file, not
    # by the container — so root-only is correct and costs Kibana nothing.
    chmod 600 "$keyfile" 2>/dev/null || true
    log_success "  Kibana encryption keys generated (modules/elk/secrets/kibana-keys.env)"
    return 0
}

# Single-node clusters drift back to YELLOW after the init container has
# already declared them green.
#
# modules/elk/config/setup-kibana-user.sh clears replicas and, on 2026-08-16,
# correctly reported "Cluster status now: green" at 10:49:55. The install's own
# health check then reported "Elasticsearch: yellow" at 10:53:56 — because that
# init container is a one-shot that must complete BEFORE Kibana starts (compose
# gates Kibana on `setup: service_completed_successfully`), so its sweep only
# ever covers indices that existed before Kibana created any of its own.
#
# The obvious fix -- raising the priority of its `index_patterns:["*"]`
# template above Elastic's -- is WRONG and deliberately not done. Composable
# templates do not merge: the highest-priority match wins outright. A `*`
# template above Elastic's own `logs-*-*` / `metrics-*-*` templates would
# replace their ECS mappings as well as their replica count, which trades a
# cosmetic yellow for real mapping damage. The low-priority template stays as
# it is, and this runs afterwards to catch what it could not see.
#
# Runs late (end of run_post_install_init), by which point Kibana has been up
# for minutes. Narrow by construction: does nothing unless the cluster is
# genuinely single-node AND genuinely yellow, and touches nothing but the
# replica count. Never fails the install -- a yellow cluster is serviceable.
elk_settle_single_node_replicas() {
    local elk_enabled
    elk_enabled=$(read_config "['modules']['elk']['enabled']")
    is_enabled "$elk_enabled" || return 0
    docker ps --format '{{.Names}}' 2>/dev/null | grep -qx 'intact_elasticsearch' || return 0

    local user pass health
    user=$(read_config "['modules']['elk']['id']"); user="${user:-elastic}"
    pass=$(read_config "['modules']['elk']['password']")
    health="http://localhost:9200/_cluster/health"

    local body nodes st
    body=$(curl -sf --max-time 10 -u "${user}:${pass}" "$health" 2>/dev/null) || return 0
    nodes=$(sed -n 's/.*"number_of_nodes":\([0-9]*\).*/\1/p' <<< "$body")
    st=$(sed -n 's/.*"status":"\([a-z]*\)".*/\1/p' <<< "$body")
    # A real multi-node deployment WANTS its replicas. Same guard the init
    # container uses, for the same reason.
    [[ "$nodes" == "1" ]] || return 0
    [[ "$st" == "yellow" ]] || return 0

    log_info "  Elasticsearch is ${st} on a single node — clearing replicas on the indices created since startup"
    curl -sf -o /dev/null --max-time 30 -u "${user}:${pass}" \
        -X PUT "http://localhost:9200/*/_settings?expand_wildcards=all" \
        -H 'Content-Type: application/json' \
        -d '{"index":{"number_of_replicas":0}}' 2>/dev/null || true

    local i
    for i in $(seq 1 10); do
        st=$(curl -sf --max-time 5 -u "${user}:${pass}" "$health" 2>/dev/null \
             | sed -n 's/.*"status":"\([a-z]*\)".*/\1/p')
        [[ "$st" == "green" ]] && break
        sleep 2
    done
    # Report what was achieved, not what was attempted.
    if [[ "$st" == "green" ]]; then
        log_success "  Elasticsearch cluster status: green"
    else
        log_info "  Elasticsearch cluster status: ${st:-unknown} (replicas cleared; some shards may still be relocating)"
    fi
    return 0
}

deploy_elk() {
    local elk_enabled=$(read_config "['modules']['elk']['enabled']")
    if ! is_enabled "$elk_enabled"; then
        log_info "[1/8] ELK Stack: SKIPPED (disabled in config)"
        return
    fi

    if is_module_installed intact_elasticsearch; then
        log_info "[1/8] ELK Stack: already installed + running (skipping)"
        return 0
    fi

    log_info "[1/8] Starting ELK Stack..."
    log_info "  Directory: ${SCRIPT_DIR}/modules/elk"
    cd "${SCRIPT_DIR}/modules/elk"

    if ! preflight_host_check "ELK Stack"; then
        log_error "ELK Stack: host pre-flight FAILED — see warnings above"
        track_module_failure "ELK Stack"
        return 1
    fi

    # Show what images will be used
    local elk_version=$(read_config "['versions']['elk']")
    log_info "  Elasticsearch version: ${elk_version:-8.x}"

    # Belt and braces: the orchestrator already ran this with the other secret
    # generators, but the compose file now declares secrets/kibana-keys.env as
    # an env_file and compose hard-errors on a missing one. Idempotent, so the
    # cost of guaranteeing it here is a stat().
    generate_elk_secrets || return 1

    if ! pull_compose_with_retry "ELK Stack"; then
        track_module_failure "ELK Stack"
        return 1
    fi
    if ! run_compose_up_with_retry "ELK"; then
        log_error "  Docker compose failed!"
        track_module_failure "ELK Stack"
        return 1
    fi

    # Show container status
    show_container_status "intact_elasticsearch"
    show_container_status "intact_kibana"

    # Wait for Elasticsearch to be ready
    log_info "  Waiting for Elasticsearch API (http://localhost:9200)..."
    local elk_user=$(read_config "['modules']['elk']['id']")
    local elk_pass=$(read_config "['modules']['elk']['password']")
    local es_wait=0
    local es_max_wait=90
    while [[ $es_wait -lt $es_max_wait ]]; do
        if curl -sf --max-time 5 -u "${elk_user:-elastic}:${elk_pass}" "http://localhost:9200/_cluster/health" > /dev/null 2>&1; then
            log_success "  Elasticsearch is ready! (${es_wait}s)"
            track_module_success "ELK Stack"
            return 0
        fi
        sleep 5
        ((es_wait+=5))
        log_info "  Waiting for Elasticsearch... (${es_wait}/${es_max_wait}s)"
    done

    log_error "  Elasticsearch failed to become ready after ${es_max_wait}s"
    capture_diagnostic_logs "ELK Stack (deploy timeout)" intact_elasticsearch
    track_module_failure "ELK Stack"
    return 1
}
