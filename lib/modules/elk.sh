#!/bin/bash
# Intact.AI Platform Installer — ELK Stack module.

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
