#!/bin/bash
# Intact.AI upgrade — ELK Stack.
#
# Docs: pull -> stop -> rm -> start against the same data volume -> verify the
# version at :9200. Kibana must land on the EXACT same version as
# Elasticsearch, after it; our compose pins both from the one config.yaml
# `versions.elk` value and Logstash interpolates ${ELASTIC_VERSION} directly,
# so that alignment is structural rather than something to check.

upgrade_module_elk() {
    local target="$1"
    local dir; dir="$(_u_module_dir elk)"
    local envf; envf="$(_u_env_file elk)"
    local bak=""

    u_begin elk

    # Record the pre-upgrade cluster status so the gate can tell "yellow
    # because single-node" from "yellow because we broke something".
    U_ELK_BASELINE_STATUS="$(_u_elk_status)"
    log_info "  cluster status before the upgrade: ${U_ELK_BASELINE_STATUS:-unknown}"

    # Parity with deploy_elk (lib/modules/elk.sh), which install.sh always runs
    # first: systemd health, the thing that broke the 2026-06-15 test-1
    # install by failing cgroup-unit creation mid compose-up. Cheap (a
    # systemctl call), so unconditional here rather than gated to only the
    # first-ever deploy of this module.
    u_do "host preflight" -- preflight_host_check "ELK Stack"
    u_do "elasticsearch credentials" -- ensure_elk_credentials

    bak="$(backup_file_for_rollback "$envf")" || bak=""
    u_undo "_u_compose_up_old elk"
    [[ -n "$bak" ]] && u_undo "restore_file_from_backup '${envf}' '${bak}'"

    u_do --timeout 900 "load elk images" -- \
        _u_load_tars_matching "elasticsearch-" "kibana-" "logstash-"
    u_do "ensure elasticsearch:${target}" -- \
        _u_ensure_image "docker.elastic.co/elasticsearch/elasticsearch:${target}" "elasticsearch-${target}.tar"
    u_do "ensure kibana:${target}" -- \
        _u_ensure_image "docker.elastic.co/kibana/kibana:${target}" "kibana-${target}.tar"
    u_do "ensure logstash:${target}" -- \
        _u_ensure_image "docker.elastic.co/logstash/logstash:${target}" "logstash-${target}.tar"

    u_do --timeout 300 "stop elk" -- _u_compose "$dir" down --remove-orphans
    # Kibana is pinned separately in .env but must equal ES; stamping both
    # from the one target is what enforces the docs' requirement.
    u_do "stamp elk pins" -- _u_stamp "$envf" \
        "ELASTIC_VERSION=${target}" "KIBANA_VERSION=${target}"
    u_do --timeout 900 "start elk" -- \
        _u_compose "$dir" up -d --no-build --pull never

    u_end elk rollback 240
    local rc=$?

    # Best-effort and deliberately AFTER the gate: a missing data view is a
    # cosmetic gap in Kibana, not a reason to roll back a healthy cluster.
    if (( rc == 0 )); then
        _u_kibana_data_view || log_warn "  could not re-assert the Kibana data view"
        discard_backup "$bak"
    fi
    return $rc
}

_u_elk_status() {
    local envf; envf="$(_u_env_file elk)"
    local user pass
    user="$(read_env_var "$envf" ELASTIC_USER 2>/dev/null || echo elastic)"
    pass="$(read_env_var "$envf" ELASTIC_PASSWORD 2>/dev/null || echo '')"
    curl -s --max-time 6 -u "${user}:${pass}" "http://127.0.0.1:9200/_cluster/health" 2>/dev/null \
        | grep -o '"status"[[:space:]]*:[[:space:]]*"[a-z]*"' | grep -o '[a-z]*"$' | tr -d '"'
}

# NEVER ROTATES. Elasticsearch fixes the `elastic` password at initdb, so
# generating a new one on an existing cluster locks the platform out of its
# own data. Seeds a default only when the value is genuinely absent, and says
# so loudly. Ported from elk.py:405-455, but called on BOTH paths -- the
# Python only ran it offline, which is how a security-enabled upgrade left
# Logstash 401-crash-looping while every summary signal stayed green.
ensure_elk_credentials() {
    local envf; envf="$(_u_env_file elk)"
    local backend_env="${SCRIPT_DIR}/modules/backend/.env"
    [[ -f "$envf" ]] || { log_warn "  no modules/elk/.env"; return 0; }

    local user pass kib
    user="$(read_env_var "$envf" ELASTIC_USER 2>/dev/null || echo '')"
    pass="$(read_env_var "$envf" ELASTIC_PASSWORD 2>/dev/null || echo '')"
    kib="$(read_env_var "$envf" KIBANA_PASSWORD 2>/dev/null || echo '')"

    [[ -z "$user" ]] && { user=elastic; update_env_var "$envf" ELASTIC_USER "$user"; }
    if [[ -z "$pass" ]]; then
        pass=changeme
        update_env_var "$envf" ELASTIC_PASSWORD "$pass"
        log_warn "  modules/elk/.env had no ELASTIC_PASSWORD; seeding 'changeme'."
        log_warn "  CHANGE IT: this password gates every index on this appliance."
    fi
    [[ -z "$kib" ]] && update_env_var "$envf" KIBANA_PASSWORD "$pass"

    # The backend reads these too. config.py also falls back to reading
    # modules/elk/.env at runtime, so a running backend recovers without the
    # restart it is not going to get mid-upgrade.
    if [[ -f "$backend_env" ]]; then
        update_env_var "$backend_env" ELASTICSEARCH_USER "$user"
        update_env_var "$backend_env" ELASTICSEARCH_PASSWORD "$pass"
    fi
    return 0
}

# services/kibana_init.py in three curls.
_u_kibana_data_view() {
    local envf; envf="$(_u_env_file elk)"
    local user pass code
    user="$(read_env_var "$envf" ELASTIC_USER 2>/dev/null || echo elastic)"
    pass="$(read_env_var "$envf" ELASTIC_PASSWORD 2>/dev/null || echo '')"
    local kb="http://127.0.0.1:5601"

    local waited=0
    while (( waited < 120 )); do
        code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 -u "${user}:${pass}" \
                "${kb}/api/status" 2>/dev/null)"
        [[ "$code" == "200" ]] && break
        sleep 5; waited=$((waited + 5))
    done
    [[ "$code" == "200" ]] || { log_info "  Kibana did not answer in ${waited}s; skipping the data view"; return 1; }

    if curl -s --max-time 10 -u "${user}:${pass}" "${kb}/api/data_views" 2>/dev/null \
         | grep -q '"title":"artifact\*"'; then
        log_info "  Kibana data view 'artifact*' already present"
        return 0
    fi
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 -u "${user}:${pass}" \
        -X POST "${kb}/api/data_views/data_view" \
        -H 'kbn-xsrf: true' -H 'Content-Type: application/json' \
        -d '{"data_view":{"title":"artifact*","timeFieldName":"@timestamp"}}' 2>/dev/null)"
    [[ "$code" =~ ^(200|201)$ ]] && { log_success "  Kibana data view 'artifact*' created"; return 0; }
    log_warn "  Kibana data view creation returned HTTP ${code}"
    return 1
}
