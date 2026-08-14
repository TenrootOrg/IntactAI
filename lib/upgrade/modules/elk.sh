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
    u_do "shared TLS cert" -- _u_ensure_nginx_cert
    u_do "elasticsearch credentials" -- ensure_elk_credentials

    bak="$(backup_file_for_rollback "$envf")" || bak=""
    u_undo "_u_compose_up_old elk"
    [[ -n "$bak" ]] && u_undo "_u_elk_restore_env '${envf}' '${bak}' '${target}'"

    u_do --timeout 900 "load elk images" -- \
        _u_load_module_images elk "elasticsearch-" "kibana-" "logstash-"
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
    # config.yaml too, not just the .env. `--only elk` is supported and skips
    # the intact module that would normally merge the package pins in, so
    # config.yaml keeps the OLD version while the module moves. That is not
    # cosmetic: update_env_files (install.sh, change_ip.sh) re-derives every
    # module .env FROM config.yaml, so the next repair silently REGRESSES the
    # pin -- and for Elasticsearch a regressed pin means the node refuses to
    # start at all against a data directory a newer version wrote. Observed on
    # this box 2026-08-13. plaso and aws_sigma already did this.
    u_undo_pin elk
    u_do "pin elk in config.yaml" -- _pin_module_version elk "$target"
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

# Restore elk's .env on a rollback WITHOUT downgrading Elasticsearch.
#
# Elasticsearch migrates its data directory the first time it starts on a new
# version and then refuses to open it on an older one:
#
#   cannot downgrade a node from version [9.4.4] to version [9.4.2]
#
# So a plain restore of the .env is destructive exactly when the upgrade got
# far enough to start ES. Observed 2026-08-12 on a real 0726 -> 0811 upgrade:
# ES came up healthy at 9.4.4, the elk_setup container then failed for an
# unrelated reason (a bind-mounted script that never arrived), the module
# rolled the pins back to 9.4.2, and Elasticsearch could not start at all
# afterwards. The rollback left the box in a worse state than the failure --
# the one thing a rollback must never do.
#
# Everything else in the .env is still restored; only the two version pins are
# held forward, because they are the only ones ES's own on-disk state has an
# opinion about. Detected from the container's image rather than by parsing
# ES's node metadata: if the ES container was created from the target image, it
# started, and if it started the data directory is already migrated.
_u_elk_restore_env() {
    local envf="$1" bak="$2" target="$3"
    restore_file_from_backup "$envf" "$bak" || return 1

    local img
    img="$("${DOCKER_BIN:-docker}" inspect intact_elasticsearch \
           --format '{{.Config.Image}}' 2>/dev/null)" || return 0
    [[ "$img" == *":${target}" ]] || return 0

    log_warn "  Elasticsearch already started at ${target}, so its data directory is"
    log_warn "  migrated and it will refuse to open at an older version. Holding the elk"
    log_warn "  pins at ${target} — restoring them would leave Elasticsearch unable to"
    log_warn "  start at all, which is worse than the failure being rolled back."
    _u_stamp "$envf" "ELASTIC_VERSION=${target}" "KIBANA_VERSION=${target}"
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
    # HTTPS, AND -k. Kibana serves TLS itself (modules/elk/docker-compose.yaml
    # sets SERVER_SSL_ENABLED=true with its own cert), so `http://` here never
    # got an answer and this function could not succeed on any box. The failure
    # read like impatience rather than a wrong scheme:
    #
    #   17:57:44  Kibana http server running at https://0.0.0.0:5601
    #   17:57:46  Kibana is now available
    #   17:58:59  Kibana did not answer in 120s; skipping the data view
    #
    # Kibana had been up for 73s. Elasticsearch sits directly above Kibana in
    # that compose file with xpack.security.http.ssl.enabled=false, which is
    # very likely where the plain-HTTP assumption came from.
    #
    # health/probes.sh already documents that an HTTP probe on 5601 "would
    # report a false outage", and lib/health.sh prints https://…:5601 -- this
    # was the last caller still on http://. Localhost rather than the container
    # name because this runs on the HOST, where intact_kibana does not resolve.
    local kb="https://127.0.0.1:5601"

    # Title, name and 409-handling are kept identical to
    # modules/backend/services/kibana_init.py, which is the canonical client.
    # They had drifted: this asserted "artifact*" while the backend creates
    # "artifact_*". Fixing only the scheme would therefore have created a
    # SECOND, near-duplicate data view in Discover -- worse than the silent
    # no-op it replaced.
    local view_title="artifact_*"
    local view_name="Velociraptor Artifacts"

    # Kibana rebuilds its saved objects after an upgrade and answers late: on a
    # swapping box it took ~10 minutes from container start. 120s was only
    # harmless while the scheme was wrong and nothing could succeed anyway.
    local deadline=600
    local waited=0
    while (( waited < deadline )); do
        code="$(curl -sk -o /dev/null -w '%{http_code}' --max-time 5 -u "${user}:${pass}" \
                "${kb}/api/status" 2>/dev/null)"
        [[ "$code" == "200" ]] && break
        sleep 5; waited=$((waited + 5))
    done
    [[ "$code" == "200" ]] || { log_info "  Kibana did not answer in ${waited}s; skipping the data view"; return 1; }

    if curl -sk --max-time 10 -u "${user}:${pass}" "${kb}/api/data_views" 2>/dev/null \
         | grep -qF "\"title\":\"${view_title}\""; then
        log_info "  Kibana data view '${view_title}' already present"
        return 0
    fi
    code="$(curl -sk -o /dev/null -w '%{http_code}' --max-time 20 -u "${user}:${pass}" \
        -X POST "${kb}/api/data_views/data_view" \
        -H 'kbn-xsrf: true' -H 'Content-Type: application/json' \
        -d "{\"data_view\":{\"title\":\"${view_title}\",\"name\":\"${view_name}\",\"timeFieldName\":\"@timestamp\"}}" 2>/dev/null)"
    # 409 is success: the backend's own initialiser may have created it first.
    [[ "$code" == "409" ]] && { log_info "  Kibana data view '${view_title}' already present"; return 0; }
    [[ "$code" =~ ^(200|201)$ ]] && { log_success "  Kibana data view '${view_title}' created"; return 0; }
    log_warn "  Kibana data view creation returned HTTP ${code}"
    return 1
}
