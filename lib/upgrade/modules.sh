#!/bin/bash
# Intact.AI upgrade — the modules whose upgrade is a version swap plus a
# little care: elk, iris, portainer, volweb, plaso, aws_sigma, o365rc.
#
# Timesketch, Velociraptor and intact each need enough of their own machinery
# to live in their own file.
#
# Every function here is the same nine-ish lines: open a transaction, register
# the undos coarsest-first, run the documented steps, close with the health
# gate. Anything that looks like retry, rollback or failure accounting belongs
# in core.sh, not here.

# ---------------------------------------------------------------------------
# Shared plumbing
# ---------------------------------------------------------------------------

_u_module_dir() { echo "${SCRIPT_DIR}/modules/$1"; }
_u_env_file()   { echo "${SCRIPT_DIR}/modules/$1/.env"; }

# docker compose in a module directory, output tee'd into the run log.
_u_compose() {
    local dir="$1"; shift
    ( cd "$dir" || exit 2
      "${DOCKER_BIN:-docker}" compose "$@" >>"${LOG_FILE:-/dev/null}" 2>&1 )
}

# The coarse "put it back the way it was" undo. Registered FIRST by every
# module so it unwinds LAST -- after the .env and any other files are already
# restored, because it is what reads them.
_u_compose_up_old() {
    local dir; dir="$(_u_module_dir "$1")"
    _u_compose "$dir" up -d --no-build --pull never
}

_u_image_present() {
    "${DOCKER_BIN:-docker}" image inspect "$1" >/dev/null 2>&1
}

# Make an image available, in this order: already local -> load the tar the
# package carries -> pull. A MISSING IMAGE IS FATAL, never a warning: stamping
# a pin for an image that exists nowhere reports "upgraded" and only surfaces
# later when the container will not start. That exact failure is why
# plaso.py:109-131 exists.
_u_ensure_image() {
    local ref="$1" tarname="${2:-}"
    if _u_image_present "$ref"; then
        log_info "  image present: ${ref}"
        return 0
    fi
    if [[ -n "$tarname" && -f "${UPKG_DIR}/images/${tarname}" ]]; then
        log_info "  loading ${tarname} from the package"
        if RUN_HEARTBEAT_QUIET=1 run_with_heartbeat "loading ${tarname}" 1800 \
             bash -c '"$1" load -i "$2" >>"$3" 2>&1' _ "${DOCKER_BIN:-docker}" \
             "${UPKG_DIR}/images/${tarname}" "${LOG_FILE:-/dev/null}"; then
            _u_image_present "$ref" && return 0
            log_error "  ${tarname} loaded but ${ref} is still not present"
            return 1
        fi
        log_error "  could not load ${tarname}"
        return 1
    fi
    if [[ "${INTACT_UPGRADE_OFFLINE:-0}" == "1" ]]; then
        log_error "  ${ref} is not installed and the package does not carry it"
        return 1
    fi
    log_info "  pulling ${ref}"
    RUN_HEARTBEAT_QUIET=1 run_with_heartbeat "pulling ${ref}" 1800 \
        bash -c '"$1" pull "$2" >>"$3" 2>&1' _ "${DOCKER_BIN:-docker}" "$ref" "${LOG_FILE:-/dev/null}"
}

# Load every image tar in the package whose filename starts with one of the
# given prefixes. Used by modules with several images behind one pin.
_u_load_tars_matching() {
    local prefix f n=0
    for prefix in "$@"; do
        for f in "${UPKG_DIR}"/images/${prefix}*.tar; do
            [[ -f "$f" ]] || continue
            log_info "  loading $(basename "$f")"
            RUN_HEARTBEAT_QUIET=1 run_with_heartbeat "loading $(basename "$f")" 1800 \
                bash -c '"$1" load -i "$2" >>"$3" 2>&1' _ "${DOCKER_BIN:-docker}" \
                "$f" "${LOG_FILE:-/dev/null}" && n=$((n + 1))
        done
    done
    log_info "  loaded ${n} image tar(s) from the package"
    return 0
}

# ---------------------------------------------------------------------------
# _u_stamp_transitive <module>
#
# Sidecar pins: OpenSearch, Postgres, Redis, RabbitMQ, nginx, tusd. These are
# NOT the module's own version -- they are the versions of the containers it
# runs alongside, and every one of them is interpolated by the module's
# compose file as ${VAR:?...}.
#
# Without this an upgrade moves the application image and leaves its sidecars
# on the old pins, silently: the compose file still resolves, the stack still
# comes up, and Timesketch 20261201 ends up talking to the OpenSearch 2.19.5
# it was never tested against. Nothing errors. That is why the Python did this
# before every compose-up (base.py:stamp_transitive_env_from_manifest) and why
# its absence here was a real gap rather than a missing nicety.
#
# The MANIFEST wins over config.yaml. config.yaml only carries the new sidecar
# pins after the `intact` module has merged them in, and intact can be skipped
# (--only elk) or can fail -- in either case config.yaml still holds the OLD
# values while the package plainly states the new ones.
_u_stamp_transitive() {
    local module="$1"
    local pairs=() pair env_var cfg_key value src
    case "$module" in
        timesketch) pairs=("OPENSEARCH_VERSION:opensearch:timesketch_opensearch"
                           "POSTGRES_VERSION:postgres:timesketch_postgres"
                           "REDIS_VERSION:redis:timesketch_redis"
                           "NGINX_VERSION:nginx:timesketch_nginx") ;;
        iris)       pairs=("RABBITMQ_VERSION:rabbitmq:iris_rabbitmq") ;;
        volweb)     pairs=("VOLWEB_POSTGRES_VERSION:postgres:volweb_postgres"
                           "VOLWEB_REDIS_VERSION:redis:volweb_redis") ;;
        intact)     pairs=("TUSD_VERSION:tusd:backend_tusd") ;;
        *)          return 0 ;;
    esac

    local envf
    [[ "$module" == "intact" ]] && envf="${SCRIPT_DIR}/modules/backend/.env" \
                                || envf="$(_u_env_file "$module")"
    [[ -f "$envf" ]] || { log_warn "  no ${envf} to stamp sidecar pins into"; return 0; }

    local n=0
    for pair in "${pairs[@]}"; do
        env_var="${pair%%:*}"
        local rest="${pair#*:}"
        local man_key="${rest%%:*}"
        cfg_key="${rest#*:}"

        value="$(_u_manifest_transitive "$module" "$man_key")"
        src="package manifest"
        if [[ -z "$value" ]]; then
            value="$(read_config "['versions']['${cfg_key}']" 2>/dev/null || echo '')"
            [[ "$value" == "None" ]] && value=""
            src="config.yaml"
        fi
        if [[ -z "$value" ]]; then
            # Loud, because the compose file's ${VAR:?...} will fail the very
            # next step and the reason would otherwise be a bare compose error.
            log_warn "  no value for ${env_var} (manifest or versions.${cfg_key}); leaving it as-is"
            continue
        fi
        local current; current="$(read_env_var "$envf" "$env_var" 2>/dev/null || echo '')"
        if [[ "$current" != "$value" ]]; then
            update_env_var "$envf" "$env_var" "$value" || return 1
            log_info "  sidecar pin ${env_var}: ${current:-unset} -> ${value} (from ${src})"
            n=$((n + 1))
        fi
    done
    (( n == 0 )) && log_info "  sidecar pins already current"
    return 0
}

# contents.transitive_versions.<module>.<dep> from the package manifest.
_u_manifest_transitive() {
    [[ -f "${UPKG_MANIFEST:-}" ]] || return 0
    python3 - "$UPKG_MANIFEST" "$1" "$2" <<'PY' 2>/dev/null
import json, sys
try:
    m = json.load(open(sys.argv[1], encoding="utf-8"))
except Exception:
    raise SystemExit(0)
tv = ((m.get("contents") or {}).get("transitive_versions") or {}).get(sys.argv[2]) or {}
# Accept either the dep name ('postgres') or the env var ('POSTGRES_VERSION')
# as the key: the CI packager has emitted both shapes over time.
v = tv.get(sys.argv[3])
if v is None:
    for k, val in tv.items():
        if k.lower().startswith(sys.argv[3].lower()):
            v = val
            break
print(v if v is not None else "")
PY
}

# Stamp one or more KEY=value pins, failing if any write fails.
_u_stamp() {
    local envf="$1"; shift
    local pair
    for pair in "$@"; do
        update_env_var "$envf" "${pair%%=*}" "${pair#*=}" || return 1
    done
    return 0
}

# Take an ordinary named-volume pg_dump. Best-effort by contract: the caller
# decides whether a failed dump is fatal (it is for Timesketch, where the
# next step may wipe the volume; it is not for IRIS, whose volume is never
# touched). Empty output is treated as failure -- a 0-byte .sql is worse than
# no dump, because it looks like one.
_u_pg_dump() {
    local container="$1" user="$2" db="$3" out="$4"
    mkdir -p "$(dirname "$out")" 2>/dev/null
    if ! RUN_HEARTBEAT_QUIET=1 run_with_heartbeat "pg_dump ${db}" 900 \
            bash -c '"$1" exec -t "$2" pg_dump -U "$3" -d "$4" > "$5" 2>>"$6"' \
            _ "${DOCKER_BIN:-docker}" "$container" "$user" "$db" "$out" "${LOG_FILE:-/dev/null}"; then
        rm -f "$out"
        log_warn "  pg_dump of ${db} failed"
        return 1
    fi
    if [[ ! -s "$out" ]]; then
        rm -f "$out"
        log_warn "  pg_dump of ${db} produced an empty file"
        return 1
    fi
    log_info "  database backup: ${out} ($(_human_size "$(stat -c%s "$out")"))"
    return 0
}

_u_backup_dir() {
    echo "${SCRIPT_DIR}/backups/$1"
}

# ===========================================================================
# ELK
#
# Docs: pull -> stop -> rm -> start against the same data volume -> verify the
# version at :9200. Kibana must land on the EXACT same version as
# Elasticsearch, after it; our compose pins both from the one config.yaml
# `versions.elk` value and Logstash interpolates ${ELASTIC_VERSION} directly,
# so that alignment is structural rather than something to check.
# ===========================================================================
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

# ===========================================================================
# IRIS
#
# Docs: pg_dump -> stop -> remove app/worker -> new version -> up. "Iris
# handles upgrades of the database automatically when a new version is
# started", so there is no migration step to run: post_init.py runs Alembic at
# boot. The dump is NEW here -- the Python upgrader took none, the docs ask
# for one, and it costs seconds.
# ===========================================================================
upgrade_module_iris() {
    local target="$1"
    local dir; dir="$(_u_module_dir iris)"
    local envf; envf="$(_u_env_file iris)"
    local bak="" dump

    u_begin iris
    dump="$(_u_backup_dir iris)/iris_${U_FROM// /_}_to_${target}_$(date +%Y%m%d_%H%M%S).sql"

    # Not fatal: IRIS's volumes are never touched by this upgrade, so the dump
    # is insurance against the app's own boot-time Alembic migration, not
    # against us. Role and database read from .env for the same reason as
    # VolWeb below, though IRIS does use 'postgres'/'iris_db'.
    if _u_container_state intact_iris_db | grep -q running; then
        local ir_user ir_db
        ir_user="$(read_env_var "$envf" POSTGRES_USER 2>/dev/null || echo postgres)"
        ir_db="$(read_env_var "$envf" POSTGRES_DB 2>/dev/null || echo iris_db)"
        _u_pg_dump intact_iris_db "$ir_user" "$ir_db" "$dump" \
            || log_warn "  continuing without a database backup"
    fi

    bak="$(backup_file_for_rollback "$envf")" || bak=""
    u_undo "_u_compose_up_old iris"
    [[ -n "$bak" ]] && u_undo "restore_file_from_backup '${envf}' '${bak}'"

    u_do --timeout 900 "load iris images" -- _u_load_tars_matching "iris-"
    u_do "ensure iriswebapp_app:${target}" -- \
        _u_ensure_image "ghcr.io/dfir-iris/iriswebapp_app:${target}" "iris-app-${target}.tar"
    u_do "ensure iriswebapp_db:${target}" -- \
        _u_ensure_image "ghcr.io/dfir-iris/iriswebapp_db:${target}" "iris-db-${target}.tar"
    u_do "ensure iriswebapp_nginx:${target}" -- \
        _u_ensure_image "ghcr.io/dfir-iris/iriswebapp_nginx:${target}" "iris-nginx-${target}.tar"

    u_do --timeout 300 "stop iris" -- _u_compose "$dir" down --remove-orphans
    u_do "stamp iris pin" -- _u_stamp "$envf" "IRIS_VERSION=${target}"
    u_do "stamp iris sidecar pins" -- _u_stamp_transitive iris
    u_do "iris web certificate" -- ensure_iris_web_cert
    u_do --timeout 900 "start iris" -- _u_compose "$dir" up -d --no-build --pull never

    u_end iris rollback 240
    local rc=$?
    if (( rc == 0 )); then
        # IRIS only honours IRIS_ADM_PASSWORD at first init, so config.yaml's
        # documented credentials silently stop working on any box where the DB
        # already existed. Re-asserting is what makes them true again.
        if declare -F enforce_iris_admin_password >/dev/null; then
            enforce_iris_admin_password || log_warn "  could not re-assert the IRIS admin password"
        fi
        discard_backup "$bak"
    fi
    return $rc
}

# Missing-only, never clobbering. modules/iris/config/certificates/... is
# gitignored and only ever created by lib/modules.sh:generate_certificates,
# which is gated on iris.enabled -- so enabling IRIS later leaves nginx
# crash-looping on "cannot load certificate". Ported from iris.py:17-84.
ensure_iris_web_cert() {
    local certdir="${SCRIPT_DIR}/modules/iris/config/certificates"
    local webdir="${certdir}/web_certificates"
    local src="${SCRIPT_DIR}/modules/nginx/ssl"

    mkdir -p "$webdir" "${certdir}/rootCA" 2>/dev/null

    if [[ ! -f "${webdir}/iris_dev_cert.pem" || ! -f "${webdir}/iris_dev_key.pem" ]]; then
        if [[ -f "${src}/nginx-cert.crt" && -f "${src}/nginx-cert.key" ]]; then
            cp -p "${src}/nginx-cert.crt" "${webdir}/iris_dev_cert.pem" || return 1
            cp -p "${src}/nginx-cert.key" "${webdir}/iris_dev_key.pem" || return 1
            chmod 0644 "${webdir}/iris_dev_cert.pem"
            # iris-nginx runs as www-data (uid/gid 33) and must be able to read
            # the key; 0640 root:33 is the narrowest thing that works.
            chown 0:33 "${webdir}/iris_dev_key.pem" 2>/dev/null
            chmod 0640 "${webdir}/iris_dev_key.pem"
            log_info "  synced the IRIS web certificate from modules/nginx/ssl"
        else
            log_warn "  no nginx certificate to sync; IRIS nginx may not start"
        fi
    fi

    if [[ ! -f "${certdir}/rootCA/irisRootCACert.pem" ]]; then
        openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
            -keyout "${certdir}/rootCA/irisRootCAKey.pem" \
            -out "${certdir}/rootCA/irisRootCACert.pem" \
            -subj '/CN=IRIS Root CA/O=Intact.AI/C=US' >>"${LOG_FILE:-/dev/null}" 2>&1 \
            || { log_warn "  could not generate the IRIS root CA"; return 0; }
        log_info "  generated the IRIS root CA"
    fi
    return 0
}

# ===========================================================================
# Portainer
#
# Docs: stop -> rm -> pull -> run against the SAME portainer_data volume.
# "Always match the agent version to the Portainer Server version", which is
# why one pin stamps both and the two are asserted equal.
# ===========================================================================
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

# ===========================================================================
# VolWeb
#
# No formal upstream upgrade doc beyond pull-and-restart. Postgres and media
# are named volumes and are never touched. The pg_dump is new: Django runs its
# migrations at boot, so the volume IS modified by an upgrade even though we
# do not touch it ourselves.
# ===========================================================================
upgrade_module_volweb() {
    local target="$1"
    local dir; dir="$(_u_module_dir volweb)"
    local envf; envf="$(_u_env_file volweb)"
    local bak="" dump

    u_begin volweb
    dump="$(_u_backup_dir volweb)/volweb_${U_FROM// /_}_to_${target}_$(date +%Y%m%d_%H%M%S).sql"
    if _u_container_state intact_volweb_postgresdb | grep -q running; then
        # Read the role from .env rather than assuming 'postgres': VolWeb's
        # compose creates the database owned by VOLWEB_POSTGRES_USER (volweb),
        # and there is no 'postgres' role at all, so a hardcoded -U postgres
        # fails with "role does not exist" and silently skips the backup.
        local vw_user vw_db
        vw_user="$(read_env_var "$envf" VOLWEB_POSTGRES_USER 2>/dev/null || echo volweb)"
        vw_db="$(read_env_var "$envf" VOLWEB_POSTGRES_DB 2>/dev/null || echo volweb)"
        _u_pg_dump intact_volweb_postgresdb "$vw_user" "$vw_db" "$dump" \
            || log_warn "  continuing without a database backup"
    fi

    bak="$(backup_file_for_rollback "$envf")" || bak=""
    u_undo "_u_compose_up_old volweb"
    [[ -n "$bak" ]] && u_undo "restore_file_from_backup '${envf}' '${bak}'"

    u_do --timeout 900 "load volweb images" -- _u_load_tars_matching "volweb-"
    u_do "ensure volweb-backend:${target}" -- \
        _u_ensure_image "forensicxlab/volweb-backend:${target}" "volweb-backend-${target}.tar"
    u_do "ensure volweb-frontend:${target}" -- \
        _u_ensure_image "forensicxlab/volweb-frontend:${target}" "volweb-frontend-${target}.tar"

    # One config.yaml pin drives both images.
    u_do "stamp volweb pins" -- _u_stamp "$envf" \
        "VOLWEB_BACKEND_VERSION=${target}" "VOLWEB_FRONTEND_VERSION=${target}"
    u_do "stamp volweb sidecar pins" -- _u_stamp_transitive volweb
    u_do --timeout 900 "start volweb" -- _u_volweb_compose_up "$dir"

    # Policy 'report', matching the Python: a DOWN VolWeb is named loudly but
    # not reverted. Worth revisiting once the .env rollback here is
    # field-proven, but changing it in the same release that introduces the
    # rollback would be testing two things at once.
    u_end volweb report 180
    local rc=$?
    (( rc == 0 )) && discard_backup "$bak"
    return $rc
}

# Four to six containers mount the shared volweb_media volume at once and race
# its initialisation. These four messages are that race and nothing else, so
# they are the only ones retried. Ported from volweb.py:110-183.
_u_volweb_compose_up() {
    local dir="$1" attempt
    for attempt in 1 2 3; do
        if _u_compose "$dir" up -d --no-build --pull never; then
            return 0
        fi
        local tail_out
        tail_out="$(tail -40 "${LOG_FILE:-/dev/null}" 2>/dev/null)"
        if grep -qiE 'file exists|failed to mkdir|device or resource busy|error while creating mount source path' <<< "$tail_out"; then
            log_warn "  volweb_media volume-init race on attempt ${attempt}; retrying"
            sleep $((attempt * 5))
            continue
        fi
        return 1
    done
    return 1
}

# ===========================================================================
# Plaso, aws_sigma, o365rc — no containers of their own.
# ===========================================================================

upgrade_module_plaso() {
    local target="$1"
    local envf="${SCRIPT_DIR}/modules/backend/.env"
    local bak=""

    u_begin plaso
    bak="$(backup_file_for_rollback "$envf")" || bak=""
    [[ -n "$bak" ]] && u_undo "restore_file_from_backup '${envf}' '${bak}'"

    u_do --timeout 1800 "ensure plaso:${target}" -- \
        _u_ensure_image "log2timeline/plaso:${target}" "plaso-${target}.tar"
    u_do "stamp PLASO_VERSION" -- _u_stamp "$envf" "PLASO_VERSION=${target}"
    # plaso is not in the install-function table, so it is always dispatched as
    # an UPGRADE and the generic enable-on-install writeback never fires --
    # leaving modules.plaso.enabled false forever. plaso.py:23-31.
    u_do "enable plaso in config.yaml" -- _pin_module_version plaso "$target"

    # Nothing runs, so there is nothing to probe. The job runner reads the pin
    # fresh per job; no restart is needed.
    u_end plaso none
    local rc=$?
    (( rc == 0 )) && discard_backup "$bak"
    return $rc
}

upgrade_module_o365rc() {
    local target="$1"
    local envf="${SCRIPT_DIR}/modules/backend/.env"
    local bak=""

    u_begin o365rc
    bak="$(backup_file_for_rollback "$envf")" || bak=""
    [[ -n "$bak" ]] && u_undo "restore_file_from_backup '${envf}' '${bak}'"

    u_do --timeout 1800 "ensure dfir-o365rc:${target}" -- \
        _u_ensure_image "anssi/dfir-o365rc:${target}" "o365rc-${target}.tar"
    u_do "stamp DFIR_O365RC_VERSION" -- _u_stamp "$envf" "DFIR_O365RC_VERSION=${target}"

    u_end o365rc none
    local rc=$?
    (( rc == 0 )) && discard_backup "$bak"
    return $rc
}

# The versioned artifact is a SIGMA rule pack, not an image. /opt/sigma-rules
# is mounted read-only into the backend, so it is written by a one-shot
# container instead. Non-fatal throughout: stale detection rules degrade
# coverage, they do not break the platform.
upgrade_module_aws_sigma() {
    local target="$1"
    local envf="${SCRIPT_DIR}/modules/backend/.env"
    local bak=""

    u_begin aws_sigma
    bak="$(backup_file_for_rollback "$envf")" || bak=""
    [[ -n "$bak" ]] && u_undo "restore_file_from_backup '${envf}' '${bak}'"

    u_do --timeout 600 "install the AWS SIGMA rule pack" -- _u_install_sigma_pack "$target"
    # Keep the env var name: renaming it would break every consumer, and the
    # config migration deliberately does not rename it either.
    u_do "stamp CLOUDTRAIL_VERSION" -- _u_stamp "$envf" "CLOUDTRAIL_VERSION=${target}"
    u_do "enable aws_sigma in config.yaml" -- _pin_module_version aws_sigma "$target"

    u_end aws_sigma none
    local rc=$?
    (( rc == 0 )) && discard_backup "$bak"
    return $rc
}

_u_install_sigma_pack() {
    local target="$1" tar=""
    # Accept the pre-rename filename too: a package cut before the
    # cloudtrail -> aws_sigma rename carries the old one.
    local c
    for c in "aws_sigma-${target}.tar" "cloudtrail-${target}.tar"; do
        [[ -f "${UPKG_DIR}/images/${c}" ]] && { tar="${UPKG_DIR}/images/${c}"; break; }
    done
    if [[ -z "$tar" ]]; then
        log_warn "  no AWS SIGMA rule pack in this package; leaving the existing rules"
        return 0
    fi
    local dest="/opt/sigma-rules/rules/cloud/aws"
    # Streamed over stdin so no host path has to be translated into the
    # container. aws.py:110-115.
    if ! "${DOCKER_BIN:-docker}" run --rm -i -v /opt/sigma-rules:/opt/sigma-rules \
            ubuntu:22.04 sh -c "mkdir -p '${dest}' && tar xf - -C '${dest}'" \
            < "$tar" >>"${LOG_FILE:-/dev/null}" 2>&1; then
        log_warn "  could not unpack the AWS SIGMA rule pack"
        return 0
    fi
    log_info "  AWS SIGMA rule pack ${target} installed"
    return 0
}
