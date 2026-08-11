#!/bin/bash
# Intact.AI upgrade — shared plumbing the per-module files in this directory
# all lean on: compose wrappers, image resolution, sidecar pin stamping,
# pg_dump. Timesketch, Velociraptor and intact each need enough of their own
# machinery to live in their own top-level file (lib/upgrade/timesketch/,
# lib/upgrade/velociraptor/, lib/upgrade/intact/); everything here is common
# to the simpler version-swap-plus-a-little-care modules: elk, iris,
# portainer, volweb, plaso, aws_sigma, o365rc.

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
#
# "The way it was" is NOTHING when the module was not installed before this
# run. Bringing up the old stack then means starting containers from a .env
# that was just deleted and images that were never pulled, so the undo fails,
# and a failed undo is reported as "ROLLBACK FAILED -- this module needs manual
# repair". Observed 2026-08-11: a fresh iris install failed on a missing
# rabbitmq image and told the operator to hand-repair a box on which iris had
# never existed and nothing was broken.
#
# So for an install the undo is the opposite operation: remove what the failed
# attempt created. `down` WITHOUT -v -- named volumes stay. They are empty on a
# failed first install, but "empty" is this function's guess, not its
# knowledge, and no undo path should be the thing that deletes a volume.
_u_compose_up_old() {
    local m="$1"
    local dir; dir="$(_u_module_dir "$m")"
    if [[ "${PLAN_ACTION[$m]:-}" == install ]]; then
        log_info "  ${m} was not installed before this run — removing what the failed install created"
        _u_compose "$dir" down --remove-orphans
        return 0
    fi
    _u_compose "$dir" up -d --no-build --pull never
}

_u_image_present() {
    "${DOCKER_BIN:-docker}" image inspect "$1" >/dev/null 2>&1
}

# Emits "<rendered image ref>\t<rendered tar filename>" per line for a
# module's PRIMARY_IMAGES entries at the given version, or nothing for a
# module PRIMARY_IMAGES does not cover (intact, velociraptor, aws_sigma --
# built or ruleset-only, not pulled).
#
# Reads modules/backend/services/image_map.py by EXEC, not `import
# services.image_map`: importing it as a package member runs
# services/__init__.py first regardless of which submodule was asked for,
# and that file eagerly imports the whole backend service graph including
# grpc. exec()ing the source directly never touches the package machinery at
# all -- same fix scripts/ci/packager/order.py applies to the exact same
# problem on the CI side. Single source of truth either way: this is the
# SAME file app.py's boot-time image reclaim and the CI packager both read,
# so a repo/tar-name change here cannot silently disagree between what
# prunes an old image and what the box actually shipped it as.
_u_primary_image_refs() {
    local module="$1" version="$2"
    local f="${SCRIPT_DIR}/modules/backend/services/image_map.py"
    [[ -f "$f" ]] || return 1
    python3 -c "
import sys
ns = {}
exec(open(sys.argv[1], encoding='utf-8').read(), ns)
for img, tar in ns.get('PRIMARY_IMAGES', {}).get(sys.argv[2], []):
    print(img.format(version=sys.argv[3]) + '\t' + tar.format(version=sys.argv[3]))
" "$f" "$module" "$version" 2>/dev/null
}

# Remove <repo>:<old> for every primary image a module owns, once the module
# has genuinely committed to <new>. Never fatal, never even logged as a
# warning on failure: `docker image rm` refuses on its own when the tag is
# still in use or was never pulled locally, and that refusal is exactly the
# safety net that makes calling this unconditionally fine. User-requested
# 2026-06-09 after several GB of obsolete module images piling up on the
# host post-upgrade; the Python engine this replaced had it
# (base.py:remove_old_module_image), the bash rewrite initially did not.
_u_prune_old_module_images() {
    local module="$1" old="$2" new="$3"
    [[ -n "$old" && "$old" != "not installed" && "$old" != "$new" ]] || return 0
    local ref tar old_ref
    while IFS=$'\t' read -r ref tar; do
        [[ -n "$ref" ]] || continue
        old_ref="${ref%:*}:${old}"
        [[ "$old_ref" == "$ref" ]] && continue   # same tag rendered differently; nothing to prune
        if "${DOCKER_BIN:-docker}" image inspect "$old_ref" >/dev/null 2>&1; then
            "${DOCKER_BIN:-docker}" image rm "$old_ref" >/dev/null 2>&1 \
                && log_info "  cleaned up old image: ${old_ref}"
        fi
    done < <(_u_primary_image_refs "$module" "$new")
    return 0
}

# Preflight, called once before the module loop: with no network access, a
# missing image used to surface only when THAT module's own turn came --
# after however many earlier modules had already swapped. Checks every
# module about to upgrade/install against what is already local and what
# the package bundles; a real gap is refused up front, before anything is
# touched, rather than three modules in.
_u_preflight_images() {
    [[ "${INTACT_UPGRADE_OFFLINE:-0}" == "1" ]] || return 0
    local missing=() m ref tar
    for m in "${UPGRADE_ORDER[@]}"; do
        case "${PLAN_ACTION[$m]:-}" in upgrade|install) ;; *) continue ;; esac
        while IFS=$'\t' read -r ref tar; do
            [[ -n "$ref" ]] || continue
            _u_image_present "$ref" && continue
            [[ -n "$tar" && -f "${UPKG_DIR}/images/${tar}" ]] && continue
            missing+=("${m}: ${ref} (not present, and ${tar:-no tar} not in the package)")
        done < <(_u_primary_image_refs "$m" "${PLAN_TARGET[$m]}")
    done
    if (( ${#missing[@]} )); then
        log_error "Offline, and this package is missing image(s) it needs:"
        local x; for x in "${missing[@]}"; do log_error "  - ${x}"; done
        return 1
    fi
    return 0
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
# The image-tar filename prefixes a module owns: its PRIMARY_IMAGES *and* its
# TRANSITIVE_IMAGES, read from image_map.py -- the same file the pruner, the
# CI packager and app.py's boot reclaim all read.
#
# WHY THIS EXISTS. Each module used to name its own prefixes by hand, and they
# only covered the module's own images. Every transitive dependency was
# packaged and then never loaded: `iris` loaded "iris-" and left
# rabbitmq-3-management-alpine.tar sitting in the package, `timesketch` loaded
# "timesketch-" and left postgres, opensearch, redis and nginx. Offline, that
# is fatal and it is fatal LATE -- the images load, the pins stamp, the
# certificates generate, and then compose up dies with "No such image:
# rabbitmq:3-management-alpine" (observed 2026-08-11 installing iris from a
# per-module package). It hid for so long because it only bites when the image
# is not already in the local store: any box that had ever run the module
# online had it cached, and CI's dry-run stops before compose up.
#
# volweb was never affected, purely because its deps were renamed
# volweb-postgres-*.tar to avoid colliding with timesketch's postgres-*.tar --
# so the one module whose transitive tars happened to share its own prefix is
# the one that worked. That is luck, not design, and it is why this reads the
# table instead of trusting names.
#
# Prefix, not exact filename: a transitive tar is named for its own version
# ("rabbitmq-3-management-alpine.tar"), which lives in the sidecar pins rather
# than anywhere this function can cheaply resolve. The literal text before the
# first {placeholder} is unambiguous enough -- "nginx-" for timesketch does not
# match "iris-nginx-v2.4.27.tar", because that one starts with "iris-".
_u_module_tar_prefixes() {
    local module="$1"
    local f="${SCRIPT_DIR}/modules/backend/services/image_map.py"
    [[ -f "$f" ]] || return 1
    python3 -c "
import sys
ns = {}
exec(open(sys.argv[1], encoding='utf-8').read(), ns)
mod = sys.argv[2]
tars = [t for _img, t in (ns.get('PRIMARY_IMAGES', {}).get(mod) or [])]
tars += [t for _dep, _pat, t in (ns.get('TRANSITIVE_IMAGES', {}).get(mod) or [])]
seen = []
for t in tars:
    p = t.split('{')[0]
    if p and p not in seen:
        seen.append(p)
print('\n'.join(seen))
" "$f" "$module" 2>/dev/null
}

# Load every image tar the package carries for <module>, primary and
# transitive. Falls back to the caller's literal prefixes when image_map.py
# cannot be read, so a module with no table entry still behaves as before.
_u_load_module_images() {
    local module="$1"; shift
    local prefixes=()
    local p
    while IFS= read -r p; do
        [[ -n "$p" ]] && prefixes+=("$p")
    done < <(_u_module_tar_prefixes "$module")
    if (( ${#prefixes[@]} == 0 )); then
        log_warn "  no image map entry for ${module}; falling back to built-in prefixes"
        prefixes=("$@")
    fi
    _u_load_tars_matching "${prefixes[@]}"
}

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
