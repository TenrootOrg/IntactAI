#!/bin/bash
# Intact.AI upgrade — config.yaml: version-pin merge, schema migration, and
# post-merge validation.
#
# Merges only the `versions:` block from the package's config.yaml into the
# operator's. Text-level and key-by-key, never a yaml load+dump: the operator's
# file carries their github_token, module passwords, domain and the comments
# above half the pins, and a round-trip deletes all of it.
#
# Uses _pin_module_version (lib/config.sh), which truncates the real file in
# place rather than renaming a temp over it -- config.yaml is bind-mounted into
# the backend BY INODE, so a rename leaves the container reading the old file
# while the edit sits on disk looking applied.
_intact_merge_versions() {
    local src="$1"
    local new="${src}/config.yaml"

    # The MANIFEST is the pin source, not the package's config.yaml.
    #
    # config.yaml is deliberately excluded from what ships -- it is the
    # operator's live file and carries secrets (see the packager's copytree
    # ignore_patterns). So this function's original source never exists in a
    # real package and the merge was a permanent no-op: it logged "package
    # carries no config.yaml; keeping local pins" and returned, leaving every
    # module pin at its pre-upgrade value. Observed on a real 20260726 ->
    # 20260811 run, 2026-08-12: elk upgraded to 9.4.4 and reported healthy while
    # config.yaml still said 9.4.2, so the box disagreed with itself and the
    # NEXT upgrade would re-plan elk from a version it is no longer on.
    #
    # manifest.json carries the same versions block, is already authoritative
    # for the plan and for the backend image tag, and ships in every package.
    # Prefer it; fall back to a packaged config.yaml for the older shape.
    if [[ -f "${UPKG_MANIFEST:-}" ]]; then
        new="$UPKG_MANIFEST"
    elif [[ ! -f "$new" ]]; then
        log_info "  package carries no manifest or config.yaml; keeping local pins"
        return 0
    fi

    cp -p "$CONFIG_FILE" "${CONFIG_FILE}.pre-upgrade-backup" 2>/dev/null

    local pairs
    pairs="$(python3 - "$new" <<'PY'
import sys, json
# manifest.json or a legacy packaged config.yaml -- both keep the pins under
# a top-level "versions" mapping, so only the parser differs.
try:
    raw = open(sys.argv[1], encoding="utf-8").read()
except Exception:
    raise SystemExit(0)
d = None
try:
    d = json.loads(raw)
except Exception:
    try:
        import yaml
        d = yaml.safe_load(raw)
    except Exception:
        raise SystemExit(0)
if not isinstance(d, dict):
    raise SystemExit(0)
for k, v in (d.get("versions") or {}).items():
    if v is None or str(v).strip() == "":
        continue
    print("%s\t%s" % (k, v))
PY
)"
    [[ -n "$pairs" ]] || { log_info "  package config.yaml has no versions block"; return 0; }

    # The manifest names the platform "intact"; config.yaml pins it as
    # "backend". Writing the manifest key verbatim would invent a bogus
    # versions.intact and leave versions.backend stale -- the same key-mismatch
    # class that _intact_validate_config_pins already maps for aws_sigma and
    # o365rc.
    declare -A _pin_key=( [intact]=backend )

    local n=0 key val cur
    while IFS=$'\t' read -r key val; do
        [[ -n "$key" ]] || continue
        key="${_pin_key[$key]:-$key}"
        cur="$(read_config "['versions']['${key}']" 2>/dev/null || echo '')"
        [[ "$cur" == "$val" ]] && continue
        _pin_module_version "$key" "$val" && n=$((n + 1))
    done <<< "$pairs"
    log_info "  merged ${n} version pin(s) from the package into config.yaml"
    return 0
}

# ---------------------------------------------------------------------------
# _intact_seed_missing_pins — add sidecar pins the operator's config.yaml has
# never had, BEFORE _intact_validate_config_pins demands them.
#
# The validator requires a versions.<module>_<sidecar> key for every enabled
# module, but nothing on the forward path ever ADDS one: _intact_merge_versions
# copies only the manifest's top-level `versions:` block (module primaries), and
# _u_stamp_transitive writes .env, not config.yaml -- and runs ~9 steps LATER
# anyway. So a box installed before a sidecar pin existed fails validation on a
# key it had no way to acquire.
#
# That is not hypothetical: 0615 carries every timesketch/iris/volweb sidecar but
# NOT versions.backend_tusd (introduced in 0726), so a real 0615 -> 0813 air-gap
# run died at "no versions.backend_tusd in config.yaml (sidecar pin)" and, because
# the snapshot step was then skipped while its undo had already been registered,
# took intact's rollback down with it. Exactly the shape of the aws_sigma /
# cloudtrail rename bug documented in _intact_validate_config_pins below.
#
# Resolution order per pin, first hit wins -- each source is something the
# PACKAGE carries, so this works on an air-gapped box:
#   1. the manifest's contents.transitive_versions (covers timesketch/iris/volweb)
#   2. the bundled image tar's filename (covers backend_tusd: the packager reads
#      nginx/backend_tusd from the build checkout's config.yaml and deliberately
#      does NOT put them in the manifest, so images/tusd-<ver>.tar is the only
#      statement of the version that ships)
#   3. the new compose file's ${VAR:-default} (a floor, so a pin is still seeded
#      if the sidecar image was best-effort and missing)
#
# ONLY ever adds an absent key. An operator's existing value is never rewritten.
_intact_pkg_image_version() {
    local prefix="$1" f base
    [[ -n "${UPKG_DIR:-}" ]] || return 0
    for f in "${UPKG_DIR}"/images/${prefix}*.tar; do
        [[ -f "$f" ]] || continue
        base="$(basename "$f" .tar)"
        printf '%s\n' "${base#"$prefix"}"
        return 0
    done
    return 0
}

_intact_compose_default() {
    local compose="$1" var="$2"
    [[ -f "$compose" ]] || return 0
    sed -nE "s/.*\\\$\{${var}:-([^}]+)\}.*/\1/p" "$compose" | head -1
}

_intact_seed_missing_pins() {
    local src="${1:-${UPKG_DIR:-}}"

    # module -> "ENV_VAR:manifest_key:config_key[:tar_prefix] ..."
    # Mirrors _u_stamp_transitive's own table (lib/upgrade/modules/shared.sh) --
    # kept as its own copy for the same reason the validator keeps one: a change
    # to either is then a visible diff, not an invisible coupling. The optional
    # 4th field is the bundled-tar prefix, given only where it is unambiguous
    # (`postgres-` alone would match timesketch's tar when resolving volweb's).
    local -A _seed=(
        [timesketch]="OPENSEARCH_VERSION:opensearch:timesketch_opensearch POSTGRES_VERSION:postgres:timesketch_postgres REDIS_VERSION:redis:timesketch_redis NGINX_VERSION:nginx:timesketch_nginx"
        [iris]="RABBITMQ_VERSION:rabbitmq:iris_rabbitmq:rabbitmq-"
        [volweb]="VOLWEB_POSTGRES_VERSION:postgres:volweb_postgres:volweb-postgres- VOLWEB_REDIS_VERSION:redis:volweb_redis:volweb-redis-"
        [intact]="TUSD_VERSION:tusd:backend_tusd:tusd-"
    )
    # The compose that states the ${VAR:-default} for each module, inside the
    # PACKAGE (the new release's), not the box's older copy.
    local -A _compose=(
        [timesketch]="modules/timesketch/docker-compose.yaml"
        [iris]="modules/iris/docker-compose.yaml"
        [volweb]="modules/volweb/docker-compose.yaml"
        [intact]="modules/backend/docker-compose.yaml"
    )

    local m spec entry env_var rest man_key cfg_key tar_prefix cur val how n=0
    for m in "${UPGRADE_ORDER[@]}"; do
        spec="${_seed[$m]:-}"
        [[ -n "$spec" ]] || continue
        _plan_module_enabled "$m" || continue

        for entry in $spec; do
            env_var="${entry%%:*}"
            rest="${entry#*:}"
            man_key="${rest%%:*}"
            rest="${rest#*:}"
            cfg_key="${rest%%:*}"
            tar_prefix=""
            [[ "$rest" == *:* ]] && tar_prefix="${rest#*:}"

            cur="$(read_config "['versions']['${cfg_key}']" 2>/dev/null || echo '')"
            [[ "$cur" == "None" ]] && cur=""
            [[ -n "$cur" ]] && continue          # operator's value wins, always

            val="$(_u_manifest_transitive "$m" "$man_key")"; how="package manifest"
            if [[ -z "$val" && -n "$tar_prefix" ]]; then
                val="$(_intact_pkg_image_version "$tar_prefix")"; how="bundled image ${tar_prefix}*.tar"
            fi
            if [[ -z "$val" ]]; then
                val="$(_intact_compose_default "${src}/${_compose[$m]:-}" "$env_var")"
                how="compose default for ${env_var}"
            fi
            if [[ -z "$val" ]]; then
                # Not fatal here: the validator right after this is the one that
                # decides, and it names the key far better than we could.
                log_warn "  could not resolve a value for versions.${cfg_key}; validation will report it"
                continue
            fi

            if _pin_module_version "$cfg_key" "$val"; then
                log_info "  seeded versions.${cfg_key} = ${val} (from ${how})"
                n=$((n + 1))
            else
                log_warn "  could not write versions.${cfg_key} into config.yaml"
            fi
        done
    done

    (( n )) && log_success "  seeded ${n} sidecar pin(s) this release expects"
    return 0
}

# ---------------------------------------------------------------------------
# config.yaml schema migrations.
#
# An ORDERED REGISTRY of named steps, applied one version at a time, each
# stamping its own version on success. The previous shape -- a single inline
# block that did every rename and then stamped the final number -- meant a
# failure anywhere left config.yaml partly migrated but still labelled with the
# OLD version, so the next run would redo the half that had already been done.
# Stepping one version at a time makes an interrupted migration resumable: the
# file always says exactly which steps have been applied.
#
# Rules for a migration function:
#   * takes the config path, returns 0/1, and NEVER stamps schema_version --
#     the driver below owns that, so a step cannot lie about what it completed;
#   * must be IDEMPOTENT. A crash between the edit and the stamp re-runs it;
#   * edits config.yaml TEXTUALLY and truncates in place. Never yaml.safe_load
#     + dump: this is the operator's file, carrying their github_token, module
#     passwords and the comments above half the pins, and a round-trip deletes
#     all of it. In place because config.yaml is bind-mounted into the backend
#     BY INODE -- writing a temp file and renaming it over the original leaves
#     the container reading the old inode while the edit looks applied on disk.
#
# NOT the place for new *pins*. A pin that a later release introduces has to be
# seeded on every upgrade, not once at a version boundary -- a box already at
# the current schema would never receive it. That is _intact_seed_missing_pins,
# which runs unconditionally. Migrations are for RESHAPING what is already
# there; seeding is for filling in what is absent.
_CONFIG_SCHEMA_TARGET=3

# "<from>:<to>:<description>:<function>"
_CONFIG_MIGRATIONS=(
    "1:2:consolidate cloudtrail/prowler into aws_sigma:_cfgmig_1_to_2_aws_sigma"
    "2:3:rename options.download_forensic_tools to options.download_tools:_cfgmig_2_to_3_download_tools"
)

# Stamp schema_version, inserting it at the top when absent.
_cfg_stamp_schema() {
    python3 - "$CONFIG_FILE" "$1" <<'PY'
import os, re, sys
path, ver = sys.argv[1], sys.argv[2]
out = open(path, encoding="utf-8").readlines()
for i, ln in enumerate(out):
    if re.match(r"^schema_version\s*:", ln):
        out[i] = "schema_version: %s\n" % ver
        break
else:
    out.insert(0, "schema_version: %s\n" % ver)
with open(path, "w", encoding="utf-8") as fh:
    fh.write("".join(out)); fh.flush(); os.fsync(fh.fileno())
PY
}

# 1 -> 2. Renames modules.cloudtrail / modules.prowler to modules.aws_sigma,
# carrying `enabled` forward. Deliberately does NOT rename the CLOUDTRAIL_VERSION
# env var: that name is a compat contract with every consumer of it.
_cfgmig_1_to_2_aws_sigma() {
    python3 - "$1" <<'PY'
import os, re, sys
path = sys.argv[1]
out = []
for ln in open(path, encoding="utf-8").readlines():
    m = re.match(r"^(\s+)(cloudtrail|prowler)(\s*:\s*)$", ln)
    if m and m.group(2) == "cloudtrail":
        out.append("%saws_sigma%s\n" % (m.group(1), m.group(3))); continue
    m2 = re.match(r"^(\s+)cloudtrail(\s*:\s*)(.+)$", ln)
    if m2:
        out.append("%saws_sigma%s%s\n" % (m2.group(1), m2.group(2), m2.group(3))); continue
    out.append(ln)
with open(path, "w", encoding="utf-8") as fh:
    fh.write("".join(out)); fh.flush(); os.fsync(fh.fileno())
PY
}

# _intact_seed_missing_options — add options: keys this release expects and the
# operator's config.yaml has never had.
#
# The forward path carried NOTHING into options:. _intact_merge_versions copies
# the manifest's `versions:` block and nothing else, migrations only reshape
# what is already there, and a release ships no config.yaml at all (the
# packager's copytree excludes it), so there has never been a template to seed
# from. Confirmed on a real 0615 -> 0818 upgrade, 2026-08-19: the box came out
# the far side still holding ['check_module_updates', 'download_forensic_tools']
# and neither new key.
#
# github_token is the one that bites. Without it every api.github.com call is
# anonymous against a 60-request/hour PER-IP cap, so an upgraded box quietly
# loses the 5,000/hr limit and the Online Upgrade UI starts reporting "rate
# limited -- try again later" with nowhere in config.yaml to fix it.
#
# Same contract as _intact_seed_missing_pins: ONLY ever adds an absent key,
# never rewrites an operator's value, and seeds the SHIPPED DEFAULT so a box
# that never touched the key behaves exactly as a fresh install of this release
# would. Each seeded key gets a one-line comment; the full explanation lives in
# the shipped config.yaml, which this deliberately does not try to reproduce.
_intact_seed_missing_options() {
    # Passed as argv, one "key<TAB>default<TAB>comment" per argument. NOT on
    # stdin: the script itself arrives there via the heredoc, so anything piped
    # in is swallowed before the program can read it -- which is exactly how the
    # first cut of this function silently seeded nothing at all.
    local added
    added="$(python3 - "$CONFIG_FILE" \
        "download_tools	false	# Also download the OPTIONAL forensic tools (see config.yaml in the release)." \
        "github_token	''	# GitHub API token: raises 60 req/hr (anonymous) to 5,000 req/hr for upgrades." \
        <<'PYSEEDOPT'
import os, re, sys
path = sys.argv[1]
want = []
for row in sys.argv[2:]:
    if not row.strip():
        continue
    key, default, comment = row.split("\t", 2)
    want.append((key, default, comment))

lines = open(path, encoding="utf-8").readlines()

start = None
for i, ln in enumerate(lines):
    if re.match(r"^options\s*:\s*$", ln):
        start = i
        break

if start is None:
    # No options: block at all. Append one at the end of the file rather than
    # guessing a position among the operator's other top-level blocks.
    if lines and lines[-1].strip():
        lines.append("\n")
    start = len(lines)          # the header's own index, not the blank before it
    lines.append("options:\n")
    end = len(lines)
    present = set()
    indent = "  "
else:
    end = len(lines)
    for i in range(start + 1, len(lines)):
        st = lines[i].strip()
        if not st or st.startswith("#"):
            continue
        if not lines[i][:1].isspace():
            end = i
            break
    present = set()
    indent = "  "
    for i in range(start + 1, end):
        m = re.match(r"^(\s+)([A-Za-z_][A-Za-z0-9_]*)\s*:", lines[i])
        if m:
            present.add(m.group(2))
            indent = m.group(1)

missing = [(k, d, c) for k, d, c in want if k not in present]
if not missing:
    raise SystemExit(0)

insert_at = end
while insert_at > start + 1 and not lines[insert_at - 1].strip():
    insert_at -= 1

block = []
for n, (key, default, comment) in enumerate(missing):
    # A blank line between entries, but not immediately under a header this
    # call just created -- "options:" followed by an empty line reads like an
    # empty mapping.
    if n or insert_at > start + 1:
        block.append("\n")
    block.append("%s%s\n" % (indent, comment))
    block.append("%s%s: %s\n" % (indent, key, default))
lines[insert_at:insert_at] = block

payload = "".join(lines)
# In place, never os.replace -- config.yaml is bind-mounted into the backend by
# inode (see _pin_module_version).
d = os.path.dirname(os.path.abspath(path)) or "."
import tempfile
fd, tmp = tempfile.mkstemp(dir=d, prefix=".config.yaml.opt-")
try:
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(payload); fh.flush(); os.fsync(fh.fileno())
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(payload); fh.flush(); os.fsync(fh.fileno())
finally:
    try:
        os.unlink(tmp)
    except OSError:
        pass

sys.stdout.write(" ".join(k for k, _, _ in missing))
PYSEEDOPT
)" || {
        log_warn "  could not seed options into config.yaml"
        return 0
    }

    if [[ -n "$added" ]]; then
        log_info "  seeded options this release expects: ${added}"
    fi
    return 0
}

# 2 -> 3. options.download_forensic_tools -> options.download_tools.
#
# The key was renamed between 0615 and now and NOTHING carried the operator's
# value across. Worse, on 0615 the old name already had zero readers -- shell
# or backend -- so an operator who set it `false` got the extra-tool download
# anyway and had no way to tell. Demonstrated live on a 0615 box, 2026-08-19.
#
# Carries the VALUE, not just the name: the flag states an intent the box was
# never able to honour, and the new key is the first thing that can. The
# shipped default is `false`, so this only ever changes behaviour for someone
# who explicitly asked for the optional tools.
#
# Renames in place, one line, keeping the operator's comment block above it --
# and refuses to act if `download_tools` is somehow already present, because
# two keys of the same name in one mapping is a config.yaml that no longer
# parses the way anyone intended.
_cfgmig_2_to_3_download_tools() {
    python3 - "$1" <<'PYMIG23'
import os, re, sys
path = sys.argv[1]
lines = open(path, encoding="utf-8").readlines()

# The options: block, header to the next column-0 non-comment line.
start = None
for i, ln in enumerate(lines):
    if re.match(r"^options\s*:\s*$", ln):
        start = i
        break
if start is None:
    raise SystemExit(0)                      # no options block: nothing to rename

end = len(lines)
for i in range(start + 1, len(lines)):
    st = lines[i].strip()
    if not st or st.startswith("#"):
        continue
    if not lines[i][:1].isspace():
        end = i
        break

old_at = new_at = None
for i in range(start + 1, end):
    if re.match(r"^\s+download_forensic_tools\s*:", lines[i]):
        old_at = i
    elif re.match(r"^\s+download_tools\s*:", lines[i]):
        new_at = i

if old_at is None:
    raise SystemExit(0)                      # already renamed, or never had it
if new_at is not None:
    # Both names present -- someone hand-added the new key on an old box. The
    # live one already says what the operator wants and the dead one is inert,
    # so this is untidy, not broken. Say so and move on: failing the migration
    # here would fail the whole intact module and roll the upgrade back over a
    # config.yaml that works.
    sys.stderr.write(
        "config.yaml has both download_forensic_tools (dead) and "
        "download_tools (live); leaving both alone, download_tools wins\n")
    raise SystemExit(0)

lines[old_at] = re.sub(r"^(\s+)download_forensic_tools(\s*:)",
                       r"\1download_tools\2", lines[old_at], count=1)

payload = "".join(lines)
# Truncate in place, never os.replace: config.yaml is bind-mounted into the
# backend BY INODE (see _pin_module_version).
with open(path, "w", encoding="utf-8") as fh:
    fh.write(payload); fh.flush(); os.fsync(fh.fileno())
PYMIG23
}

_intact_config_migrations() {
    local current
    current="$(read_config "['schema_version']" 2>/dev/null || echo '')"
    [[ "$current" == "None" || -z "$current" ]] && current=1

    if (( current >= _CONFIG_SCHEMA_TARGET )); then
        log_info "  config.yaml schema is current (v${current})"
        return 0
    fi

    cp -p "$CONFIG_FILE" "${CONFIG_FILE}.pre-migration-backup" 2>/dev/null
    log_info "  migrating config.yaml schema v${current} -> v${_CONFIG_SCHEMA_TARGET}"

    local entry from to desc fn rest
    for entry in "${_CONFIG_MIGRATIONS[@]}"; do
        from="${entry%%:*}"; rest="${entry#*:}"
        to="${rest%%:*}";    rest="${rest#*:}"
        desc="${rest%:*}"
        fn="${rest##*:}"

        (( from < current )) && continue          # already applied
        (( to > _CONFIG_SCHEMA_TARGET )) && break # not for this release

        log_info "    v${from} -> v${to}: ${desc}"
        if ! "$fn" "$CONFIG_FILE"; then
            log_error "  schema migration v${from} -> v${to} failed; restoring config.yaml"
            cp -p "${CONFIG_FILE}.pre-migration-backup" "$CONFIG_FILE" 2>/dev/null
            return 1
        fi
        # Stamp only after the step actually succeeded, so an interruption is
        # resumable rather than ambiguous.
        if ! _cfg_stamp_schema "$to"; then
            log_error "  could not stamp schema v${to}; restoring config.yaml"
            cp -p "${CONFIG_FILE}.pre-migration-backup" "$CONFIG_FILE" 2>/dev/null
            return 1
        fi
        current="$to"
    done

    log_success "  config.yaml migrated to schema v${current}"
    return 0
}

# ---------------------------------------------------------------------------
# _intact_validate_config_pins — after the merge and the schema migration,
# before anything downstream reads config.yaml expecting it complete.
#
# Every ENABLED module needs its primary pin AND every sidecar pin
# _u_stamp_transitive (lib/upgrade/modules/shared.sh) will go looking for.
# Kept as its OWN small table rather than sharing shared.sh's -- a change to
# one is then a visible diff against the other, not an invisible dependency
# two functions quietly relied on staying in sync.
#
# Without this, a missing pin surfaces as compose's `${VAR:?...}` dying
# mid-`up`, which reads as a compose bug. It is not one: it is an
# operator-editable config.yaml missing a value this release needs, and that
# deserves a message that says so before anything tries to start a
# container over it.
# ---------------------------------------------------------------------------
_intact_validate_config_pins() {
    local errors=() m primary sidecars sk pin

    declare -A _primary_key=(
        [elk]=elk [iris]=iris [timesketch]=timesketch
        [velociraptor]=velociraptor [volweb]=volweb [portainer]=portainer
        [plaso]=plaso [aws_sigma]=aws_sigma [o365rc]=o365rc [intact]=backend
    )
    # Pre-rename spellings, accepted only as a fallback. _intact_config_migrations
    # (line 59 of intact.sh, one step BEFORE this validation) renames
    # versions.cloudtrail -> versions.aws_sigma, so a migrated box has the new
    # name and an un-migrated one may still have the old.
    #
    # This map said `cloudtrail` and `dfir_o365rc` outright until 2026-08-12 --
    # the pre-rename names, demanded by a check that runs immediately AFTER the
    # rename that removes them. Any box with aws_sigma or o365rc enabled could
    # not upgrade at all: "config.yaml is missing pin(s) this release needs:
    # aws_sigma: no versions.cloudtrail". It bit a customer on 0811 -> 0813, and
    # it took intact's rollback down with it.
    declare -A _legacy_key=( [aws_sigma]=cloudtrail [o365rc]=dfir_o365rc )
    declare -A _sidecar_keys=(
        [timesketch]="timesketch_opensearch timesketch_postgres timesketch_redis timesketch_nginx"
        [iris]="iris_rabbitmq"
        [volweb]="volweb_postgres volweb_redis"
        [intact]="backend_tusd"
    )

    for m in "${UPGRADE_ORDER[@]}"; do
        _plan_module_enabled "$m" || continue

        primary="${_primary_key[$m]:-}"
        if [[ -n "$primary" ]]; then
            pin="$(read_config "['versions']['${primary}']" 2>/dev/null || echo '')"
            [[ "$pin" == "None" ]] && pin=""
            if [[ -z "$pin" && -n "${_legacy_key[$m]:-}" ]]; then
                pin="$(read_config "['versions']['${_legacy_key[$m]}']" 2>/dev/null || echo '')"
                [[ "$pin" == "None" ]] && pin=""
                [[ -n "$pin" ]] && log_info "  ${m}: using the pre-rename pin versions.${_legacy_key[$m]}"
            fi
            [[ -z "$pin" ]] && errors+=("${m}: no versions.${primary} in config.yaml")
        fi

        sidecars="${_sidecar_keys[$m]:-}"
        for sk in $sidecars; do
            pin="$(read_config "['versions']['${sk}']" 2>/dev/null || echo '')"
            [[ "$pin" == "None" ]] && pin=""
            [[ -z "$pin" ]] && errors+=("${m}: no versions.${sk} in config.yaml (sidecar pin)")
        done
    done

    if (( ${#errors[@]} )); then
        log_error "  config.yaml is missing pin(s) this release needs:"
        local e
        for e in "${errors[@]}"; do log_error "    - ${e}"; done
        return 1
    fi
    log_info "  config.yaml pins verified for every enabled module"
    return 0
}

# ---------------------------------------------------------------------------
# _intact_add_missing_env_keys
#
# Add .env keys a newer release expects and this box has never had.
#
# update_env_files() derives every module's .env from config.yaml, and it is
# called from install.sh ONLY -- never from an upgrade. So a key introduced in
# a later release reaches a fresh install and never reaches an upgraded box.
#
# Seen for real: a 0726 appliance upgraded to current had no
# ELASTICSEARCH_USER / ELASTICSEARCH_PASSWORD in modules/backend/.env, because
# 0726's config.sh never wrote them. The backend's own docker-compose.yaml
# interpolates ${ELASTICSEARCH_USER}, so every recreate logged
#
#   The "ELASTICSEARCH_USER" variable is not set. Defaulting to a blank string.
#
# and the container came up with blank credentials. Harmless while elk is
# disabled; on a box with elk enabled the backend cannot authenticate to
# Elasticsearch, and nothing says why. The elk module upgrader writes those two
# keys, but only when elk itself is being upgraded -- which is exactly the run
# where nobody is looking for this.
#
# ADD-ONLY, deliberately. This runs mid-upgrade, and update_env_files also
# writes VERSION pins; rewriting those from config.yaml while the engine is
# stamping them module by module would make plan_current_versions believe a
# module is already at its target before it has been touched. Existing values
# -- pins, operator-edited credentials -- are left exactly as they are.
# ---------------------------------------------------------------------------
_intact_add_missing_env_keys() {
    if ! declare -F update_env_files >/dev/null 2>&1; then
        log_warn "  update_env_files is unavailable; skipping the .env key check"
        return 0
    fi
    local before after
    before="$(cat "${SCRIPT_DIR}"/modules/*/.env 2>/dev/null | wc -l)"
    UPDATE_ENV_ADD_ONLY=1 update_env_files >/dev/null 2>&1
    unset UPDATE_ENV_ADD_ONLY
    after="$(cat "${SCRIPT_DIR}"/modules/*/.env 2>/dev/null | wc -l)"
    if (( after > before )); then
        log_info "  added $(( after - before )) .env key(s) this release expects that this box did not have"
    fi
    return 0
}
