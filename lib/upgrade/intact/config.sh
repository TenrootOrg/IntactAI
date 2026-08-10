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
    [[ -f "$new" ]] || { log_info "  package carries no config.yaml; keeping local pins"; return 0; }

    cp -p "$CONFIG_FILE" "${CONFIG_FILE}.pre-upgrade-backup" 2>/dev/null

    local pairs
    pairs="$(python3 - "$new" <<'PY'
import sys
try:
    import yaml
    d = yaml.safe_load(open(sys.argv[1], encoding="utf-8")) or {}
except Exception:
    raise SystemExit(0)
for k, v in (d.get("versions") or {}).items():
    if v is None or str(v).strip() == "":
        continue
    print("%s\t%s" % (k, v))
PY
)"
    [[ -n "$pairs" ]] || { log_info "  package config.yaml has no versions block"; return 0; }

    local n=0 key val cur
    while IFS=$'\t' read -r key val; do
        [[ -n "$key" ]] || continue
        cur="$(read_config "['versions']['${key}']" 2>/dev/null || echo '')"
        [[ "$cur" == "$val" ]] && continue
        _pin_module_version "$key" "$val" && n=$((n + 1))
    done <<< "$pairs"
    log_info "  merged ${n} version pin(s) from the package into config.yaml"
    return 0
}

# The registry currently holds exactly one migration, 1 -> 2: consolidate the
# renamed cloudtrail/prowler modules into aws_sigma, carrying `enabled`
# forward. It does NOT rename the CLOUDTRAIL_VERSION env var -- that is a
# compat contract with every consumer of it.
_intact_config_migrations() {
    local current
    current="$(read_config "['schema_version']" 2>/dev/null || echo '')"
    [[ "$current" == "None" || -z "$current" ]] && current=1

    local CURRENT_SCHEMA_VERSION=2
    if (( current >= CURRENT_SCHEMA_VERSION )); then
        log_info "  config.yaml schema is current (v${current})"
        return 0
    fi

    cp -p "$CONFIG_FILE" "${CONFIG_FILE}.pre-migration-backup" 2>/dev/null
    log_info "  migrating config.yaml schema v${current} -> v${CURRENT_SCHEMA_VERSION}"

    if ! python3 - "$CONFIG_FILE" <<'PY'
import re, sys
path = sys.argv[1]
lines = open(path, encoding="utf-8").readlines()
out, changed = [], False

# modules.cloudtrail / modules.prowler -> modules.aws_sigma, keeping enabled.
for ln in lines:
    m = re.match(r"^(\s+)(cloudtrail|prowler)(\s*:\s*)$", ln)
    if m and m.group(2) == "cloudtrail":
        out.append("%saws_sigma%s\n" % (m.group(1), m.group(3))); changed = True; continue
    m2 = re.match(r"^(\s+)cloudtrail(\s*:\s*)(.+)$", ln)
    if m2:
        out.append("%saws_sigma%s%s\n" % (m2.group(1), m2.group(2), m2.group(3)))
        changed = True; continue
    out.append(ln)

# Stamp the new schema_version, inserting it first if absent.
for i, ln in enumerate(out):
    if re.match(r"^schema_version\s*:", ln):
        out[i] = "schema_version: 2\n"; break
else:
    out.insert(0, "schema_version: 2\n")

payload = "".join(out)
# Truncate in place: config.yaml is bind-mounted by inode.
with open(path, "w", encoding="utf-8") as fh:
    fh.write(payload); fh.flush()
    import os; os.fsync(fh.fileno())
PY
    then
        log_error "  schema migration failed; restoring config.yaml"
        cp -p "${CONFIG_FILE}.pre-migration-backup" "$CONFIG_FILE" 2>/dev/null
        return 1
    fi
    log_success "  config.yaml migrated to schema v${CURRENT_SCHEMA_VERSION}"
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
        [plaso]=plaso [aws_sigma]=cloudtrail [o365rc]=dfir_o365rc [intact]=backend
    )
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
