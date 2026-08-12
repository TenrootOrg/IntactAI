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
