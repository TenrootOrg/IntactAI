#!/bin/bash
# Intact.AI upgrade — small file/string helpers every module leans on.
#
# Nothing here is upgrade-specific in the way core.sh's primitives are; these
# are just generic enough that lib/common.sh felt like the wrong home (they
# exist FOR the backup/restore/read-a-pin shape u_undo registrations use).

# Snapshot a file so an undo can put it back. Echoes the backup path; echoes
# nothing and returns 1 if the source does not exist, so a caller can tell
# "backed up" from "there was nothing to back up" without a stat of its own.
backup_file_for_rollback() {
    local src="$1"
    [[ -f "$src" ]] || return 1
    local bak="${src}.upgrade-bak-$(date +%Y%m%d_%H%M%S)"
    if cp -p "$src" "$bak" 2>/dev/null; then
        echo "$bak"
        return 0
    fi
    log_warn "could not back up ${src}"
    return 1
}

# Restore, preserving the destination inode. `cp` onto the existing path
# rather than `mv` for the same reason _pin_module_version truncates in
# place: .env files are bind-mount and env_file sources, and swapping the
# inode under a running container is a change that appears to work.
restore_file_from_backup() {
    local dst="$1" bak="$2"
    [[ -f "$bak" ]] || { log_warn "no backup at ${bak} to restore"; return 1; }
    cp -p --no-preserve=mode "$bak" "$dst" 2>/dev/null || cp "$bak" "$dst" || return 1
    return 0
}

# Drop a backup once the transaction has committed. Best-effort by design:
# a leftover .upgrade-bak-* is harmless clutter, and failing an otherwise
# successful upgrade over an unlink error would be absurd.
discard_backup() {
    [[ -n "${1:-}" && -f "$1" ]] && rm -f "$1"
    return 0
}

sha256_of() {
    [[ -f "${1:-}" ]] || return 1
    sha256sum "$1" 2>/dev/null | awk '{print $1}'
}

# Read one KEY from a .env-style file. Returns 1 (and echoes nothing) when the
# key is absent, so callers can distinguish "unset" from "set to empty".
read_env_var() {
    local file="$1" key="$2" line
    [[ -f "$file" ]] || return 1
    line="$(grep -m1 -E "^[[:space:]]*${key}[[:space:]]*=" "$file" 2>/dev/null)" || return 1
    [[ -n "$line" ]] || return 1
    line="${line#*=}"
    # strip one layer of surrounding quotes, if present
    line="${line%\"}"; line="${line#\"}"
    line="${line%\'}"; line="${line#\'}"
    echo "$line"
    return 0
}

# u_undo_pin <module> [cfg_key]
#
# Register the undo for a config.yaml version pin. Call it BEFORE the u_do that
# pins, in the PARENT shell -- u_do runs its command in a forked subshell
# (`( "$@" ) &` in _u_run_with_deadline), so a u_undo issued from inside the
# pinned function appends to the child's copy of U_UNDO and dies with the fork.
#
# All seven modules pinned without registering any undo, so a rolled-back run
# left versions.<m> behind. On an UPGRADE that is merely untidy -- the module is
# still installed, just mislabelled. On a failed INSTALL it strands the box:
# U_FROM reads the pin, the retry plans an upgrade instead of an install, the
# install-only branches never fire, and for timesketch the empty-alembic
# refusal makes every subsequent attempt fail identically. Observed 2026-08-14:
# three consecutive runs only reached the install path because the pin was
# cleared by hand between them.
# The config.yaml `versions:` block as it stood BEFORE any module ran.
#
# Populated once by u_snapshot_pins (scripts/upgrade.sh, right after
# plan_build) and read by u_undo_pin. Declared -gA so it survives into the
# module functions, which run in this same shell for every non---timeout step.
declare -gA U_PIN_BEFORE=()
U_PIN_SNAPSHOT_TAKEN=0

# Record every versions.<key> before the package merge overwrites them.
#
# Deliberately NOT reused from ${CONFIG_FILE}.pre-upgrade-backup: that file is
# written by _intact_merge_versions AFTER its own early-return, is never
# restored by anything, and on an `--only <module>` run intact never executes
# -- so on disk it is a stale copy from some previous run, and restoring from
# it would pin last week's version.
u_snapshot_pins() {
    local m v
    U_PIN_BEFORE=()
    for m in "${UPGRADE_ORDER[@]}"; do
        v="$(read_config "['versions']['${m}']" 2>/dev/null || echo '')"
        [[ -n "$v" ]] && U_PIN_BEFORE["$m"]="$v"
    done
    # The pre-rename spelling, so a box old enough to pin `cloudtrail` still
    # has something to restore for aws_sigma.
    v="$(read_config "['versions']['cloudtrail']" 2>/dev/null || echo '')"
    [[ -n "$v" && -z "${U_PIN_BEFORE[aws_sigma]:-}" ]] && U_PIN_BEFORE[aws_sigma]="$v"
    U_PIN_SNAPSHOT_TAKEN=1
    log_info "  recorded ${#U_PIN_BEFORE[@]} config.yaml version pin(s) for rollback"
}

u_undo_pin() {
    local module="$1" key="${2:-$1}" prev

    # ELK IS DELIBERATELY EXEMPT, and this is not an oversight.
    #
    # _u_elk_restore_env holds ELASTIC_VERSION/KIBANA_VERSION FORWARD on
    # rollback when Elasticsearch has already started on the new image, because
    # ES refuses to open a data directory written by a newer version. Restoring
    # versions.elk to the older pin would put config.yaml BELOW the running
    # node -- and update_env_files re-derives .env from config.yaml, so the
    # next repair would push .env back down and the node would refuse to start.
    # That is the ELK-rollback-bricks-ES failure, reintroduced through a
    # different door. Leave elk's pin where the upgrade put it.
    if [[ "$key" == "elk" ]]; then
        log_info "  elk: version pin deliberately not rolled back (ES cannot open a newer data dir)"
        return 0
    fi

    # The snapshot is the whole point: reading config.yaml HERE returns the
    # value the package merge already wrote, which is what made this a no-op.
    # Fall back to the old behaviour only when no snapshot exists (an
    # install.sh-driven path, or a caller that never went through main()), so
    # this is never a behaviour change where there is nothing better to use.
    if (( U_PIN_SNAPSHOT_TAKEN )); then
        prev="${U_PIN_BEFORE[$key]:-}"
        if [[ -z "$prev" ]]; then
            # The key was absent before the upgrade -- e.g. intact-20260615 has
            # no versions.aws_sigma at all. Unpinning would delete a key that
            # _intact_validate_config_pins then requires for an enabled module,
            # and nothing re-adds it on an `--only <module>` repair. Leaving it
            # alone is the conservative half of the trade.
            log_info "  ${key}: no pre-upgrade pin recorded; leaving config.yaml untouched on rollback"
            return 0
        fi
    else
        prev="$(read_config "['versions']['${key}']" 2>/dev/null || echo '')"
    fi

    # printf %q, not hand-rolled single quotes. The undo stack is EVAL'd
    # (_u_unwind_current), and `prev` is a value out of the operator's own
    # config.yaml -- so a version string containing a single quote used to close
    # the quoting and hand the rest of itself to the shell. Measured: a pin of
    # `v2.4.27'; touch /tmp/PWNED; echo '` created the file during rollback. The
    # likelier version of the same bug is duller and worse for an operator: one
    # stray quote makes the eval a syntax error, the undo "fails", and a module
    # that rolled back perfectly well is reported as "ROLLBACK FAILED; needs
    # manual repair". %q is the shell's own answer to this -- its output is
    # defined as safe to re-read as input.
    if [[ -n "$prev" ]]; then
        u_undo "$(printf '_pin_module_version %q %q' "$key" "$prev")"
    else
        u_undo "$(printf '_unpin_module_version %q' "$key")"
    fi
}
