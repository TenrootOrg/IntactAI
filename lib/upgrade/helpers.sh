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
u_undo_pin() {
    local module="$1" key="${2:-$1}" prev

    prev="$(read_config "['versions']['${key}']" 2>/dev/null || echo '')"
    if [[ -n "$prev" ]]; then
        u_undo "_pin_module_version '${key}' '${prev}'"
    else
        u_undo "_unpin_module_version '${key}'"
    fi
}
