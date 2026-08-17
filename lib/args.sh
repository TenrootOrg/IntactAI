#!/bin/bash
# Intact.AI Platform Installer - Command-line Arguments
#
# Parses install.sh's arguments and normalises whatever --package was pointed
# at into the concrete list of assets the rest of the install consumes.
#
# Split out of install.sh, where this ran as bare top-level code. It is a
# function now for two reasons: sourcing a file that executes off inherited
# "$@" is surprising, and a function can be called from a test with a
# synthetic argument list.
#
# Sets, all deliberately global:
#   INTACT_PACKAGES          the individual module-image asset files to load
#   INTACT_PACKAGE_ARGS      the raw --package arguments, before expansion
#   INTACT_AIRGAP             1 when --package was given at all
#   INTACT_UNWRAP_DIRS       scratch dirs to delete once the images are loaded
#   INTACT_SYSTEM_BUNDLE_SRC the located system bundle (Docker/apt deps) --
#                            a directory or a *-system-bundle.tar file, or
#                            empty if this release/args carry none. Resolved
#                            further (extracted if it's a tar) by
#                            lib/deps.sh:ensure_core_dependencies().

# True if $1's basename matches the well-known system-bundle asset name.
# Centralised here because five different call sites below need to agree on
# it: a bare file argument can BE one, a directory can CONTAIN one, a
# wrapper tar can carry one as a member, and none of those should ever be
# handed to load_images_from_package() -- it has no idea what a Docker/apt
# .deb repo tar is.
_is_system_bundle_tar_name() {
    [[ "$(basename -- "$1")" == *-system-bundle.tar ]]
}

# Records the first system-bundle source found among --package arguments.
# First match wins (mirrors every other "first of N inputs" rule in this
# file) -- a no-op once INTACT_SYSTEM_BUNDLE_SRC is already set.
#
# $1 may be a file or a directory:
#   directory -> an already-extracted "system-bundle/" subdirectory, else a
#                "*-system-bundle.tar" sitting directly inside it
#   file      -> the bundle tar itself if it matches the name, else its
#                PARENT directory is checked for a same-named sibling (the
#                common "USB stick with the wrapper and the bundle side by
#                side" layout)
_note_system_bundle_candidate() {
    local p="$1" dir sb
    [[ -n "${INTACT_SYSTEM_BUNDLE_SRC:-}" ]] && return 0
    [[ -n "$p" ]] || return 0
    if [[ -d "$p" ]]; then
        if [[ -d "${p}/system-bundle" ]]; then
            INTACT_SYSTEM_BUNDLE_SRC="${p}/system-bundle"
        else
            sb="$(find "$p" -maxdepth 1 -name '*-system-bundle.tar' 2>/dev/null | head -1)"
            [[ -n "$sb" ]] && INTACT_SYSTEM_BUNDLE_SRC="$sb"
        fi
    elif [[ -f "$p" ]]; then
        if _is_system_bundle_tar_name "$p"; then
            INTACT_SYSTEM_BUNDLE_SRC="$p"
        else
            dir="$(dirname -- "$p")"
            sb="$(find "$dir" -maxdepth 1 -name '*-system-bundle.tar' 2>/dev/null | head -1)"
            [[ -n "$sb" ]] && INTACT_SYSTEM_BUNDLE_SRC="$sb"
        fi
    fi
}

# ---------------------------------------------------------------------------
# Air-gap: install from release assets instead of the internet.
#
#   sudo bash install.sh --package /path/to/intact-upgrade-<tag>.tar
#   sudo bash install.sh --package /path/to/dir-of-module-assets/
#   sudo bash install.sh --package a.tar --package b.tar           (repeatable)
#
# A release publishes one asset per module plus a single bundle carrying all of
# them. Either works here: the bundle because it is one file and that is easier
# to carry into an air-gapped site, the module assets because they are what the
# release is actually made of. Point --package at a directory and every
# *.tar / *.tar.gz in it is used.
#
# BOTH suffixes, everywhere below. Assets and the wrapper are plain tar now --
# their contents are already-compressed image layers, so the outer gzip bought
# 0.55% for a full deflate pass over 5.4 GB -- but every package cut before that
# is a .tar.gz sitting on a USB stick in a site with no way to re-fetch it, and
# has to keep installing. `tar -xf`/`tar -tf` auto-detect the compression, so
# reading both costs nothing but the extra -name in the discovery globs.
#
# Loading the images up front means _pull_image_with_retry finds each one
# already in the local store and skips the registry -- so every existing
# deploy_* path works offline with no changes of its own. That is the whole
# trick; there is no separate offline code path to keep in step with the online
# one.
#
# An INSTALL always needs the complete module set. There is no baseline to
# compare against on a box with nothing on it, so "only what changed" has no
# meaning here -- that is an upgrade-side idea.
parse_install_args() {
    INTACT_PACKAGES=()
    INTACT_AIRGAP=0
    INTACT_SYSTEM_BUNDLE_SRC=""
    # Raw --package arguments, kept alongside INTACT_PACKAGES (which the
    # directory-expansion below overwrites with individual asset files) --
    # some callers still want the arguments as originally typed.
    INTACT_PACKAGE_ARGS=()
    local _p
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --package)
                _p="${2:-}"; INTACT_PACKAGE_ARGS+=("$_p"); INTACT_AIRGAP=1
                _note_system_bundle_candidate "$_p"
                # A bundle tar named directly on the command line is a
                # dependency repo, not a module-image asset -- keep it out
                # of INTACT_PACKAGES so load_images_from_package() never
                # sees it (it would fail with "the assets did not merge").
                _is_system_bundle_tar_name "$_p" || INTACT_PACKAGES+=("$_p")
                shift 2 ;;
            --package=*)
                _p="${1#*=}"; INTACT_PACKAGE_ARGS+=("$_p"); INTACT_AIRGAP=1
                _note_system_bundle_candidate "$_p"
                _is_system_bundle_tar_name "$_p" || INTACT_PACKAGES+=("$_p")
                shift ;;
            --help|-h)
                echo "Usage: sudo bash install.sh [--package <asset|dir> ...]"
                echo ""
                echo "  --package  install offline from release assets; no registry"
                echo "             access is attempted. Accepts the single bundle"
                echo "             (intact-upgrade-<tag>.tar), a directory of"
                echo "             per-module assets, or the flag repeated."
                echo ""
                echo "  With no arguments the release assets are downloaded from"
                echo "  GitHub. Images come only from those assets either way --"
                echo "  there is no per-image registry fallback."
                exit 0 ;;
            *)
                echo "Unknown argument: $1" >&2
                echo "Usage: sudo bash install.sh [--package <asset|dir> ...]" >&2
                exit 2 ;;
        esac
    done

    # Expand any directory into the assets inside it, so --package can point at a
    # folder someone copied off a USB stick without them having to list each file.
    #
    # EXCLUDES *-system-bundle.tar: that asset carries Docker/apt .deb files, not
    # a module image set, and load_images_from_package() has no idea what to do
    # with one. Already captured above by _note_system_bundle_candidate() (which
    # ran on the un-expanded directory argument), so dropping it here loses
    # nothing -- it just keeps it out of INTACT_PACKAGES, the same as the
    # release index (*.index.json) this loop already leaves alone by only
    # matching *.tar[.gz].
    if (( ${#INTACT_PACKAGES[@]} > 0 )); then
        _expanded=()
        for _p in "${INTACT_PACKAGES[@]}"; do
            if [[ -d "$_p" ]]; then
                while IFS= read -r _f; do _expanded+=("$_f"); done \
                    < <(find "$_p" -maxdepth 1 \
                             \( -name '*.tar.gz' -o -name '*.tar' \) \
                             ! -name '*-system-bundle.tar' \
                             ! -name '*-bootstrap.tar' \
                             ! -name '*-engine.tar.gz' | sort)
            else
                _expanded+=("$_p")
            fi
        done
        INTACT_PACKAGES=("${_expanded[@]}")
        unset _expanded _p _f
    fi

    # Unwrap a single-file WRAPPER package. scripts/prepare_package.sh (and the
    # UI's Prepare Package feature, which just runs that script) produce one
    # tar containing N per-module assets, an <tag>.index.json, and (when the
    # release carries one) the system bundle -- flat, no shared top-level
    # directory, no manifest.json of its own. It is deliberately NOT
    # extracted/merged before being carried across the air gap; see that
    # script's header for why. Detect that shape and splice its inner module
    # assets into INTACT_PACKAGES exactly as the directory case above does, so
    # load_images_from_package() merges them by the same shared-top-level-
    # directory construction it already relies on for a folder of assets -- no
    # change needed there. Its system bundle, if any, is routed to
    # INTACT_SYSTEM_BUNDLE_SRC instead, same as everywhere else in this
    # function -- it is not a module-image asset either.
    #
    # The unwrapped copies are temporary duplicates of bytes the operator already
    # has, so they are tracked in INTACT_UNWRAP_DIRS and deleted once the images
    # are in the docker store -- several GB that would otherwise sit in data/tmp
    # forever. The operator's own file is never touched.
    INTACT_UNWRAP_DIRS=()
    if (( ${#INTACT_PACKAGES[@]} > 0 )); then
        _expanded=()
        for _p in "${INTACT_PACKAGES[@]}"; do
            _wrapper_listing=""
            if [[ -f "$_p" ]]; then
                # -tf, not -tzf: the wrapper is a plain tar now and -tzf would fail
                # on it outright, leaving the listing empty and the package handed
                # to load_images_from_package as if it were a single module asset --
                # which would extract N tarballs into one directory, find no shared
                # root, and report "the assets did not merge". -tf reads gzip and
                # plain alike, so a .tar.gz wrapper carried into a site before this
                # change is still detected by exactly the same three tests below.
                _wrapper_listing="$(tar -tf "$_p" 2>/dev/null)" || _wrapper_listing=""
            fi
            # The suffix test accepts .tar as well as .tar.gz for the same reason:
            # the members are whatever CI published. Note this runs on assets too,
            # not just wrappers -- a module asset lists a shared top-level directory
            # and so is rejected by the '/' test above it, exactly as before.
            if [[ -n "$_wrapper_listing" ]] \
               && ! grep -q '/' <<< "$_wrapper_listing" \
               && ! grep -qx 'manifest.json' <<< "$_wrapper_listing" \
               && grep -q '\.tar\(\.gz\)\?$' <<< "$_wrapper_listing"; then
                # data/tmp is NOT in the repo (only data/.gitkeep is), so on a
                # fresh checkout mktemp -p would fail and fall back to /tmp --
                # which many hosts mount as a small tmpfs, so unwrapping a
                # multi-GB package there fills RAM and dies with a confusing
                # ENOSPC. Same reasoning as load_images_from_package's own
                # extraction dir; create it rather than rely on it existing.
                mkdir -p "${SCRIPT_DIR}/data/tmp" 2>/dev/null || true
                _unwrap_dir="$(mktemp -d -p "${SCRIPT_DIR}/data/tmp" unwrap-XXXXXX 2>/dev/null)" \
                    || _unwrap_dir="$(mktemp -d)"
                INTACT_UNWRAP_DIRS+=("$_unwrap_dir")
                log_info "$(basename "$_p") is a single-file package -- unwrapping its module assets"
                grep '\.tar\(\.gz\)\?$' <<< "$_wrapper_listing" | tar -xf "$_p" -C "$_unwrap_dir" -T -
                while IFS= read -r _f; do
                    if _is_system_bundle_tar_name "$_f"; then
                        _note_system_bundle_candidate "$_f"
                    else
                        case "$(basename -- "$_f")" in
                            # Stage 1's payload (the frozen upgrade engine) and
                            # the no-checkout bootstrap tar ride beside the
                            # module assets; neither is a module image set and
                            # load_images_from_package() must not see them.
                            *-engine.tar.gz|*-bootstrap.tar) ;;
                            *) _expanded+=("$_f") ;;
                        esac
                    fi
                done < <(find "$_unwrap_dir" -maxdepth 1 \
                             \( -name '*.tar.gz' -o -name '*.tar' \) | sort)
            else
                _expanded+=("$_p")
            fi
        done
        INTACT_PACKAGES=("${_expanded[@]}")
        unset _expanded _p _f _wrapper_listing _unwrap_dir
    fi

    export INTACT_AIRGAP
}
