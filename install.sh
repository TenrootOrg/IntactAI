#!/bin/bash
# Intact.AI Platform Installer
# For Ubuntu 24.04
#
# This script installs and configures the Intact.AI platform.
#
# Usage: sudo bash install.sh

set -o pipefail

# Every file this installer creates inherits this. Without it the operator's
# umask decides the mode: on a umask-000 host (common on Vagrant/dev VMs)
# install.sh was creating world-WRITABLE files — including its own
# install_*.log, which carries command output that has leaked credentials
# before. Must precede the LOG_FILE definition below, because the log is
# created by later redirects and would otherwise land 0666.
umask 022

# ============================================================================
# Script Configuration
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/config.yaml"
LOG_FILE="${SCRIPT_DIR}/install_$(date +%Y%m%d_%H%M%S).log"

# Export the real install path so each module's docker-compose.yaml can bind
# mount from the correct host location even when the user extracts the
# project outside the default /home/tenroot/intact (the backend compose
# reads ${INTACT_HOST_PATH:-...}).
export INTACT_HOST_PATH="$SCRIPT_DIR"

# ============================================================================
# Harden the code we are about to source, BEFORE sourcing it
# ============================================================================
# This installer runs as root, so a group/world-writable lib/*.sh is a local
# root-escalation path: anyone who can write there between extraction and
# `sudo bash install.sh` gets their code executed as root.
#
# It is reachable in practice. actions/upload-artifact strips every Unix mode
# bit from the release zip, so the extracted tree's modes come from the target
# box's umask — on a umask-000 host that is 0777 dirs / 0666 files.
#
# fix_source_permissions() does the full sweep, but it is called from main(),
# hundreds of lines AFTER the source statements below. This block is the only
# thing protecting the sourcing itself.
#
# Scoped deliberately to executable code. A blanket `chmod -R` over SCRIPT_DIR
# would also hit data/, client_installers/ and modules/timesketch/config/ —
# writable bind mounts holding live container-written files — and install.sh
# re-runs on every upgrade, so that would strip group-write from a populated
# appliance, not just a fresh extract.
#
# go-w only: removes group/other WRITE, preserves read and the execute bit, so
# sourcing here and the `chmod +x` in fix_source_permissions are unaffected.
chmod go-w "${SCRIPT_DIR}/install.sh" 2>/dev/null || true
chmod go-w "${SCRIPT_DIR}"/lib/*.sh 2>/dev/null || true
chmod go-w "${SCRIPT_DIR}"/scripts/*.sh 2>/dev/null || true

# Best-effort by design — warn, never abort. On a VirtualBox vboxsf / 9p / NTFS
# mount chmod is a silent no-op and every file is forced 0777, so failing closed
# would refuse to install on exactly those test VMs. Be honest about the limit:
# this warning makes the exposure visible, it does not close it. chmod cannot
# fix a filesystem that ignores chmod.
_writable_libs="$(find "${SCRIPT_DIR}/lib" -maxdepth 1 -name '*.sh' -perm /022 2>/dev/null)"
if [[ -n "$_writable_libs" ]]; then
    echo "" >&2
    echo "WARNING: these files are group/world-writable and are about to be sourced as root:" >&2
    while IFS= read -r _wl; do echo "    $_wl" >&2; done <<< "$_writable_libs"
    echo "         chmod could not fix them, which usually means a vboxsf/9p/NTFS mount." >&2
    echo "         Anyone who can write them can run code as root. Prefer a local ext4 path." >&2
    echo "" >&2
fi
unset _writable_libs _wl

# ============================================================================
# Load Library Modules
# ============================================================================

source "${SCRIPT_DIR}/lib/common.sh"
source "${SCRIPT_DIR}/lib/config.sh"
source "${SCRIPT_DIR}/lib/docker.sh"
source "${SCRIPT_DIR}/lib/modules.sh"
source "${SCRIPT_DIR}/lib/health.sh"

# ============================================================================
# Main Installation Flow
# ============================================================================

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
INTACT_PACKAGES=()
INTACT_AIRGAP=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --package)
            INTACT_PACKAGES+=("${2:-}"); INTACT_AIRGAP=1; shift 2 ;;
        --package=*)
            INTACT_PACKAGES+=("${1#*=}"); INTACT_AIRGAP=1; shift ;;
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
if (( ${#INTACT_PACKAGES[@]} > 0 )); then
    _expanded=()
    for _p in "${INTACT_PACKAGES[@]}"; do
        if [[ -d "$_p" ]]; then
            while IFS= read -r _f; do _expanded+=("$_f"); done \
                < <(find "$_p" -maxdepth 1 \
                         \( -name '*.tar.gz' -o -name '*.tar' \) | sort)
        else
            _expanded+=("$_p")
        fi
    done
    INTACT_PACKAGES=("${_expanded[@]}")
    unset _expanded _p _f
fi

# Unwrap a single-file WRAPPER package. scripts/prepare_package.sh (and the
# UI's Prepare Package feature, which just runs that script) produce one
# tar containing N per-module assets plus an <tag>.index.json --
# flat, no shared top-level directory, no manifest.json of its own. It is
# deliberately NOT extracted/merged before being carried across the air gap;
# see that script's header for why. Detect that shape and splice its N inner
# assets into INTACT_PACKAGES exactly as the directory case above does, so
# load_images_from_package() merges them by the same shared-top-level-
# directory construction it already relies on for a folder of assets -- no
# change needed there.
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
            while IFS= read -r _f; do _expanded+=("$_f"); done \
                < <(find "$_unwrap_dir" -maxdepth 1 \
                         \( -name '*.tar.gz' -o -name '*.tar' \) | sort)
        else
            _expanded+=("$_p")
        fi
    done
    INTACT_PACKAGES=("${_expanded[@]}")
    unset _expanded _p _f _wrapper_listing _unwrap_dir
fi

export INTACT_AIRGAP

# Display names for progress lines below. Keys are module ids, matched
# against each asset's filename by suffix ("...-<id>.tar[.gz]") -- a --package
# install can point at files carrying no release tag at all, so this cannot
# assume the "intact-<tag>-<module>" shape and parse the tag back out.
declare -A INTACT_MODULE_DISPLAY=(
    [intact]="Intact.AI platform" [elk]="ELK" [iris]="IRIS"
    [timesketch]="TimeSketch" [plaso]="Plaso" [velociraptor]="Velociraptor"
    [volweb]="VolWeb" [aws_sigma]="AWS SIGMA rules" [portainer]="Portainer"
)

_module_from_asset_name() {
    # Strip .tar.gz first, then .tar, so both asset shapes reduce to the same
    # "...-<module>" stem. Without the second strip a plain-tar asset keeps its
    # ".tar" suffix, matches no module id, and every progress line for it reads
    # as the raw filename with no display name -- cosmetic, but it is the line
    # an operator watches for 20 minutes during an air-gapped install.
    local base="${1%.tar.gz}" id
    base="${base%.tar}"
    for id in "${!INTACT_MODULE_DISPLAY[@]}"; do
        [[ "$base" == *"-${id}" ]] && { echo "$id"; return 0; }
    done
    echo ""
}

# Display name for a module id, or $2 when the id is unknown/empty. Goes
# through a function rather than ${INTACT_MODULE_DISPLAY[$id]:-...} inline
# because bash raises "bad array subscript" on an EMPTY subscript, and an
# empty id is the normal case for a legacy single bundle or an
# operator-renamed file.
_module_display() {
    local id="${1:-}" fallback="${2:-}"
    [[ -n "$id" && -n "${INTACT_MODULE_DISPLAY[$id]:-}" ]] \
        && { echo "${INTACT_MODULE_DISPLAY[$id]}"; return 0; }
    echo "${id:-$fallback}"
}

_human_size() {
    numfmt --to=iec "${1:-0}" 2>/dev/null || echo "${1:-0}B"
}

# True if $1 looks like a `docker save` archive (top-level manifest.json /
# index.json / oci-layout), false if it is a plain data tar bundled under
# images/ (e.g. the aws_sigma SIGMA rule pack). Ports
# services/upgrade/base.py:_tar_is_docker_image() so install.sh applies the
# same distinction the upgrade engine already does -- see that function's
# docstring for why. On any read error this returns TRUE (fail-open): an
# unreadable tar still gets handed to `docker load`, which is today's
# behaviour, rather than being silently skipped as "not an image".
_tar_is_docker_image() {
    local t="$1" listing name
    listing="$(tar -tf "$t" 2>/dev/null)" || return 0
    while IFS= read -r name; do
        name="${name#./}"
        case "$name" in
            manifest.json|index.json|oci-layout) return 0 ;;
        esac
    done <<< "$listing"
    return 1
}

# Load every image out of the package into the local docker store.
#
# Idempotent and non-fatal per image: `docker load` on an image that is already
# present is a no-op, and one unreadable tar should not abort an install that
# may not even need that module. What DOES abort is a package that yields no
# images at all -- that is a wrong or corrupt file, and continuing would fall
# through to registry pulls that cannot work on an air-gapped box.
#
# Sets INTACT_PKG_BACKEND_TAG (best-effort) to the backend image tag this
# package actually shipped, so the caller can correct a stale
# config.yaml versions.backend rather than trust it -- see lib/config.sh and
# lib/modules.sh:deploy_backend.
load_images_from_package() {
    # Takes ONE OR MORE assets. Per-module assets share a top-level directory
    # name, so extracting them all into one place merges them into the single
    # tree the rest of this function expects -- the same contract the on-box
    # assembler relies on. A single bundle is just the degenerate case of one.
    local pkgs=("$@")
    if (( ${#pkgs[@]} == 0 )); then
        log_error "No release assets supplied"
        return 1
    fi
    local pkg
    for pkg in "${pkgs[@]}"; do
        if [[ ! -f "$pkg" ]]; then
            log_error "Asset not found: $pkg"
            return 1
        fi
    done
    log_info "Installing from ${#pkgs[@]} asset(s): $(basename "${pkgs[0]}")$( (( ${#pkgs[@]} > 1 )) && echo " (+$(( ${#pkgs[@]} - 1 )) more)")"
    mkdir -p "${SCRIPT_DIR}/data/tmp" 2>/dev/null || true
    INTACT_PKG_BACKEND_TAG=""

    # Extract onto the appliance's own disk, not /tmp. The assets total several
    # GB and many hosts mount /tmp as a small tmpfs -- extracting there fills RAM
    # and fails with a confusing ENOSPC partway through, after the download
    # already succeeded. Fall back to /tmp only if the repo disk is unusable,
    # which is the situation where nothing will work anyway.
    local work
    work="$(mktemp -d -p "${SCRIPT_DIR}/data/tmp" pkg-XXXXXX 2>/dev/null)" \
        || work="$(mktemp -d)"

    local total_size=0 pkg_size
    for pkg in "${pkgs[@]}"; do
        pkg_size=$(stat -c%s "$pkg" 2>/dev/null || echo 0)
        total_size=$((total_size + pkg_size))
    done
    log_info "Extracting assets — ${#pkgs[@]} asset(s), $(_human_size "$total_size")"

    local ext_i=0 base mod_id display
    for pkg in "${pkgs[@]}"; do
        ext_i=$((ext_i + 1))
        base="$(basename "$pkg")"
        mod_id="$(_module_from_asset_name "$base")"
        display="$(_module_display "$mod_id" "$base")"
        pkg_size=$(stat -c%s "$pkg" 2>/dev/null || echo 0)
        # -xf, not -xzf: tar auto-detects, so this one call reads a plain-tar
        # asset and a .tar.gz asset from an older release without the caller
        # having to know which it was handed.
        #
        # QUIET + a single after-the-fact line, same as the image-load loop
        # below: the start line and the wrapper's "completed in Ns" said the
        # same thing twice per asset.
        if ! RUN_HEARTBEAT_QUIET=1 run_with_heartbeat "extracting ${display} asset" 1800 \
                bash -c 'tar -xf "$1" -C "$2" 2>>"$3"' _ "$pkg" "$work" "$LOG_FILE"; then
            log_error "  Could not extract ${display} (${base})"
            rm -rf "$work"; return 1
        fi
        log_info "  [${ext_i}/${#pkgs[@]}] ${display} — extracted $(_human_size "$pkg_size") in ${RUN_HEARTBEAT_ELAPSED:-?}s"
    done
    log_success "Extraction complete: ${#pkgs[@]} asset(s), $(_human_size "$total_size")"

    # One merged tree, or the assets did not share a root and each would be a
    # separate half-package.
    local roots
    roots=$(find "$work" -mindepth 1 -maxdepth 1 -type d | wc -l)
    if (( roots != 1 )); then
        log_error "  The assets did not merge — got $roots top-level directories."
        log_error "  They are not from the same release, or were built without"
        log_error "  a shared --work-dir."
        rm -rf "$work"; return 1
    fi

    # A DELTA package predates the per-module scheme: it carried only the
    # modules whose versions had moved since some other release. Deltas are no
    # longer produced, but one can still be sitting on a USB stick, and it must
    # be refused by name rather than half-applied. Checked here, on the
    # EXTRACTED tree, rather than pre-extraction as before: gzip isn't
    # seekable, so reading `*/manifest.json` out of each compressed asset
    # meant fully decompressing every one of them just to read a few bytes of
    # JSON -- an unexplained multi-minute silence on a multi-GB release with
    # nothing to show for it. Now it's a handful of small files already on
    # disk. Scans both the root manifest.json (legacy single bundle) and every
    # per-module manifests/*.json sidecar, so a delta shipped as a per-module
    # asset can't slip through either.
    local delta_kind
    delta_kind="$(python3 -c "
import json, glob, sys
work = sys.argv[1]
paths = glob.glob(f'{work}/*/manifest.json') + glob.glob(f'{work}/*/manifests/*.json')
for p in paths:
    try:
        m = json.load(open(p))
    except Exception:
        continue
    if (m.get('contents') or {}).get('package_kind') == 'delta':
        print('delta')
        break
" "$work" 2>/dev/null)"
    if [[ "$delta_kind" == "delta" ]]; then
        log_error "  This package is a DELTA package: it carries only the"
        log_error "  modules whose versions moved since another release, so it"
        log_error "  cannot install a box from scratch. Use the release bundle"
        log_error "  or its per-module assets."
        rm -rf "$work"; return 1
    fi

    # Attribute every bundled image tar to its owning module and record its
    # size, from the manifest sidecars already on disk -- no extra I/O. Each
    # per-module asset carries manifests/<module>.json (a full copy of that
    # module's manifest, contents.images + contents.image_sizes included); a
    # legacy single-bundle asset has only the root manifest.json and no
    # per-module attribution, so its images are labelled "(unattributed)"
    # rather than guessed.
    declare -A IMG_OWNER=() IMG_SIZE=()
    local _iname _iowner _isize
    # Field separator is '|', not a tab: bash's `read` squeezes RUNS of tab
    # (and space/newline) as a single delimiter no matter what IFS is set to,
    # so an empty owner field -- "name<TAB><TAB>size", the normal case for a
    # legacy single-bundle package with no per-module manifest to attribute
    # images to -- collapses the two tabs into one and shifts size into
    # _iowner, leaving _isize empty. That mislabels every image with its own
    # byte count as a bogus "module id", which matches no enabled module and
    # gets every image skipped -- an install that loads zero images and
    # aborts. '|' is never whitespace, so consecutive delimiters do NOT
    # collapse and an empty field reads back empty.
    while IFS='|' read -r _iname _iowner _isize; do
        [[ -n "$_iname" ]] || continue
        IMG_OWNER["$_iname"]="$_iowner"
        [[ -n "$_isize" ]] && IMG_SIZE["$_iname"]="$_isize"
    done < <(python3 -c "
import json, glob, os, sys
work = sys.argv[1]
owner, size = {}, {}
sidecars = glob.glob(os.path.join(work, '*', 'manifests', '*.json'))
sources = sidecars if sidecars else glob.glob(os.path.join(work, '*', 'manifest.json'))
for p in sources:
    module = os.path.splitext(os.path.basename(p))[0] if sidecars else ''
    try:
        m = json.load(open(p))
    except Exception:
        continue
    c = m.get('contents') or {}
    sizes = c.get('image_sizes') or {}
    for img in c.get('images') or []:
        if module:
            owner[img] = module
        if img in sizes:
            size[img] = sizes[img]
for img in sorted(set(owner) | set(size)):
    print(f'{img}|{owner.get(img, \"\")}|{size.get(img, \"\")}')
" "$work" 2>/dev/null)

    # Classify every bundled tar up front: a docker-save image, or a plain
    # data tar (e.g. the aws_sigma SIGMA rule pack) that must NOT be handed to
    # `docker load` -- see _tar_is_docker_image(). Data tars are staged aside
    # rather than applied here: download_sigma_rules() runs later in main()
    # and rm -rf's /opt/sigma-rules before cloning, so anything written here
    # would be silently destroyed. install_bundled_rule_packs() applies them
    # after that clone step.
    local image_tars=() data_tars=() t
    while IFS= read -r t; do
        if _tar_is_docker_image "$t"; then
            image_tars+=("$t")
        else
            data_tars+=("$t")
        fi
    done < <(find "$work" -type f -name '*.tar' 2>/dev/null | sort)

    local rule_pack_dir="${SCRIPT_DIR}/data/tmp/rule-packs"
    if (( ${#data_tars[@]} > 0 )); then
        mkdir -p "$rule_pack_dir"
        for t in "${data_tars[@]}"; do
            base="$(basename "$t")"
            log_info "  ${base}: bundled data/rule pack, not a docker image — staged for install"
            cp -f "$t" "$rule_pack_dir/" 2>/dev/null || true
        done
    fi

    local images_total_size=0
    for t in "${image_tars[@]}"; do
        images_total_size=$(( images_total_size + $(stat -c%s "$t" 2>/dev/null || echo 0) ))
    done
    log_info "Package contents: ${#image_tars[@]} image tar(s) ($(_human_size "$images_total_size")), ${#data_tars[@]} rule pack(s)"

    # Which modules' images are worth loading. A release package carries every
    # module; a box installs the ones it has enabled. Loading the rest writes
    # gigabytes into the docker store that no container will ever reference --
    # observed on this appliance: IRIS is disabled and its four images (2.0 GB)
    # were sitting there anyway, because this loop knew the owning module (it
    # prints it on every line) and never asked whether it was wanted.
    #
    # The upgrade path already does this, pruning unselected modules' tars
    # before the load (services/upgrade/__init__.py, "Pruned N image(s) for
    # unselected modules"); the installer simply never got the same treatment.
    #
    # Unattributed images are ALWAYS loaded. An image nobody owns is a
    # packaging gap, and skipping one a module silently needs turns that into
    # a failed install -- the same reasoning the upgrade-side prune uses.
    declare -A _MOD_WANTED=()
    local _m _en
    for _m in "${!INTACT_MODULE_DISPLAY[@]}"; do
        [[ "$_m" == "intact" ]] && { _MOD_WANTED[$_m]=1; continue; }   # platform: always
        _en="$(read_config "['modules']['${_m}']['enabled']" 2>/dev/null || echo "")"
        if [[ -z "$_en" ]] || is_enabled "$_en"; then _MOD_WANTED[$_m]=1; fi
    done

    local loaded=0 failed=0 skipped=0 skipped_bytes=0 img_i=0 img_total=${#image_tars[@]}
    for tar_file in "${image_tars[@]}"; do
        img_i=$((img_i + 1))
        base="$(basename "$tar_file")"
        mod_id="${IMG_OWNER[$base]:-}"
        display="$(_module_display "$mod_id" "(unattributed)")"
        if [[ -n "$mod_id" && -z "${_MOD_WANTED[$mod_id]:-}" ]]; then
            pkg_size="${IMG_SIZE[$base]:-$(stat -c%s "$tar_file" 2>/dev/null || echo 0)}"
            skipped=$((skipped + 1)); skipped_bytes=$((skipped_bytes + pkg_size))
            log_info "  [${img_i}/${img_total}] ${display} — skipped, module disabled in config.yaml ($(_human_size "$pkg_size"))"
            continue
        fi
        pkg_size="${IMG_SIZE[$base]:-$(stat -c%s "$tar_file" 2>/dev/null || echo 0)}"
        local load_log; load_log="$(mktemp -p "${SCRIPT_DIR}/data/tmp" load-XXXXXX)"
        # ONE line per image on success, not four. The start line is dropped
        # (the success line carries the same counter and more information), the
        # wrapper's generic "completed in Ns" is suppressed via QUIET with its
        # duration folded in here, and docker's own "Loaded image: <ref>" is no
        # longer echoed into the log because ${ref} below already IS that value
        # parsed out of it. See lib/common.sh:run_with_heartbeat.
        if RUN_HEARTBEAT_QUIET=1 run_with_heartbeat "loading ${display}/${base}" 1800 \
                bash -c '"$1" load -i "$2" >"$3" 2>&1' _ "${DOCKER_BIN:-docker}" "$tar_file" "$load_log"; then
            loaded=$((loaded + 1))
            local ref; ref="$(sed -n 's/^Loaded image: //p' "$load_log" | tail -1)"
            log_success "  [${img_i}/${img_total}] ${display} — ${ref:-loaded} ($(_human_size "$pkg_size"), ${RUN_HEARTBEAT_ELAPSED:-?}s)"
            # Capture what the package actually shipped as the backend image,
            # so the caller can correct a stale config.yaml versions.backend
            # instead of trusting it (see lib/config.sh + lib/modules.sh).
            if [[ -z "$INTACT_PKG_BACKEND_TAG" && "$base" == intact-backend-*.tar ]]; then
                if [[ -n "$ref" && "$ref" == intact-backend:* ]]; then
                    INTACT_PKG_BACKEND_TAG="${ref#intact-backend:}"
                else
                    INTACT_PKG_BACKEND_TAG="${base#intact-backend-}"
                    INTACT_PKG_BACKEND_TAG="${INTACT_PKG_BACKEND_TAG%.tar}"
                fi
            fi
            # FREE AS WE GO. Once an image is in the docker store its extracted
            # tar is dead weight, but all 23 of them used to sit here until the
            # whole loop finished -- 13 GB of extracted tars coexisting with the
            # 5.5 GB of source assets AND the images being written into
            # /var/lib/docker. Measured peak on a 9-module install: ~22 GB of
            # scratch before the first byte of image store.
            #
            # Safe to delete: $work is a mktemp copy this function extracted, so
            # an operator's --package files on a USB stick are never touched.
            # The merged-tree invariant is untouched too -- only already-loaded
            # image tars go; binaries/, tools/, yara_rulesets/ and manifests/
            # all survive for the staging step below.
            rm -f "$tar_file"
        else
            failed=$((failed + 1))
            log_warn "  [${img_i}/${img_total}] ${display} — could not load ${base}: $(tail -1 "$load_log" 2>/dev/null)"
            # Only on failure: here it is diagnostic. On success it repeated
            # the image ref the line above already printed.
            cat "$load_log" >> "$LOG_FILE" 2>/dev/null
        fi
        rm -f "$load_log"
    done

    # Prefer the manifest's own version.intact over anything guessed from a
    # tar filename or docker's own "Loaded image:" line -- it's what
    # ensure_backend_runtime_image() on the upgrade side treats as
    # authoritative, and it's readable even when the backend image was
    # ALREADY present locally and docker load therefore printed nothing new.
    local manifest_backend_tag
    manifest_backend_tag="$(python3 -c "
import json, glob, sys
work = sys.argv[1]
for p in glob.glob(f'{work}/*/manifests/intact.json') + glob.glob(f'{work}/*/manifest.json'):
    try:
        v = (json.load(open(p)).get('versions') or {}).get('intact')
    except Exception:
        v = None
    if v:
        print(v)
        break
" "$work" 2>/dev/null)"
    if [[ -n "$manifest_backend_tag" ]]; then
        INTACT_PKG_BACKEND_TAG="$manifest_backend_tag"
    fi
    if [[ -n "$INTACT_PKG_BACKEND_TAG" ]]; then
        log_info "  Package backend image tag: ${INTACT_PKG_BACKEND_TAG}"
    fi
    export INTACT_PKG_BACKEND_TAG

    # Images are not the only thing an air-gapped box cannot fetch. The
    # installer also downloads Velociraptor binaries (current + legacy
    # clients, the offline collector) and clones SigmaHQ. Deliver whatever
    # the package carries so the download_* / stage_* functions find their
    # work already done; each reports honestly if something is genuinely
    # absent (see lib/docker.sh:_airgap_asset_check).
    local dl_dir="${SCRIPT_DIR}/modules/nginx/html/downloads"
    local staged_bin=0 bin
    mkdir -p "$dl_dir"
    while IFS= read -r bin; do
        # cp -n exits 0 whether it copied or declined to overwrite an
        # existing file of the same name -- count only what it actually
        # placed, or "Staged N binaries" over-reports on a re-run.
        if [[ ! -e "$dl_dir/$(basename "$bin")" ]] && cp -n "$bin" "$dl_dir/" 2>/dev/null; then
            staged_bin=$((staged_bin + 1))
        fi
    done < <(find "$work" -type d -name binaries -exec find {} -type f \; 2>/dev/null)
    if (( staged_bin > 0 )); then
        chmod 755 "$dl_dir"/* 2>/dev/null || true   # 755, not +x: umask filters symbolic modes
        log_success "  Staged $staged_bin Velociraptor binary/binaries into ${dl_dir}"
    fi

    # Also stage into the Velociraptor build-context paths the Dockerfile
    # COPYs from (modules/velociraptor/clients/...) and drop the .version
    # sidecar stage_velociraptor_client_binaries() needs to skip a re-download
    # -- see lib/docker.sh. Without this the flat copy above satisfies
    # download_offline_collector_binaries()'s check but NOT this one, and the
    # image build re-fetches ~250 MB from github.com even though the package
    # already carried it (observed 2026-08-04).
    local velo_dir="${SCRIPT_DIR}/modules/velociraptor"
    local velo_bin
    velo_bin="$(find "$work" -type f -name 'velociraptor-v*-linux-amd64' ! -name '*-musl' 2>/dev/null | head -1)"
    if [[ -n "$velo_bin" ]]; then
        local vfile vver
        vfile="$(basename "$velo_bin")"
        vver="$(sed -n 's/^velociraptor-v\(.*\)-linux-amd64$/\1/p' <<< "$vfile")"
        local expect_ver; expect_ver="$(read_config "['versions']['velociraptor']" 2>/dev/null)"
        if [[ -n "$expect_ver" && "$expect_ver" != "$vver" ]]; then
            log_warn "  Bundled Velociraptor client is v${vver} but config.yaml pins v${expect_ver}"
        fi
        mkdir -p "${velo_dir}/clients/linux" "${velo_dir}/clients/mac" "${velo_dir}/clients/windows"
        local _pairs=(
            "velociraptor-v${vver}-linux-amd64|${velo_dir}/clients/linux/velociraptor"
            "velociraptor-v${vver}-darwin-amd64|${velo_dir}/clients/mac/velociraptor_client"
            "velociraptor-v${vver}-windows-amd64.exe|${velo_dir}/clients/windows/velociraptor_client.exe"
            "velociraptor-v${vver}-windows-amd64.msi|${velo_dir}/clients/windows/velociraptor_client.msi"
        )
        local _p _srcname _dest _src staged_ctx=0
        for _p in "${_pairs[@]}"; do
            _srcname="${_p%%|*}"; _dest="${_p##*|}"
            _src="$(find "$work" -type f -name "$_srcname" 2>/dev/null | head -1)"
            [[ -n "$_src" ]] || continue
            cp -f "$_src" "$_dest" && staged_ctx=$((staged_ctx + 1))
            [[ "$_dest" != *.msi ]] && chmod 755 "$_dest" 2>/dev/null || true
            printf '%s\n' "$vver" > "${_dest}.version"
        done
        (( staged_ctx > 0 )) && log_success "  Staged ${staged_ctx} Velociraptor client binary/binaries for the image build (v${vver})"
        local _collector_src
        _collector_src="$(find "$work" -type f -name 'velociraptor-collector' 2>/dev/null | head -1)"
        if [[ -n "$_collector_src" ]]; then
            mkdir -p "${SCRIPT_DIR}/data/tools"
            cp -f "$_collector_src" "${SCRIPT_DIR}/data/tools/velociraptor-collector"
            log_success "  Staged velociraptor-collector into data/tools"
        fi
    fi

    # Stage the remaining payload directories the release ships. Until now this
    # function looked at `binaries/` and nothing else, then `rm -rf "$work"`
    # below deleted the rest -- so three directories that CI deliberately packs
    # were carried across the air gap and thrown away, and the installer went
    # to the internet for the exact same bytes. Verified on intact-20260805:
    # tools/lolrmm.csv (137755), tools/lastactivityview.zip (89801) and
    # tools/autorunsc64.exe (1460024) shipped in the velociraptor asset, and
    # the install re-downloaded all three at byte-identical sizes.
    #
    # Each destination is where the ALREADY-EXISTING consumer looks, so no
    # consumer changes: tools_download_service skips files already in
    # data/tools, velociraptor_init_service reads the artifacts zip from the
    # same place, and seed_yara_rulesets (lib/modules.sh) prefers
    # data/yara_rulesets over a GitHub clone.
    #
    # cp -n throughout: a package must never clobber something a previous run
    # or the operator put there. Counting only what landed keeps the log honest
    # on re-runs, same rule as the binaries loop above.
    # The YARA destination mirrors a package layout on purpose --
    # `<dir>/manifest.json` + `<dir>/yara_rulesets/*.zip` -- because that is
    # exactly what services/upgrade/volweb.py:_seed_yara_from_bundle() already
    # consumes. Staging into that shape lets seed_yara_rulesets() delegate to
    # the tested importer instead of reimplementing ORM ingest in bash.
    local _yara_seed="${SCRIPT_DIR}/data/yara-seed"
    local _stage_pairs=(
        # <find-path-under-work>|<destination dir>|<label>
        "tools|${SCRIPT_DIR}/data/tools|Velociraptor tool"
        "artifacts/velociraptor|${SCRIPT_DIR}/data/tools|Velociraptor artifact bundle"
        "yara_rulesets|${_yara_seed}/yara_rulesets|VolWeb YARA ruleset"
    )
    local _sp _srcdir _destdir _label _f _n
    for _sp in "${_stage_pairs[@]}"; do
        IFS='|' read -r _srcdir _destdir _label <<< "$_sp"
        # The asset root is intact-upgrade-<tag>/, so match at any depth.
        _srcdir="$(find "$work" -type d -path "*/${_srcdir}" 2>/dev/null | head -1)"
        [[ -n "$_srcdir" && -d "$_srcdir" ]] || continue
        mkdir -p "$_destdir"
        _n=0
        while IFS= read -r _f; do
            if [[ ! -e "$_destdir/$(basename "$_f")" ]] \
                    && cp -n "$_f" "$_destdir/" 2>/dev/null; then
                _n=$((_n + 1))
            fi
        done < <(find "$_srcdir" -maxdepth 1 -type f 2>/dev/null)
        if (( _n > 0 )); then
            chmod 755 "$_destdir"/* 2>/dev/null || true
            log_success "  Staged ${_n} ${_label}(s) into ${_destdir#"${SCRIPT_DIR}/"}"
        fi
    done

    # Pair the staged zips with the manifest that describes them (name,
    # description, source_url per ruleset). Prefer the per-module
    # manifests/volweb.json: assets all extract under ONE shared top-level
    # directory, so the root manifest.json is whichever module landed last,
    # while manifests/<module>.json survives the merge intact.
    if [[ -d "${_yara_seed}/yara_rulesets" ]] \
            && ! ls "${_yara_seed}"/yara_rulesets/*.zip >/dev/null 2>&1; then
        rmdir "${_yara_seed}/yara_rulesets" "${_yara_seed}" 2>/dev/null || true
    elif [[ -d "${_yara_seed}/yara_rulesets" ]]; then
        local _ymf
        _ymf="$(find "$work" -type f -path '*/manifests/volweb.json' 2>/dev/null | head -1)"
        [[ -n "$_ymf" ]] || _ymf="$(find "$work" -maxdepth 2 -type f -name manifest.json 2>/dev/null | head -1)"
        if [[ -n "$_ymf" ]] && cp -f "$_ymf" "${_yara_seed}/manifest.json" 2>/dev/null; then
            log_success "  Staged VolWeb YARA seed manifest into data/yara-seed"
        else
            # Without it the importer has no ruleset names; say so rather than
            # letting the seed silently no-op later.
            log_warn "  Bundled YARA zips staged but no manifest found — VolWeb seeding will fall back to online"
        fi
    fi

    rm -rf "$work"
    if (( loaded == 0 )); then
        log_error "  No images loaded from the package — wrong or corrupt file."
        return 1
    fi
    if (( failed > 0 )); then
        log_success "  Loaded $loaded image(s) from the package ($failed failed)"
    else
        log_success "  Loaded $loaded image(s) from the package"
    fi
    if (( skipped > 0 )); then
        log_info "  Skipped $skipped image(s) for disabled modules, keeping $(_human_size "$skipped_bytes") out of the docker store"
        log_info "  Enable a module in config.yaml and re-run to load its images."
    fi
    # Loading is not installing. config.yaml's per-module `enabled` flag still
    # decides what gets deployed, exactly as on an online install -- a full
    # package deliberately carries images for modules this box has turned OFF,
    # so one can be enabled later and installed with no route to a registry.
    # Said out loud because "20 images loaded, 6 modules running" otherwise
    # reads as something having gone wrong.
    # Every downstream pull helper keys off this: the per-image one and
    # pull_compose_with_retry. Set only after images actually loaded, so a
    # failed load never silently disables the fallback to registries.
    INTACT_FROM_PACKAGE=1
    export INTACT_FROM_PACKAGE

    log_info "  Images are now local; config.yaml's enabled flags still decide"
    log_info "  which modules are deployed. Disabled modules keep their images"
    log_info "  on disk so they can be enabled later without internet access."
    return 0
}

# Fetch the release package this checkout corresponds to, so an ONLINE install
# runs the same code as an air-gapped one.
#
# THE POINT IS NOT THE DOWNLOAD, IT IS THE SHARED PATH. Installing from a
# package means install and upgrade converge on one implementation: the same
# images, loaded the same way, deployed by the same compose files. Two
# implementations of "get this box running" are what let the installer and the
# upgrade engine drift -- secrets generated in both bash and Python, chmod
# policies that disagree, an ELK script one of them shipped and the other did
# not. One path is one thing to test.
#
# Falls back to per-image registry pulls if the asset cannot be had. That is the
# old behaviour, still correct, so a release without a published package (or a
# GitHub outage) degrades to a slower install rather than no install.
download_release_assets() {
    # Fetch every asset this release needs into $2 and leave their paths in
    # INTACT_PACKAGES.
    #
    # An INSTALL takes the COMPLETE module set. There is no baseline on a box
    # with nothing installed, so "only what changed" has no meaning here.
    #
    # Two shapes, both supported permanently:
    #   index present -> per-module assets (the current CI)
    #   no index      -> the single bundle (older releases, and the one-file
    #                    air-gap path)
    local tag="$1" dest_dir="$2"
    local repo="${INTACT_REPO:-TenrootOrg/IntactAI}"
    local api="https://api.github.com/repos/${repo}/releases/tags/${tag}"
    local hdr=(-H "Accept: application/vnd.github+json")
    [[ -n "${GITHUB_TOKEN:-}" ]] && hdr+=(-H "Authorization: token ${GITHUB_TOKEN}")

    log_info "Looking for release assets for ${tag}..."
    local json
    json="$(curl -sSL --max-time 60 "${hdr[@]}" "$api" 2>/dev/null)" || true
    [[ -n "$json" ]] || { log_error "  Could not reach the GitHub releases API"; return 1; }

    # The index, if this release has one. It is the ONLY place per-module
    # checksums live -- CI stopped publishing a `.sha256` file beside every
    # asset, because the release page then carried three files per module and
    # two of them were digests nothing read. Fetch it before anything else so
    # the payload can be verified against it below.
    #
    # Two spellings accepted: `<tag>.index.json`, and the older
    # `intact-release-<tag>.index.json` that doubled the prefix on a tag
    # already beginning with `intact-`.
    local index_json="" index_name=""
    local candidate
    for candidate in "${tag}.index.json" "intact-release-${tag}.index.json"; do
        if printf '%s' "$json" | grep -q "\"${candidate}\""; then
            index_name="$candidate"
            break
        fi
    done
    if [[ -n "$index_name" ]]; then
        log_info "  Reading the release index (${index_name})..."
        index_json="$(curl -fsSL --max-time 120 \
            "https://github.com/${repo}/releases/download/${tag}/${index_name}" \
            2>/dev/null)" || index_json=""
        [[ -n "$index_json" ]] || log_warn "  Could not read the release index — falling back to name matching"
    fi

    # What to fetch, and what it must hash to once whole. One
    # "<file-to-download><TAB><whole-asset><TAB><sha256-or-empty>" per line --
    # three columns because a split asset is downloaded as .part-NN pieces but
    # verified as the reassembled tarball.
    local names
    names="$(printf '%s' "$json" | INDEX_TAG="$tag" INDEX_JSON="$index_json" python3 -c '
import json, os, sys
tag = os.environ["INDEX_TAG"]
try:
    rel = json.load(sys.stdin)
except Exception:
    sys.exit(0)
names = [a.get("name", "") for a in (rel.get("assets") or [])]

# GitHub publishes a per-asset digest for every asset it hosts, including
# each individual split part -- captured here so every part can be verified
# right after its own download, before reassembly ever touches it. A -C -
# resumed download that continues past an earlier truncated or corrupted
# leftover ends up the right SIZE (curl only checks byte count) but the
# wrong CONTENT, which only a digest catches.
own_digest = {}
for a in (rel.get("assets") or []):
    d = (a.get("digest") or "")
    own_digest[a.get("name") or ""] = d.split(":", 1)[1] if d.startswith("sha256:") else ""

# Per-module assets, straight from the index: it names the modules a release
# carries and the sha256 of each WHOLE tarball (taken pre-split, so it is also
# the only digest that covers a reassembled multi-part asset -- GitHub can only
# digest each .part-NN it received).
want = []
try:
    index = json.loads(os.environ.get("INDEX_JSON") or "")
except Exception:
    index = None
if index:
    attached, missing = set(names), []
    for entry in (index.get("assets") or {}).values():
        whole, sha = entry["asset"], entry.get("sha256") or ""
        parts = [p for p in (entry.get("parts") or []) if p in attached]
        if whole in attached:
            want.append((whole, whole, sha))
        elif parts:
            want.extend((p, whole, sha) for p in parts)
        else:
            missing.append(whole)
    if missing:
        # Marker on STDOUT -- stderr is discarded by the caller, so a bare
        # sys.exit(msg) here would read to the shell as "no assets found".
        print("__MISSING__" + ", ".join(sorted(missing)))
        sys.exit(0)

# No index: an older release, carrying the single bundle. GitHub publishes a
# per-asset digest of its own ("sha256:...") -- exact for an unsplit file, and
# all that shape ever is.
#
# TEMPORARY -- this branch exists only to bridge boxes on releases older than
# intact-20260807 (which predate the per-module index.json wrapper) through
# that one release. Remove it, and the CI trigger swap that made
# intact-20260807 publish in this single-bundle shape in the first place,
# once the fleet is past this transition -- planned for the patch after
# intact-20260807. See the legacy image-attribution handling in
# load_images_from_package() below for the other half of this bridge.
if not want:
    base = f"intact-upgrade-{tag}.tar.gz"
    for a in (rel.get("assets") or []):
        n = a.get("name") or ""
        if n == base:
            d = (a.get("digest") or "")
            want.append((n, n, d.split(":", 1)[1] if d.startswith("sha256:") else ""))
        elif n.startswith(base + ".part-"):
            # A reassembled bundle has no published digest of the whole on a
            # release this old; the parts are fetched and joined unverified
            # at the WHOLE-file level -- but each part is verified on its own
            # via own_digest above.
            want.append((n, base, ""))

for n, whole, sha in sorted(set(want)):
    own = own_digest.get(n) or ""
    print(f"{n}|{whole}|{sha}|{own}")
' 2>/dev/null)" || true

    # An asset the index names but the release does not carry is fatal, not a
    # thing to install around: the install would come up missing a module while
    # reporting success.
    if [[ "$names" == __MISSING__* ]]; then
        log_error "  Release ${tag} indexes ${names#__MISSING__} but does not publish it"
        return 1
    fi
    if [[ -z "$names" ]]; then
        log_error "  Release ${tag} publishes no installable assets"
        return 1
    fi

    mkdir -p "$dest_dir"
    local n whole sha own
    # sha_of[<whole asset>] = expected sha256 of the WHOLE reassembled file,
    # from the index -- verified after reassembly, further below.
    #
    # Field separator is "|", not a tab: "sha" is a middle column here and is
    # routinely empty for a legacy release, so a tab-joined line reads
    # "name<TAB><TAB>whole..." -- bash's `read` squeezes RUNS of tab into one
    # delimiter no matter what IFS is set to, which shifts every later column
    # left by one. "|" is never whitespace, so it does not.
    declare -A sha_of=()
    local _dl_list; _dl_list="$(mktemp -p "${SCRIPT_DIR}/data/tmp" dl-list-XXXXXX)"
    local _count=0
    while IFS='|' read -r n whole sha own; do
        [[ -n "$n" ]] || continue
        sha_of["$whole"]="$sha"
        # name|own-digest per line: _intact_fetch_asset runs in its own bash
        # process via xargs, so an associative array here would not survive
        # into it -- passing the digest alongside the name in the same line
        # does.
        printf '%s|%s\n' "$n" "$own" >> "$_dl_list"
        _count=$((_count + 1))
    done <<< "$names"

    # FOUR AT A TIME. This fetched one asset at a time while both other paths
    # that download the same assets already parallelise -- prepare_package.sh
    # with `xargs -P 4`, the backend's download.py with _ASSET_WORKERS = 4 --
    # so a first install was the slowest way to get the bytes. Measured on
    # intact-20260805: 5.85 GB serially in ~12 min, on a link that reached
    # 12 MB/s per stream.
    #
    # 4, matching the other two, because release assets come from one host and
    # more streams mostly steal bandwidth from each other.
    log_info "  Downloading ${_count} asset(s), 4 at a time..."

    # Multi-GB assets over a slow/throttled link can sit in this xargs fan-out
    # for 15+ minutes with ZERO output -- curl runs -fsSL (silent) and the only
    # progress signal that existed here was a printf that never reached
    # $LOG_FILE, so a healthy download and a hung one looked identical in the
    # log. This heartbeat + marker-file mechanism gives a live "N/M done"
    # count every 30s. Not `run_with_heartbeat` (lib/common.sh): that helper
    # takes one static description string and wraps a single foreground
    # command with a hard timeout -- fine for "still extracting X", but it
    # can't show a live count across N parallel workers, and download time
    # scales with link speed in a way a single fixed timeout can't bound
    # sanely. This loop is disposable scaffolding around the same xargs call
    # below, not a replacement for that helper.
    local _dl_status_dir
    _dl_status_dir="$(mktemp -d -p "${SCRIPT_DIR}/data/tmp" dl-status-XXXXXX)"
    local _dl_start=$SECONDS
    local _dl_heartbeat_pid=""
    (
        while sleep 30; do
            local _dl_done_n
            _dl_done_n=$(find "$_dl_status_dir" -maxdepth 1 -name '*.done' 2>/dev/null | wc -l)
            log_info "  ... downloading: ${_dl_done_n}/${_count} asset(s) done ($(( SECONDS - _dl_start ))s elapsed)"
        done
    ) &
    _dl_heartbeat_pid=$!
    # shellcheck disable=SC2064
    trap "kill ${_dl_heartbeat_pid} 2>/dev/null; rm -rf '${_dl_status_dir}'; trap - RETURN INT TERM" RETURN INT TERM

    _intact_fetch_asset() {
        # $1 is "name|own-digest" (own-digest may be empty) -- see the
        # _dl_list comment above for why it travels this way rather than
        # through an associative array.
        local line="$1" name digest dest got
        name="${line%%|*}"
        digest="${line#*|}"
        dest="${_DL_DEST}/${name}"
        # --retry-all-errors: plain --retry only retries a curated list of
        # conditions (timeouts, 5xx, a few others) -- an HTTP/2 stream error
        # (curl exit 92, "stream N was not closed cleanly: PROTOCOL_ERROR"),
        # seen for real against GitHub's release CDN under 4-way concurrency,
        # is NOT on that list, so it failed the whole install on one bad
        # stream instead of retrying. -C -: resume, so a retry on a
        # multi-hundred-MB asset continues instead of restarting at byte 0 --
        # the same fix prepare_package.sh's downloader already carries.
        #
        # Resume has its own failure mode though, also seen for real: a run
        # that dies mid-write (like the HTTP/2 error above) can leave a
        # partial file that is not cleanly truncated, and a LATER run's -C -
        # then builds on top of it -- ending up the right SIZE but the wrong
        # CONTENT, since curl's resume trusts the existing bytes rather than
        # re-checking them. The digest check right below is what actually
        # catches that; without it this would silently ship a corrupt
        # package that only fails much later, at tar extraction.
        if curl -fsSL -C - --retry 3 --retry-all-errors --retry-delay 5 --max-time 3600 \
                -o "$dest" \
                "https://github.com/${_DL_REPO}/releases/download/${_DL_TAG}/${name}" \
                2>>"${_DL_LOG}"; then
            if [[ -n "$digest" ]]; then
                got="$(sha256sum "$dest" 2>/dev/null | awk '{print $1}')"
                if [[ "$got" != "$digest" ]]; then
                    rm -f "$dest"
                    printf '[install]   CORRUPT   %s (checksum mismatch, deleted -- a retry fetches it fresh)\n' "$name" >&2
                    return 1
                fi
            fi
            printf '[install]   done      %s\n' "$name"
            touch "${_DL_STATUS_DIR}/${name//\//_}.done" 2>/dev/null || true
        else
            printf '[install]   FAILED    %s\n' "$name" >&2
            return 1
        fi
    }
    export -f _intact_fetch_asset
    export _DL_DEST="$dest_dir" _DL_REPO="$repo" _DL_TAG="$tag" _DL_LOG="$LOG_FILE" \
           _DL_STATUS_DIR="$_dl_status_dir"

    # xargs exits 123 if ANY invocation failed, so one bad asset still fails
    # the install -- "a package that cannot be fetched is a FAILED INSTALL".
    # Piped through tee (matching every other long-running step in this
    # codebase, e.g. lib/docker.sh) so the per-asset done/FAILED/CORRUPT
    # lines land in $LOG_FILE too, not just the terminal; PIPESTATUS[0]
    # recovers xargs's own exit code since pipefail alone doesn't hand it
    # back cleanly through a `tee` consumer that always exits 0.
    xargs -P 4 -I{} -a "$_dl_list" bash -c '_intact_fetch_asset "$@"' _ {} 2>&1 | tee -a "$LOG_FILE"
    local _dl_rc=${PIPESTATUS[0]}
    kill "$_dl_heartbeat_pid" 2>/dev/null
    wait "$_dl_heartbeat_pid" 2>/dev/null
    rm -rf "$_dl_status_dir"
    trap - RETURN INT TERM
    if [[ $_dl_rc -ne 0 ]]; then
        log_error "  One or more asset downloads failed — see $LOG_FILE"
        rm -f "$_dl_list"
        unset -f _intact_fetch_asset
        return 1
    fi
    rm -f "$_dl_list"
    unset -f _intact_fetch_asset
    unset _DL_DEST _DL_REPO _DL_TAG _DL_LOG _DL_STATUS_DIR

    # Reassemble any split assets. CI splits anything over the 2 GiB asset cap;
    # the index's sha256 is of the WHOLE tarball, taken pre-split, so it is the
    # join that gets verified below, not the pieces.
    local part0
    while IFS= read -r part0; do
        [[ -n "$part0" ]] || continue
        local joined="${part0%.part-00}"
        log_info "  Reassembling $(basename "$joined")..."
        cat "${joined}".part-* > "$joined" && rm -f "${joined}".part-*
    done < <(find "$dest_dir" -maxdepth 1 \
                  \( -name '*.tar.gz.part-00' -o -name '*.tar.part-00' \) | sort)

    # Verify everything BEFORE anything is applied.
    INTACT_PACKAGES=()
    local f verified=0 unverified=0
    while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        local want="${sha_of[$(basename "$f")]:-}"
        if [[ -n "$want" ]]; then
            local got
            got="$(sha256sum "$f" | awk '{print $1}')"
            if [[ "$want" != "$got" ]]; then
                log_error "  $(basename "$f") FAILED its checksum (expected ${want:0:16}…, got ${got:0:16}…)"
                return 1
            fi
            verified=$((verified + 1))
        else
            unverified=$((unverified + 1))
        fi
        INTACT_PACKAGES+=("$f")
    done < <(find "$dest_dir" -maxdepth 1 \
                  \( -name '*.tar.gz' -o -name '*.tar' \) | sort)

    if (( ${#INTACT_PACKAGES[@]} == 0 )); then
        log_error "  Nothing downloaded"
        return 1
    fi
    log_success "  ${#INTACT_PACKAGES[@]} asset(s) ready (${verified} checksum-verified)"
    if (( unverified > 0 )); then
        log_warn "  ${unverified} asset(s) had no checksum in the release index — integrity unverified"
    fi
    return 0
}

main() {
    echo ""
    echo "=============================================="
    echo "       Intact.AI Platform Installer"
    echo "=============================================="
    echo ""
    echo "Log file: $LOG_FILE"
    echo ""

    log_info "Starting Intact.AI installation..."

    # -------------------------------------------------------------------------
    # Prerequisites
    # -------------------------------------------------------------------------
    check_root
    check_initialization_marker
    check_ubuntu
    check_config

    # Resolved as early as possible, before either load_images_from_package()
    # call site below (both run BEFORE the "Core Dependencies" section further
    # down installs/verifies docker for a genuinely fresh box) -- covers the
    # far more common case of docker already being present. That function
    # invokes docker again inside a nested `bash -c` (via run_with_heartbeat /
    # `timeout --foreground`); that child normally inherits the same PATH, but
    # on at least one real box (docker installed via snap, PATH set up only
    # for interactive shells, sudo's secure_path not including it, ...) the
    # nested shell's fresh PATH search failed to find it: every image load
    # exited 127 "docker: command not found" even though `docker` worked fine
    # everywhere else in this same script run. Passing the resolved absolute
    # path through removes the dependency on that lookup succeeding a second
    # time in a different shell. Empty here just means "not installed yet" --
    # the later re-resolution (after install_docker) covers that box.
    DOCKER_BIN="$(command -v docker 2>/dev/null || echo docker)"

    # Point this clone's git at scripts/git-hooks so the pre-commit secret
    # guard actually runs. core.hooksPath lives in .git/config, which is
    # per-clone and untracked — so the guard shipped in the repo was off by
    # default on every fresh clone. Best-effort: a tarball install has no .git
    # and the script exits cleanly, and a hook-install failure must never stop
    # a platform install.
    if [[ -f "${SCRIPT_DIR}/scripts/install-git-hooks.sh" ]]; then
        bash "${SCRIPT_DIR}/scripts/install-git-hooks.sh" >/dev/null 2>&1 \
            && log_info "Git pre-commit secret guard: installed" \
            || true
    fi
    # Authenticate this install's GitHub API calls (module-update polling,
    # quota pre-flights, release lookups) when the operator set
    # options.github_token in config.yaml — raises the shared anonymous
    # 60 req/hr per-IP cap to 5,000 req/hr. Read-only-public token; see the
    # comment on github_token in config.yaml. Env var (if already exported)
    # wins so CI can override.
    if [[ -z "${GITHUB_TOKEN:-}" ]]; then
        _cfg_gh_token=$(read_config "['options']['github_token']")
        if [[ -n "$_cfg_gh_token" && "$_cfg_gh_token" != "None" ]]; then
            export GITHUB_TOKEN="$_cfg_gh_token"
            log_info "GitHub API: authenticated via options.github_token (5,000 req/hr)"
        fi
    fi
    print_installation_config_summary
    if [[ "$INTACT_AIRGAP" == "1" ]]; then
        # No connectivity check: there is deliberately no route out. The
        # package replaces every registry fetch, so reachability is irrelevant
        # and the existing gate would abort a perfectly valid install.
        log_info "Air-gapped mode — skipping the internet connectivity check"
        if ! load_images_from_package "${INTACT_PACKAGES[@]}"; then
            log_error "Could not load the release assets - aborting installation"
            exit 1
        fi
        # Copies we made while unwrapping a single-file package; the images are
        # in the docker store now. The operator's own file is left alone.
        if (( ${#INTACT_UNWRAP_DIRS[@]} > 0 )); then
            rm -rf "${INTACT_UNWRAP_DIRS[@]}" 2>/dev/null || true
        fi
    elif ! check_network_connectivity; then
        log_error "Network connectivity check failed - aborting installation"
        exit 1
    else
        # ONLINE — and STILL installing from the release package. This is the
        # only way a box gets its images now; there is deliberately no
        # per-image registry fallback.
        #
        # The point is not the download, it is that install and upgrade run ONE
        # implementation: the same asset, the same loader, the same compose
        # files. Two ways to "get this box running" is precisely what let the
        # installer and the upgrade engine drift -- secrets generated in both
        # bash and Python, chmod policies that disagree, an ELK script one of
        # them shipped and the other did not. A fallback would quietly restore
        # that second path and with it the second test matrix, which is the
        # entire cost this change exists to remove.
        #
        # So a package that cannot be fetched or loaded is a FAILED INSTALL,
        # stated plainly, rather than a silent downgrade to a different code
        # path that nobody tested this release.
        local _rel_tag; _rel_tag="$(cat "${SCRIPT_DIR}/VERSION" 2>/dev/null || true)"
        if [[ -z "$_rel_tag" ]]; then
            log_error "=============================================="
            log_error "No VERSION file in ${SCRIPT_DIR}, so there is no way to tell"
            log_error "which release package to install."
            log_error ""
            log_error "Use a release checkout, or install offline with:"
            log_error "    sudo bash install.sh --package <release-assets-dir>/"
            log_error "=============================================="
            exit 1
        fi
        if ! download_release_assets "$_rel_tag" "${SCRIPT_DIR}/data/tmp/install-pkg"; then
            log_error "=============================================="
            log_error "Could not obtain the release assets for ${_rel_tag}."
            log_error ""
            log_error "Images come only from those assets now, so the install"
            log_error "cannot continue. Either fix connectivity to GitHub, or"
            log_error "fetch them on another machine and run:"
            log_error "    sudo bash install.sh --package <release-assets-dir>/"
            log_error "=============================================="
            exit 1
        fi
        if ! load_images_from_package "${INTACT_PACKAGES[@]}"; then
            log_error "The release assets could not be loaded - aborting installation"
            exit 1
        fi
        # Reclaim the downloads; their contents are in the docker store now.
        rm -f "${INTACT_PACKAGES[@]}" 2>/dev/null || true
    fi

    # -------------------------------------------------------------------------
    # Core Dependencies
    # -------------------------------------------------------------------------
    # Air-gap: apt and the docker repo are both internet-only, so these have to
    # be satisfied ALREADY. Check rather than attempt -- a failed `apt-get
    # update` on a box with no route produces a confusing wall of DNS errors,
    # where "docker is not installed and I cannot install it here" is the
    # actual problem and is worth saying in one line.
    if [[ "$INTACT_AIRGAP" == "1" ]]; then
        local _missing=()
        command -v docker >/dev/null 2>&1 || _missing+=("docker")
        docker compose version >/dev/null 2>&1 || _missing+=("docker-compose-plugin")
        command -v python3 >/dev/null 2>&1 || _missing+=("python3")
        python3 -c 'import yaml' >/dev/null 2>&1 || _missing+=("python3-yaml")
        command -v openssl >/dev/null 2>&1 || _missing+=("openssl")
        if (( ${#_missing[@]} > 0 )); then
            log_error "=============================================="
            log_error "Air-gapped install needs these already present: ${_missing[*]}"
            log_error ""
            log_error "They come from apt and the Docker repository, which this"
            log_error "install cannot reach by design. Install them on this host"
            log_error "first (or use an image that ships them), then re-run with"
            log_error "--package."
            log_error "=============================================="
            exit 1
        fi
        log_success "Host prerequisites present (docker, compose, python3, yaml, openssl)"
    else
        install_dependencies
        prefer_ipv4_dns
    fi
    if [[ "$INTACT_AIRGAP" != "1" ]] && ! install_docker; then
        log_error "=============================================="
        log_error "Docker installation failed — aborting install."
        log_error ""
        log_error "Fix the underlying issue (DNS, firewall, apt, etc.),"
        log_error "then re-run this script. Nothing below this point will"
        log_error "work without a functional docker daemon."
        log_error "=============================================="
        exit 1
    fi
    # Defensive: install_docker can log success for an unhealthy daemon if
    # something exotic happens mid-install. Gate the rest of the flow on a
    # real `docker version` call so we don't cascade through 'command not
    # found' errors for every module if Docker isn't actually usable.
    if ! command -v docker &>/dev/null || ! docker version &>/dev/null; then
        log_error "Docker reports installed but 'docker version' fails — aborting"
        exit 1
    fi
    # Re-resolve now that install_docker has had a chance to put it there for
    # a genuinely fresh box (the early resolution above can only have found a
    # pre-existing install). See that comment for why this exists at all.
    DOCKER_BIN="$(command -v docker 2>/dev/null || echo docker)"
    # Advisory: warn (never block) if the daemon is below the supported floor.
    # Matters mainly when Docker was pre-installed (a fresh install pulls the
    # current release from download.docker.com, which is always new enough).
    check_docker_min_version
    configure_docker_resolver
    create_network

    # -------------------------------------------------------------------------
    # Timeline Processing (Plaso/Timesketch) - Air-gap Support
    # -------------------------------------------------------------------------
    local timesketch_enabled
    timesketch_enabled=$(read_config "['modules']['timesketch']['enabled']")
    if is_enabled "$timesketch_enabled"; then
        pull_plaso_image
        pull_python_alpine_image
        download_timesketch_packages
    else
        log_info "Timeline Processing pre-downloads: SKIPPED (TimeSketch disabled)"
    fi

    # -------------------------------------------------------------------------
    # Forensic Collection (Velociraptor/Offline Collector) - Air-gap Support
    # -------------------------------------------------------------------------
    local velociraptor_enabled
    velociraptor_enabled=$(read_config "['modules']['velociraptor']['enabled']")
    if is_enabled "$velociraptor_enabled"; then
        download_offline_collector_binaries
        download_legacy_velociraptor_binaries
        create_velociraptor_collector
        pull_velociraptor_base_image
    else
        log_info "Velociraptor/offline-collector pre-downloads: SKIPPED (Velociraptor disabled)"
    fi

    # -------------------------------------------------------------------------
    # IRIS — pre-pull all runtime images so compose up doesn't depend on the
    # registry being reachable mid-deploy.
    # -------------------------------------------------------------------------
    local iris_enabled
    iris_enabled=$(read_config "['modules']['iris']['enabled']")
    if is_enabled "$iris_enabled"; then
        pull_iris_images
    else
        log_info "IRIS image pre-pull: SKIPPED (IRIS disabled)"
    fi

    # -------------------------------------------------------------------------
    # Azure Security Tools (SIGMA Rules + DFIR-O365RC)
    # -------------------------------------------------------------------------
    download_sigma_rules
    # STRICTLY AFTER download_sigma_rules: that function rm -rf's
    # /opt/sigma-rules before cloning, so the bundled pack has to be laid down
    # afterwards or it is silently wiped. See install_bundled_rule_packs().
    install_bundled_rule_packs
    pull_dfir_o365rc_image
    generate_azure_certificate

    # -------------------------------------------------------------------------
    # AWS DFIR (CloudTrail + SIGMA) — native, no image to pull. boto3 is
    # installed into the backend by install_deps.py. The SIGMA AWS rule pack
    # comes from one of two places: the release package (applied by
    # install_bundled_rule_packs above — the only route that works offline), or
    # the SigmaHQ clone download_sigma_rules() makes when the aws_sigma or
    # o365rc module is enabled. When both happen the bundled pack is applied
    # last, so the release-pinned rules win over whatever the clone carried.

    # -------------------------------------------------------------------------
    # Backend base image — always built, so always pre-pull. Keeps the
    # ~46 MB python:3.11-slim out of the build's wall-clock budget on
    # slow-uplink VMs.
    # -------------------------------------------------------------------------
    pull_backend_base_image

    # -------------------------------------------------------------------------
    # Configuration
    # -------------------------------------------------------------------------
    update_env_files
    create_data_directory

    # -------------------------------------------------------------------------
    # Services
    # -------------------------------------------------------------------------
    start_services

    # -------------------------------------------------------------------------
    # Verification & Reports
    # -------------------------------------------------------------------------
    # Refresh per-module nginx DNS caches BEFORE the health probes — fixes
    # the stale-upstream race where nginx cached an upstream container's
    # IP at startup and never noticed the upstream was recreated. Caught
    # us with TimeSketch on a fresh install (intact_timesketch_nginx
    # was returning 502 for a perfectly-healthy backend). Restart is
    # idempotent so this is also a no-op on already-healthy nginxes.
    refresh_nginx_upstreams

    verify_installation
    # Runs after verify_installation so the backend is known to be up and can be
    # asked whether a credential exists, and before the report so a repair shows
    # up in the final ATTENTION block instead of scrolling past.
    ensure_dashboard_login_is_reachable
    print_installation_report
    create_initialization_marker

    # -------------------------------------------------------------------------
    # Fix Permissions (for development/upgrades)
    # -------------------------------------------------------------------------
    fix_source_permissions

    print_summary
    # Neutral "this is expected" notes recorded during the install. Kept
    # separate from — and printed before — the ATTENTION block so that
    # deliberate behaviour is never mistaken for something that went wrong.
    print_install_notes
    # Final ATTENTION block listing every warning/error tracked anywhere
    # during the install. Operators currently miss yellow [WARN] lines
    # that scrolled past — this surfaces them right after the success
    # banner so they can't be missed. Pure formatter, no side effects.
    print_final_issues_report
}

# ============================================================================
# Fix Source File Permissions
# ============================================================================
# After upgrades, source files may be owned by root. Fix them so they remain
# editable for development and future upgrades.

fix_source_permissions() {
    log_info "Fixing source file permissions..."
    local uid=$(stat -c '%u' "${SCRIPT_DIR}")
    local gid=$(stat -c '%g' "${SCRIPT_DIR}")

    # Fix ownership for entire project
    chown -R "${uid}:${gid}" "${SCRIPT_DIR}" 2>/dev/null || true

    # Fix directory permissions (755 = rwxr-xr-x)
    find "${SCRIPT_DIR}" -type d -exec chmod 755 {} \; 2>/dev/null || true

    # Fix file permissions (644 = rw-r--r--), but leave secret material that
    # earlier steps in this same run deliberately hardened to a tighter mode
    # untouched: module secrets/ dirs (Portainer admin password, IRIS
    # IRIS_SECRET_KEY/POSTGRES_*_PASSWORD, ...), module .env files (DB/
    # session secrets, GitHub token), the shared Nginx/Kibana TLS private
    # key, the IRIS web TLS private key (a copy of that same shared key),
    # the IRIS Root CA private key, and the Azure cert bundle. Without
    # these exclusions this blanket sweep silently reverted all of that
    # hardening to world-readable 644 on every install/upgrade.
    #
    # The downloads/ exclusion is a different kind: those are the Velociraptor
    # client BINARIES, and 644 strips their execute bit. The backend runs one
    # of them to decrypt password-protected offline collections, so this sweep
    # broke that import on every installed host — and because lib/docker.sh only
    # chmods +x on a fresh download, re-running the installer never repaired it.
    find "${SCRIPT_DIR}" -type f \
        -not -path "*/modules/*/secrets/*" \
        -not -path "*/modules/*/.env" \
        -not -path "*/modules/nginx/ssl/*.key" \
        -not -path "*/modules/iris/config/certificates/rootCA/irisRootCAKey.pem" \
        -not -path "*/modules/iris/config/certificates/web_certificates/iris_dev_key.pem" \
        -not -path "*/modules/nginx/html/downloads/*" \
        -not -path "*/data/azure_cert.pfx" \
        -not -path "*/data/azure_cert.pfx.pass" \
        -not -path "${SCRIPT_DIR}/config.yaml" \
        -exec chmod 644 {} \; 2>/dev/null || true

    # Re-assert the restrictive modes (and, for the IRIS web key, the
    # root:33 ownership the iris-nginx container's www-data gid needs) on
    # those same secret files in case any of them predate this run and
    # weren't already at the intended mode (e.g. left over from an older
    # install), or had their ownership reset by the chown -R above.
    #
    # IRIS's own 5 app/postgres secrets are EXCLUDED here on purpose --
    # see the dedicated 644 pass a few lines down for why. Every other
    # module's secrets/ and every .env still get the blanket 600.
    find "${SCRIPT_DIR}/modules" -type f \( -path "*/secrets/*" -o -name ".env" \) \
        -not -path "*/modules/iris/secrets/IRIS_ADM_PASSWORD" \
        -not -path "*/modules/iris/secrets/IRIS_SECRET_KEY" \
        -not -path "*/modules/iris/secrets/IRIS_SECURITY_PASSWORD_SALT" \
        -not -path "*/modules/iris/secrets/POSTGRES_ADMIN_PASSWORD" \
        -not -path "*/modules/iris/secrets/POSTGRES_PASSWORD" \
        -exec chmod 600 {} \; 2>/dev/null || true
    # These 5 stay 644 (world-readable), matching
    # services/upgrade/iris.py:399-423's documented policy exactly --
    # iris_app and iris_worker run their gunicorn/celery processes as
    # `nobody` (uid 65534), and these secrets are bind-mounted into
    # /run/secrets/ owned by whatever this chown -R above just set
    # (this script's own uid, e.g. 1000). A 600 file owned by a UID that
    # isn't 65534 is unreadable to `nobody`; IRIS then reads an empty
    # password, connects with "", and its gunicorn workers crash-loop on
    # "password authentication failed for user postgres" the next time
    # intact_iris_app is recreated for ANY reason (upgrade, `docker
    # compose restart`, host reboot) -- NOT at first boot, which is why
    # this went unnoticed: generate_iris_secrets() (lib/modules.sh)
    # creates these files at the default umask (644), so the FIRST
    # deploy_iris works fine, and only breaks on the next recreate after
    # THIS blanket 600 sweep has already reverted them. Confirmed live on
    # 2026-08-05: an online upgrade recreated intact_iris_app and it
    # crash-looped with exactly this error; restoring 644 fixed it
    # immediately, no data or credentials touched.
    find "${SCRIPT_DIR}/modules/iris/secrets" -maxdepth 1 -type f \
        \( -name IRIS_ADM_PASSWORD -o -name IRIS_SECRET_KEY \
           -o -name IRIS_SECURITY_PASSWORD_SALT \
           -o -name POSTGRES_ADMIN_PASSWORD -o -name POSTGRES_PASSWORD \) \
        -exec chmod 644 {} \; 2>/dev/null || true
    # config.yaml is as sensitive as anything under secrets/: it carries
    # options.github_token (a real GitHub PAT), the dashboard login and every
    # module password. It was landing at 664/644 — readable by every local
    # account on the box — because the sweep above treats it as ordinary source.
    # config.yaml is tracked but sanitized on commit, so git only ever holds
    # shipping defaults; the live file here still needs 600.
    [[ -f "${SCRIPT_DIR}/config.yaml" ]] && chmod 600 "${SCRIPT_DIR}/config.yaml" 2>/dev/null || true
    [[ -f "${SCRIPT_DIR}/modules/nginx/ssl/nginx-cert.key" ]] && chmod 640 "${SCRIPT_DIR}/modules/nginx/ssl/nginx-cert.key" 2>/dev/null || true
    # No htpasswd override needed any more. nginx used to evaluate auth_basic in
    # its worker process (uid/gid 101), so the file had to be root:101/640 rather
    # than the blanket "secrets/* -> 600" this sweep applies. That gate is gone —
    # the dashboard login is an application-level session now (see
    # modules/backend/services/auth_service.py). Any leftover htpasswd from a
    # pre-upgrade install is simply an unused file and the 600 sweep above is the
    # correct treatment for it.
    [[ -f "${SCRIPT_DIR}/modules/iris/config/certificates/rootCA/irisRootCAKey.pem" ]] && chmod 600 "${SCRIPT_DIR}/modules/iris/config/certificates/rootCA/irisRootCAKey.pem" 2>/dev/null || true
    if [[ -f "${SCRIPT_DIR}/modules/iris/config/certificates/web_certificates/iris_dev_key.pem" ]]; then
        chown root:33 "${SCRIPT_DIR}/modules/iris/config/certificates/web_certificates/iris_dev_key.pem" 2>/dev/null || true
        chmod 640 "${SCRIPT_DIR}/modules/iris/config/certificates/web_certificates/iris_dev_key.pem" 2>/dev/null || true
    fi
    [[ -f "${SCRIPT_DIR}/data/azure_cert.pfx" ]] && chmod 600 "${SCRIPT_DIR}/data/azure_cert.pfx" 2>/dev/null || true
    [[ -f "${SCRIPT_DIR}/data/azure_cert.pfx.pass" ]] && chmod 600 "${SCRIPT_DIR}/data/azure_cert.pfx.pass" 2>/dev/null || true

    # ---- secrets created AFTER the exclusion list above was written ---------
    # These are NOT umask drift: the blanket `chmod 644` sweep above has no
    # exclusion for data/velociraptor/, data/intact.db, modules/*/config/ or
    # data/auth/, so it ACTIVELY reset them to world-readable on every install
    # and upgrade. Hand-fixing the modes never survived the next run.
    #
    # Hardened here as a positive pass rather than by adding more exclusions:
    # an exclusion list only protects secrets that existed when it was written,
    # and this file has now been bitten by that twice (the gitleaks pre-commit
    # hook was the other). A corrective pass means a newly added secret ends up
    # restrictive by default.
    #
    # What is at stake:
    #   server.config.yaml  - the Velociraptor CA private key, which signs every
    #                         enrolled endpoint. World-readable = anyone local
    #                         can mint client certs and impersonate the server.
    #   api.config.yaml     - API client private key (arbitrary VQL on all hosts)
    #   intact.db           - the `secrets` table is plaintext and holds
    #                         auth_session_key, which SIGNS the dashboard session
    #                         cookie. Readable = forge a session, bypassing the
    #                         login, the lockout and the audit log entirely.
    #                         -wal/-shm carry the same rows and are recreated by
    #                         SQLite, so they must be hardened alongside it.
    #   timesketch*.conf    - live SECRET_KEY + OPENSEARCH_PASSWORD
    #   auth/audit.jsonl    - login/lockout history
    #
    # Safe at 600: every consuming container runs as root (verified with
    # `docker top`, not Config.User) and root ignores mode bits. Keep this list
    # in sync with _SECRET_PATHS_0600 in
    # modules/backend/services/upgrade/base.py — the in-UI upgrade never runs
    # install.sh, so both paths must harden the same files. A parity test
    # enforces it (tests/test_secret_files_are_not_world_readable.py).
    #
    # IRIS secrets are deliberately NOT here: install.sh and the upgrade path
    # disagree on their mode (600 vs 644) for a documented reason — see
    # services/upgrade/iris.py:399-423. Adding them here would risk the
    # iris_app crashloop.
    # BEGIN shared-secret-hardening  (parity-checked against base.py)
    chmod 600 "${SCRIPT_DIR}/data/velociraptor/server.config.yaml" 2>/dev/null || true
    chmod 600 "${SCRIPT_DIR}/data/velociraptor/api.config.yaml" 2>/dev/null || true
    # The Velociraptor CLI binary must stay EXECUTABLE. Everything that runs
    # VQL via `docker exec intact_velociraptor /velociraptor/velociraptor ...`
    # depends on it -- memory acquisition, flow cancellation -- and when it is
    # not, the failure surfaces as an opaque "VQL query failed (rc=126)".
    # Cheap to assert here so a hardening pass can never quietly clear it.
    [ -f "${SCRIPT_DIR}/data/velociraptor/velociraptor" ] && \
        chmod 755 "${SCRIPT_DIR}/data/velociraptor/velociraptor" 2>/dev/null || true
    chmod 600 "${SCRIPT_DIR}/data/intact.db" 2>/dev/null || true
    chmod 600 "${SCRIPT_DIR}/data/intact.db-wal" 2>/dev/null || true
    chmod 600 "${SCRIPT_DIR}/data/intact.db-shm" 2>/dev/null || true
    chmod 600 "${SCRIPT_DIR}/modules/timesketch/config/timesketch.conf" 2>/dev/null || true
    chmod 600 "${SCRIPT_DIR}/modules/timesketch/config/timesketch_legacy.conf" 2>/dev/null || true
    chmod 600 "${SCRIPT_DIR}/data/auth/audit.jsonl" 2>/dev/null || true
    # END shared-secret-hardening

    # Restore execute permission on scripts
    chmod +x "${SCRIPT_DIR}/install.sh" 2>/dev/null || true
    chmod +x "${SCRIPT_DIR}/lib/"*.sh 2>/dev/null || true
    chmod +x "${SCRIPT_DIR}/scripts/"*.sh 2>/dev/null || true
    # ...and the Python ones beside them. The globs here are per-extension, so
    # `scripts/*.sh` does not cover `scripts/*.py` -- which meant the 644 sweep
    # de-executed the first top-level Python script added to that directory
    # (make_single_package.py) on every install, and the repo showed a
    # permanently dirty mode change nobody could explain. scripts/migrate/*.py
    # below already had this line; the top level was simply missed.
    chmod +x "${SCRIPT_DIR}/scripts/"*.py 2>/dev/null || true
    chmod +x "${SCRIPT_DIR}/modules/iris/scripts/"*.sh 2>/dev/null || true
    chmod +x "${SCRIPT_DIR}/modules/backend/scripts/"*.py 2>/dev/null || true
    # git SILENTLY skips a hook that is not executable — no error, no warning
    # from the hook itself. The 644 sweep above stripped +x from
    # scripts/git-hooks/pre-commit on every single install, which switched the
    # gitleaks secret guard off and left it looking installed. `git commit` says
    # "hook was ignored because it's not set as executable" and that is the only
    # sign. The glob (not *.sh) is deliberate: hooks have no extension.
    chmod +x "${SCRIPT_DIR}/scripts/git-hooks/"* 2>/dev/null || true
    # Subdirectories the `scripts/*.sh` glob above does not reach, plus two
    # module-level helpers the sweep also de-executed.
    chmod +x "${SCRIPT_DIR}/scripts/migrate/"*.sh 2>/dev/null || true
    chmod +x "${SCRIPT_DIR}/scripts/migrate/"*.py 2>/dev/null || true
    chmod +x "${SCRIPT_DIR}/modules/elk/config/"*.sh 2>/dev/null || true
    chmod +x "${SCRIPT_DIR}/modules/nginx/build-tailwind.sh" 2>/dev/null || true

    log_info "Source file permissions fixed"
}

# ============================================================================
# Entry Point
# ============================================================================

# Initialize log file
touch "$LOG_FILE"

# Run main installation
main "$@"

# Exit with appropriate code. Non-zero on either:
#   - any module's deploy step failed (FAILED_MODULES) — same as before, OR
#   - any deployed module didn't pass its end-to-end health probe
#     (UNHEALTHY_MODULES). Previously the script exited 0 in that case,
#     which lied about the actual state of the platform.
#
# When we DO exit non-zero, list which modules tripped the gate so the
# operator doesn't have to re-grep the install log. Previously this was
# a silent `exit 1` which is unfriendly for both humans and CI logs.
if [[ ${#FAILED_MODULES[@]} -gt 0 ]] || [[ ${#UNHEALTHY_MODULES[@]} -gt 0 ]]; then
    log_error "=============================================="
    log_error "Installation finished with critical failures"
    log_error "=============================================="
    if [[ ${#FAILED_MODULES[@]} -gt 0 ]]; then
        log_error "Failed to deploy (${#FAILED_MODULES[@]} module(s)):"
        for m in "${FAILED_MODULES[@]}"; do
            log_error "  - $m"
        done
    fi
    if [[ ${#UNHEALTHY_MODULES[@]} -gt 0 ]]; then
        log_error "Deployed but unhealthy (${#UNHEALTHY_MODULES[@]} module(s)):"
        for m in "${UNHEALTHY_MODULES[@]}"; do
            log_error "  - $m"
        done
    fi
    log_error "Fix the underlying issue and re-run install.sh."
    log_error "Install log: $LOG_FILE"
    exit 1
fi
exit 0
