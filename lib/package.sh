#!/bin/bash
# Intact.AI Platform Installer - Release Package Loading
#
# Everything that turns already-on-disk release assets into loaded Docker
# images: asset->module attribution, the docker-save vs plain-data-tar
# distinction, and the merge/extract/load pipeline itself.
#
# Split out of install.sh unchanged. Fetching those assets from GitHub lives
# in lib/release.sh; deciding WHICH assets to use lives in lib/args.sh.

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

# Stage DFIQ data (dfiq/dfiq-data.tar, bundled inside the timesketch asset --
# see scripts/ci/packager/package.py's DFIQ block) into
# modules/timesketch/config/dfiq. Shared between install.sh's
# load_images_from_package (called with $work, the extracted temp dir) and
# the upgrade path's upgrade_module_timesketch (called with $UPKG_DIR, the
# already-resolved package root) -- these differ in exactly how deep the
# asset's own top-level directory sits, so `find -path` at any depth handles
# both without the caller needing to know which shape it has.
#
# Only stages into an EMPTY destination -- an operator's own populated
# modules/timesketch/config/dfiq/ (a prior live clone, or hand-curated
# content) must never be overwritten by a package's bundled copy. The
# scenarios/ check mirrors deploy_timesketch's own presence check
# (lib/modules/timesketch.sh) exactly, so staging here reliably makes that
# check pass and the live git-clone fallback is never attempted when a
# bundled copy was already applied.
stage_dfiq_from_package() {
    local root="$1"
    local dest="${SCRIPT_DIR}/modules/timesketch/config/dfiq"
    local pack
    pack="$(find "$root" -type f -path '*/dfiq/dfiq-data.tar' 2>/dev/null | head -1)"
    [[ -n "$pack" ]] || return 0
    [[ -z "$(ls "${dest}/scenarios" 2>/dev/null)" ]] || return 0
    mkdir -p "$dest"
    if tar -xf "$pack" -C "$dest" 2>>"${LOG_FILE:-/dev/null}"; then
        log_success "  Staged DFIQ data ($(find "$dest" -name '*.yaml' 2>/dev/null | wc -l) YAML files) into modules/timesketch/config/dfiq"
        return 0
    fi
    log_warn "  Bundled DFIQ tar found but extraction failed — deploy_timesketch will fall back to its own clone"
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
# lib/modules/backend.sh:deploy_backend.
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
    # per-module attribution, so its images are labelled "(legacy bundle)"
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
        # "(unattributed)" used to be the fallback here, which reads as an
        # anomaly to an operator watching the install scroll by. It isn't one
        # -- a legacy single-bundle release (see the comment above IMG_OWNER)
        # has no per-module manifest to attribute images from, by design, and
        # every image is loaded regardless. "(legacy bundle)" says why instead
        # of sounding like something is missing or broken.
        display="$(_module_display "$mod_id" "(legacy bundle)")"
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
            # instead of trusting it (see lib/config.sh + lib/modules/backend.sh).
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
    # same place, and seed_yara_rulesets (lib/modules/volweb.sh) prefers
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

    stage_dfiq_from_package "$work"

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

    # This used to run unconditionally, right before the loaded/failed checks
    # below -- which meant a failed load (docker: command not found, a corrupt
    # tar, anything) wiped this ENTIRE scratch dir on the way out, discarding
    # every already-downloaded-and-extracted image tar the per-image failure
    # branch above deliberately left in place (line ~552-558 never deletes a
    # failed image's tar for exactly this reason). The 5.5GB download + 13GB
    # extraction then had to happen all over again just to retry the load
    # step. Keep $work whenever anything failed, so a fix-and-retry only
    # re-runs the load, not the fetch.
    if (( failed == 0 )); then
        rm -rf "$work"
    else
        log_warn "  ${failed} image(s) failed to load — extracted package left in place for retry: $work"
    fi
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
