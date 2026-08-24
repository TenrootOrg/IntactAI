#!/bin/bash
# Intact.AI upgrade — package acquisition, verification and extraction.
#
# Everything an upgrade package must survive before a single container is
# touched. All of these checks are ported from the Python engine rather than
# reinvented, because each one exists for a reason that was paid for once
# already:
#
#   sha256 of the archive          a truncated download is not a package
#   gzip -t                        catches corruption tar -x reports too late
#   TAR-SLIP defence               a member named ../../etc/cron.d/x writes
#                                  outside the extraction dir, as root
#   per-file sha256 map            the archive can be intact while a file
#                                  inside it was swapped
#   single top-level dir           per-module assets merge by sharing a root;
#                                  no shared root means a half-package
#   delta refusal                  the delta scheme was withdrawn; a delta
#                                  package applied as a full one silently
#                                  leaves modules at the wrong version
#   package_version gate           a format this code does not understand must
#                                  stop, not be guessed at
#
# The one rule worth stating separately, because it is the easiest to get
# wrong when merging per-module assets: NEVER recompute the sha256 map. Merging
# unions the maps and errors when two assets disagree about the same path. A
# recomputed map is a map of whatever arrived, which verifies nothing.

SUPPORTED_PACKAGE_FORMAT=1

UPKG_DIR=""          # the extracted, merged package tree
UPKG_MANIFEST=""     # $UPKG_DIR/manifest.json
UPKG_LOOSE_MANIFEST="" # a manifest.json found beside the assets, not inside one
# "<module>=<asset path>" entries whose extraction is deferred to that module's
# turn. Exported across the stage-0 hop for the same reason UPKG_SCRATCH is --
# the process that runs the module loop is not the one that acquired.
: "${UPKG_DEFERRED:=}"
# What to rm -rf at the end. NOT a plain assignment: the stage-0 hop in
# scripts/upgrade.sh exports this before `exec`-ing into the target release's
# upgrade.sh so the process that actually reaches upkg_cleanup can still
# remove what the ORIGINAL process's upkg_acquire extracted (the re-exec'd
# process skips extraction entirely -- it is handed --package-dir, which is now
# only ever an operator resuming by hand, not a handover). A plain
# `UPKG_SCRATCH=""` here would silently clobber that inherited value the
# instant this file is sourced in the new process.
: "${UPKG_SCRATCH:=}"

# Bytes reclaimed by upkg_release_loaded_tar, reported once at the end of the
# run. Same reasoning as UPKG_SCRATCH for the `:` form -- the freeing happens
# in the re-exec'd process, and a plain assignment would reset it on source.
: "${U_TARS_FREED:=0}"
# Set when any image load fails, so the EXIT path keeps the extraction for a
# retry instead of making the operator re-download several GB.
: "${U_KEEP_SCRATCH:=0}"
# basename -> 1 for every tar already loaded and freed this run. Lets a later
# _u_ensure_image tell "the package never carried this" apart from "we loaded
# it and the image still is not there", which are very different bugs.
declare -gA _U_TAR_FREED 2>/dev/null || true

# ---------------------------------------------------------------------------
# upkg_expand_args <arg...>
#
# Turns whatever --package was pointed at into a concrete asset list in
# UPKG_ASSETS: a directory becomes the tars inside it, a single-file wrapper
# is unwrapped into its members. Deliberately mirrors parse_install_args
# (lib/args.sh:139-232) rather than calling it, because that function also
# owns install-only globals and its own flag loop.
# ---------------------------------------------------------------------------
upkg_expand_args() {
    UPKG_ASSETS=()
    UPKG_LOOSE_MANIFEST=""
    # Not a module asset, but not nothing either: lib/upgrade/hostdeps.sh reads
    # its apt index to report whether the host's Docker matches this release.
    UPKG_SYSTEM_BUNDLE=""
    local p f listing unwrap
    for p in "$@"; do
        # Two release assets are NOT module assets and must never be collected
        # as one:
        #   *-system-bundle.tar  Docker/apt .deb files for install.sh's air-gap
        #                        path. Nothing here knows what to do with it.
        #   *-bootstrap.tar      install.sh + lib/ + scripts/ for bootstrapping
        #                        a box that has no checkout yet.
        #
        # Both sit on the release page beside the module assets, so an operator
        # who downloads a whole release into one folder and points --package at
        # it hands them to this loop. bootstrap was not excluded until
        # 2026-08-11: its tarball has its own top-level directory (the bare tag,
        # not intact-upgrade-<tag>), so extracting it into the merged tree gives
        # that tree a SECOND root and the manifest describes neither of them
        # properly. CI never caught it because dry-run-apply collects only from
        # the per-module build artifacts, and these two upload separately.
        if [[ -d "$p" ]]; then
            # *-engine.tar.gz joined the non-module set with the bootstrap
            # handover: it is stage 1's payload (flat lib/ + scripts/, its own
            # root), already extracted and EXEC'D by bootstrap_upgrade.sh
            # before this code runs. Collecting it as a module asset gives the
            # merged tree extra top-level roots and the "found 3: scripts lib
            # intact-upgrade-<tag>" refusal -- which killed the first real
            # Import of a prepared wrapper.
            while IFS= read -r f; do UPKG_ASSETS+=("$f"); done \
                < <(find "$p" -maxdepth 1 \( -name '*.tar.gz' -o -name '*.tar' \) \
                         ! -name '*-system-bundle.tar' \
                         ! -name '*-bootstrap.tar' \
                         ! -name '*-engine.tar.gz' | sort)
            if [[ -z "$UPKG_SYSTEM_BUNDLE" ]]; then
                UPKG_SYSTEM_BUNDLE="$(find "$p" -maxdepth 1 -name '*-system-bundle.tar' \
                                      2>/dev/null | head -1)"
            fi
            # The merged root manifest.json, if it's sitting beside the module
            # tarballs -- either download_release_assets already renamed it
            # (lib/release.sh), or an operator downloaded
            # <tag>.manifest.json by hand into a --package directory without
            # renaming it. Neither shape is a tar, so the glob above never
            # sees it; upkg_extract places it into the merged tree below.
            if [[ -z "$UPKG_LOOSE_MANIFEST" ]]; then
                UPKG_LOOSE_MANIFEST="$(find "$p" -maxdepth 1 \
                    \( -name 'manifest.json' -o -name '*.manifest.json' \) \
                    2>/dev/null | head -1)"
            fi
        elif [[ -f "$p" ]]; then
            UPKG_ASSETS+=("$p")
        else
            log_error "Package not found: $p"
            return 1
        fi
    done

    (( ${#UPKG_ASSETS[@]} )) || { log_error "No package assets found"; return 1; }

    # Unwrap a single-file wrapper: N assets flat at depth 0, no shared root,
    # no manifest.json of its own. -tf not -tzf; the wrapper is a plain tar
    # now but older ones on USB sticks are .tar.gz and tar auto-detects.
    local expanded=()
    for p in "${UPKG_ASSETS[@]}"; do
        listing=""
        [[ -f "$p" ]] && listing="$(tar -tf "$p" 2>/dev/null)"
        if [[ -n "$listing" ]] \
           && ! grep -q '/' <<< "$listing" \
           && ! grep -qx 'manifest.json' <<< "$listing" \
           && grep -q '\.tar\(\.gz\)\?$' <<< "$listing"; then
            mkdir -p "${SCRIPT_DIR}/data/tmp" 2>/dev/null || true
            unwrap="$(mktemp -d -p "${SCRIPT_DIR}/data/tmp" upgrade-unwrap-XXXXXX 2>/dev/null)" \
                || unwrap="$(mktemp -d)"
            UPKG_SCRATCH="${UPKG_SCRATCH} ${unwrap}"
            log_info "$(basename "$p") is a single-file package — unwrapping"
            # Extract the module tarballs AND the merged <tag>.manifest.json
            # that prepare_package.sh wraps beside them. Extracting only
            # '*.tar[.gz]' -- which is what this did until the manifest was
            # added to the wrapper -- silently dropped the one file
            # upkg_read_manifest needs, so every hand-carried air-gap package
            # died at "per-module manifests but no merged manifest.json" on
            # the target. The index.json is deliberately NOT extracted: it
            # describes the release, and nothing on the apply side reads it.
            grep -E '\.tar(\.gz)?$|\.manifest\.json$' <<< "$listing" \
                | tar -xf "$p" -C "$unwrap" -T - || {
                log_error "Could not unwrap $(basename "$p")"; return 1; }
            while IFS= read -r f; do
                case "$(basename "$f")" in
                    # The engine rides at the wrapper's top level for STAGE 1
                    # (bootstrap_upgrade.sh pulls it out and execs it before
                    # this runs); it is not a module asset and merging it in
                    # hands the tree a second and third root.
                    *-system-bundle.tar|*-bootstrap.tar|*-engine.tar.gz) continue ;;
                esac
                expanded+=("$f")
            done < <(find "$unwrap" -maxdepth 1 \( -name '*.tar.gz' -o -name '*.tar' \) | sort)
            # Same role as the directory branch above: a manifest sitting
            # beside the assets rather than inside one. upkg_extract copies it
            # into the merged tree as manifest.json.
            if [[ -z "$UPKG_LOOSE_MANIFEST" ]]; then
                UPKG_LOOSE_MANIFEST="$(find "$unwrap" -maxdepth 1 \
                    \( -name 'manifest.json' -o -name '*.manifest.json' \) \
                    2>/dev/null | head -1)"
            fi
        else
            expanded+=("$p")
        fi
    done
    UPKG_ASSETS=("${expanded[@]}")
    return 0
}

# ---------------------------------------------------------------------------
# upkg_verify_archive <asset> [expected_sha256]
#
# Pre-extraction integrity. Runs on the bytes as they arrived.
# ---------------------------------------------------------------------------
upkg_verify_archive() {
    local asset="$1" expected="${2:-}"
    local name; name="$(basename "$asset")"

    [[ -f "$asset" ]] || { log_error "Asset not found: $asset"; return 1; }
    [[ -s "$asset" ]] || { log_error "Asset is empty: ${name}"; return 1; }

    if [[ -n "$expected" ]]; then
        local actual; actual="$(sha256_of "$asset")"
        if [[ "$actual" != "$expected" ]]; then
            log_error "Checksum mismatch on ${name}"
            log_error "  expected ${expected}"
            log_error "  got      ${actual}"
            return 1
        fi
        log_info "  sha256 verified: ${name}"
    fi

    # Sniff the magic bytes rather than trusting the filename: assets became
    # plain tar at 20260805 but kept the .tar.gz name in older releases, so a
    # suffix test would run gzip -t on a plain tar and fail a good package.
    local magic; magic="$(head -c2 "$asset" 2>/dev/null | od -An -tx1 | tr -d ' \n')"
    if [[ "$magic" == "1f8b" ]]; then
        if ! gzip -t "$asset" 2>/dev/null; then
            log_error "${name} is a corrupt gzip archive"
            return 1
        fi
        log_info "  gzip integrity ok: ${name}"
    fi
    return 0
}

# ---------------------------------------------------------------------------
# upkg_check_tar_slip <asset>
#
# Refuse any member that would write outside the extraction directory. We
# extract as root, so this is the difference between a bad package and a
# rooted host. Checks BOTH separators and rejects absolute paths, '..'
# components anywhere in the path, and symlink/hardlink targets that escape.
# ---------------------------------------------------------------------------
upkg_check_tar_slip() {
    local asset="$1" bad=0 member
    local name; name="$(basename "$asset")"

    while IFS= read -r member; do
        [[ -z "$member" ]] && continue
        case "$member" in
            /*|\\*|*:\\*)
                log_error "  tar-slip: absolute path member '${member}'"; bad=1 ;;
            ..|../*|*/../*|*/..)
                log_error "  tar-slip: parent-escaping member '${member}'"; bad=1 ;;
        esac
        # Windows-style separators, which tar treats as an ordinary filename
        # character on Linux but which a naive consumer elsewhere would not.
        case "$member" in
            *..\\*) log_error "  tar-slip: backslash parent-escape '${member}'"; bad=1 ;;
        esac
        (( bad )) && break
    done < <(tar -tf "$asset" 2>/dev/null)

    if (( bad )); then
        log_error "${name} contains unsafe paths — refusing to extract"
        return 1
    fi
    return 0
}

# ---------------------------------------------------------------------------
# upkg_extract <assets...>
#
# Extracts every asset into ONE directory so per-module assets merge by their
# shared top-level name, then asserts exactly one root came out. Sets UPKG_DIR.
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# _upkg_asset_module <path> — the module a per-module asset belongs to.
#
# CI names them "<tag>-<module>.tar[.gz]" (build_release_package.py) and the
# legacy bundle "intact-upgrade-<tag>.tar[.gz]", which ends in the tag and so
# matches nothing here. Matched against UPGRADE_ORDER rather than parsed, so a
# tag that happens to contain a dash cannot be mistaken for a module name.
# Longest first: today no module name is a suffix of another, and this keeps it
# true if one ever is.
# ---------------------------------------------------------------------------
_upkg_asset_module() {
    local b; b="$(basename "${1:-}")"
    b="${b%.gz}"; b="${b%.tar}"
    local m
    for m in $(printf '%s\n' "${UPGRADE_ORDER[@]}" | awk '{print length"\t"$0}' | sort -rn | cut -f2); do
        [[ "$b" == *"-${m}" ]] && { printf '%s' "$m"; return 0; }
    done
    return 1
}

# ---------------------------------------------------------------------------
# upkg_extract_deferred <module> — extract one module's asset, at its turn.
#
# The lazy half of upkg_extract. Extracting all nine assets up front means the
# whole release (~15 GB) is resident before the first module is touched, even
# though each module needs only its own slice and the tars are freed as they
# load anyway. This brings the peak down to roughly one module.
#
# VERIFICATION. upkg_verify_file_checksums treats a manifest path missing from
# the tree as fatal -- "the map is the statement of what the package IS" -- so
# it cannot run against a tree that is deliberately incomplete. The per-asset
# manifests are CI artifacts and are NOT published as release assets (the index
# records only asset/version/size/sha256), so there is no per-module map on the
# box either. What there IS:
#
#   * the whole asset's sha256, checked by upkg_verify_archive BEFORE any of
#     this, which already covers every byte inside it;
#   * the merged <tag>.manifest.json, whose contents.sha256 covers every file
#     in the release.
#
# So each asset is verified whole on the way in, and the files it wrote are
# re-checked against the merged map on the way out. Every hash still comes from
# the release's own metadata; only the SCOPE narrows, from "every path in the
# map" to "every path this asset just created". Nothing is recomputed, which is
# the rule at the top of this file.
# ---------------------------------------------------------------------------
upkg_extract_deferred() {
    local m="${1:-}" entry path=""
    [[ -n "$m" ]] || return 0
    for entry in ${UPKG_DEFERRED:-}; do
        [[ "${entry%%=*}" == "$m" ]] && { path="${entry#*=}"; break; }
    done
    [[ -n "$path" ]] || return 0            # not deferred: already on disk
    if [[ ! -f "$path" ]]; then
        log_error "  ${m}: its asset is gone from ${path}"
        return 1
    fi

    local work; work="$(dirname "$UPKG_DIR")"
    log_info "  extracting ${m} from $(basename "$path")"
    local before; before="$(mktemp)"
    find "$UPKG_DIR" -type f -newermt '1970-01-01' -printf '%P\n' 2>/dev/null | sort > "$before"
    if ! RUN_HEARTBEAT_QUIET=1 run_with_heartbeat "extracting $(basename "$path")" 1800 \
            bash -c 'tar -xf "$1" -C "$2" 2>>"$3"' _ "$path" "$work" "${LOG_FILE:-/dev/null}"; then
        log_error "  could not extract $(basename "$path")"
        rm -f "$before"; return 1
    fi
    local after; after="$(mktemp)"
    find "$UPKG_DIR" -type f -printf '%P\n' 2>/dev/null | sort > "$after"
    local added; added="$(mktemp)"
    comm -13 "$before" "$after" > "$added"
    rm -f "$before" "$after"

    if ! upkg_verify_paths_against_manifest "$added"; then
        rm -f "$added"; return 1
    fi
    log_info "  ${m}: $(wc -l < "$added" | tr -d ' ') file(s) verified against the release manifest"
    rm -f "$added"

    # Drop it from the deferred list, and free the compressed asset now that
    # its contents are on disk and checked -- but only if we downloaded it.
    local rest="" e
    for e in ${UPKG_DEFERRED:-}; do
        [[ "${e%%=*}" == "$m" ]] || rest+="${e} "
    done
    UPKG_DEFERRED="$rest"
    upkg_release_loaded_tar "$path"
    return 0
}

# ---------------------------------------------------------------------------
# upkg_verify_paths_against_manifest <file-of-relative-paths>
#
# The scoped counterpart to upkg_verify_file_checksums. Same map, same hashes,
# but it asserts only over the listed paths -- a path with no entry in the map
# is the fatal case here, exactly as a map entry with no file is there.
# ---------------------------------------------------------------------------
upkg_verify_paths_against_manifest() {
    local list="${1:-}"
    [[ -s "$list" ]] || return 0
    python3 - "$UPKG_MANIFEST" "$UPKG_DIR" "$list" <<'PY'
import hashlib, json, os, sys
manifest, root, listfile = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    m = json.load(open(manifest))
except Exception as e:
    print(f"  cannot read the package manifest: {e}"); sys.exit(1)
smap = ((m.get("contents") or {}).get("sha256")) or {}
if not smap:
    print("  the package manifest records no per-file checksums"); sys.exit(1)
bad, unknown = [], []
for rel in (l.rstrip("\n") for l in open(listfile)):
    if not rel or rel in ("manifest.json",):
        continue
    # Per-asset metadata, not content: every per-module asset carries its own
    # manifests/<module>.json sidecar (see upkg_read_manifest), and the merged
    # manifest's sha256 map describes the package's CONTENT, not the metadata
    # describing it. The full-manifest verifier never sees these (it walks the
    # map, not the disk); this scoped walk of everything extracted does, and
    # refusing over them failed every --only fetch of an otherwise perfect
    # package. Their integrity is already covered by the asset archive's own
    # sha256, verified before extraction.
    if rel.startswith("manifests/") and rel.endswith(".json"):
        continue
    want = smap.get(rel)
    if want is None:
        unknown.append(rel); continue
    h = hashlib.sha256()
    try:
        with open(os.path.join(root, rel), "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
    except OSError as e:
        bad.append(f"{rel} ({e})"); continue
    if h.hexdigest() != want:
        bad.append(rel)
for r in unknown[:5]:
    print(f"  not described by the release manifest: {r}")
for r in bad[:5]:
    print(f"  checksum mismatch: {r}")
sys.exit(1 if (bad or unknown) else 0)
PY
    local rc=$?
    (( rc == 0 )) || log_error "  the extracted files do not match the release manifest"
    return $rc
}

upkg_extract() {
    local assets=("$@")
    mkdir -p "${SCRIPT_DIR}/data/tmp" 2>/dev/null || true
    local work
    # Not /tmp: the assets are several GB and /tmp is a small tmpfs on many
    # hosts, so extracting there fills RAM and dies with a confusing ENOSPC
    # after the download already succeeded.
    work="$(mktemp -d -p "${SCRIPT_DIR}/data/tmp" upgrade-pkg-XXXXXX 2>/dev/null)" \
        || work="$(mktemp -d)"
    UPKG_SCRATCH="${UPKG_SCRATCH} ${work}"

    local total=0 sz a i=0
    for a in "${assets[@]}"; do
        sz=$(stat -c%s "$a" 2>/dev/null || echo 0); total=$((total + sz))
    done
    # Lazy extraction: unpack only what is needed to plan, and leave each
    # module's asset compressed until its own turn (upkg_extract_deferred).
    # Off by default -- it changes when verification happens, so it wants a
    # release cycle of field evidence before it becomes the default.
    #
    # `intact` is NEVER deferred, for two reasons that are both fatal: it
    # carries source/intact/scripts/upgrade.sh, without which the stage-0 hop
    # has nothing to exec into and the box silently runs its own older engine;
    # and it establishes the single top-level directory every other asset
    # merges into.
    local -a now=() later=()
    if [[ "${INTACT_UPGRADE_LAZY_EXTRACT:-0}" == "1" ]]; then
        local mod
        for a in "${assets[@]}"; do
            if mod="$(_upkg_asset_module "$a")" && [[ "$mod" != "intact" ]]; then
                later+=("${mod}=${a}")
            else
                now+=("$a")
            fi
        done
        if (( ${#later[@]} )); then
            UPKG_DEFERRED="${later[*]}"
            log_info "Extracting ${#now[@]} of ${#assets[@]} asset(s) now; ${#later[@]} deferred to their module's turn"
        else
            now=("${assets[@]}")
        fi
    else
        now=("${assets[@]}")
    fi

    (( ${#later[@]} )) || log_info "Extracting ${#assets[@]} asset(s), $(_human_size "$total")"

    for a in "${now[@]}"; do
        i=$((i + 1))
        if ! RUN_HEARTBEAT_QUIET=1 run_with_heartbeat "extracting $(basename "$a")" 1800 \
                bash -c 'tar -xf "$1" -C "$2" 2>>"$3"' _ "$a" "$work" "${LOG_FILE:-/dev/null}"; then
            log_error "Could not extract $(basename "$a")"
            return 1
        fi
        log_info "  [${i}/${#now[@]}] $(basename "$a") extracted in ${RUN_HEARTBEAT_ELAPSED:-?}s"
    done

    local roots root_count
    roots="$(find "$work" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' 2>/dev/null)"
    root_count="$(grep -c . <<< "$roots" || true)"
    if [[ "$root_count" != "1" ]]; then
        log_error "Expected exactly one top-level directory, found ${root_count}:"
        while IFS= read -r r; do [[ -n "$r" ]] && log_error "    ${r}"; done <<< "$roots"
        log_error "  Per-module assets merge by sharing a top-level directory."
        log_error "  More than one means these assets are from different releases."
        return 1
    fi

    UPKG_DIR="${work}/${roots}"
    UPKG_MANIFEST="${UPKG_DIR}/manifest.json"

    # WHICH manifest.json describes what was just extracted.
    #
    # "Whatever is already there wins" was wrong, and it broke the per-module
    # path completely. scripts/ci/build_release_package.py writes a root
    # manifest.json into EVERY asset, per-module builds included, and N assets
    # share one top-level dir -- so they overwrite each other and exactly one
    # survives, at random. That survivor describes ONE module: its `versions`
    # holds a single pin and its `contents.sha256` covers only its own files.
    # A guard of `! -f "$UPKG_MANIFEST"` is therefore never true for shapes 2
    # and 3, the merged manifest was never placed, and the result was a
    # full-release upgrade that silently upgraded one module (plan_build marks
    # every other one `skip:not in this package`) while verifying only that
    # module's checksums.
    #
    # The manifests say which they are, so ask instead of guessing:
    #
    #   package_kind == "module"  a per-module leftover -> the merged one wins
    #   package_kind == "bundle"  a legacy single bundle's own -> it wins
    #   absent                    already merged -> it wins
    #
    # The middle row is the LEGACY case, kept for the same reason as
    # upgrade_fetch_release's single-bundle fallback in refs.sh: every release
    # published before intact-20260811 is that shape, its manifest.json is
    # authoritative for its own tree, and a loose manifest sitting beside it
    # would be for a different release entirely. Remove once no box in the
    # fleet can be old enough to hand this function a bundle-shaped manifest.
    if [[ -n "$UPKG_LOOSE_MANIFEST" && -f "$UPKG_LOOSE_MANIFEST" ]]; then
        local _place=0 _kind=""
        if [[ ! -f "$UPKG_MANIFEST" ]]; then
            _place=1
        else
            # An unreadable/!json extracted manifest is NOT treated as a
            # per-module leftover: it might be a corrupt bundle manifest, and
            # overwriting it would swap a loud failure for a quiet wrong
            # answer. Only an explicit "module" hands precedence over.
            _kind="$(python3 -c '
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception:
    sys.exit(0)
print(((d.get("contents") or {}).get("package_kind")) or "")
' "$UPKG_MANIFEST" 2>/dev/null)"
            [[ "$_kind" == "module" ]] && _place=1
        fi

        if (( _place )); then
            cp "$UPKG_LOOSE_MANIFEST" "$UPKG_MANIFEST"
            if [[ "$_kind" == "module" ]]; then
                log_info "  replaced a per-module manifest leftover with the merged manifest.json"
            else
                log_info "  placed the merged manifest.json alongside the extracted assets"
            fi
        fi
    fi

    log_success "Package extracted: $(basename "$UPKG_DIR")"
    return 0
}

# ---------------------------------------------------------------------------
# upkg_read_manifest
#
# Validates the manifest exists, parses, is a supported format, and is not a
# delta. Populates UPKG_VERSIONS (assoc: module -> version).
# ---------------------------------------------------------------------------
declare -gA UPKG_VERSIONS=()

upkg_read_manifest() {
    [[ -f "$UPKG_MANIFEST" ]] || {
        # Every per-module asset carries manifests/<module>.json, and the
        # release's CI `index` job merges those into the root manifest.json
        # this function reads -- that merge is no longer redone here (it used
        # to be, in the Python engine this replaced; see git history). A
        # missing root manifest almost always means a partial or pre-index
        # package, not a corrupt one, so say that rather than "not found".
        if find "$UPKG_DIR" -mindepth 1 -maxdepth 2 -name '*.json' -path '*/manifests/*' \
                2>/dev/null | grep -q .; then
            log_error "This package has per-module manifests but no merged"
            log_error "  manifest.json -- it predates the per-module release"
            log_error "  index, or only some of the release's assets were"
            log_error "  copied here. Use the upgrade.sh shipped with the"
            log_error "  release, or copy every asset for this release."
        else
            log_error "No manifest.json in the package"
        fi
        return 1
    }

    local out
    out="$(python3 - "$UPKG_MANIFEST" "$SUPPORTED_PACKAGE_FORMAT" <<'PY'
import json, sys
path, supported = sys.argv[1], int(sys.argv[2])
try:
    m = json.load(open(path, encoding="utf-8"))
except Exception as e:
    print("ERROR|manifest.json is not valid JSON: %s" % e); raise SystemExit(0)

# package_version is "1.0"; only the MAJOR is a compatibility statement.
pv = str(m.get("package_version", "1"))
try:
    major = int(pv.split(".")[0])
except ValueError:
    print("ERROR|unreadable package_version %r" % pv); raise SystemExit(0)
if major > supported:
    print("ERROR|package format %s is newer than this upgrader supports (%d). "
          "Upgrade in smaller steps, or use the upgrade.sh shipped with that release."
          % (pv, supported))
    raise SystemExit(0)

contents = m.get("contents") or {}
# The delta scheme was withdrawn. Applying one as if it were a full package
# leaves modules silently at the wrong version, so it is refused outright
# rather than best-efforted.
if contents.get("package_kind") == "delta" or m.get("delta_from"):
    print("ERROR|this is a DELTA package; the delta scheme was withdrawn. "
          "Use a full release package.")
    raise SystemExit(0)

for k, v in (m.get("versions") or {}).items():
    if v is None or str(v).strip() == "":
        continue
    print("V|%s|%s" % (k, v))
print("K|pins_source|%s" % contents.get("pins_source", ""))
print("K|created|%s" % m.get("created", ""))
print("K|release_tag|%s" % contents.get("release_tag", ""))
print("K|sha_entries|%d" % len(contents.get("sha256") or {}))
PY
)" || { log_error "Could not read manifest.json"; return 1; }

    # Re-declare rather than clear: `X=()` on a `declare -A` array converts it
    # to an indexed one, and every later UPKG_VERSIONS[elk] would then be an
    # arithmetic subscript. Matters because upkg_read_manifest runs a second
    # time after the stage-0 re-exec.
    unset UPKG_VERSIONS
    declare -gA UPKG_VERSIONS=()

    local line
    while IFS= read -r line; do
        case "$line" in
            ERROR\|*) log_error "${line#ERROR|}"; return 1 ;;
            V\|*)     local rest="${line#V|}"; UPKG_VERSIONS["${rest%%|*}"]="${rest#*|}" ;;
            K\|pins_source\|*)  UPKG_PINS_SOURCE="${line##*|}" ;;
            K\|release_tag\|*)  UPKG_RELEASE_TAG="${line##*|}" ;;
            K\|sha_entries\|*)  UPKG_SHA_ENTRIES="${line##*|}" ;;
        esac
    done <<< "$out"

    # Older module names, so a package cut before the rename still dispatches.
    if [[ -n "${UPKG_VERSIONS[cloudtrail]:-}" && -z "${UPKG_VERSIONS[aws_sigma]:-}" ]]; then
        UPKG_VERSIONS[aws_sigma]="${UPKG_VERSIONS[cloudtrail]}"
        log_info "  manifest uses the pre-rename name 'cloudtrail' — treating it as aws_sigma"
    fi

    if [[ "${UPKG_PINS_SOURCE:-}" == "local-fallback" ]]; then
        # Provenance is degraded but visible rather than silent: the build
        # machine could not fetch the target release's own config.yaml and
        # used its local pins instead.
        log_warn "This package's pins came from the BUILD MACHINE's config.yaml,"
        log_warn "  not the target release's (pins_source=local-fallback). Verify the"
        log_warn "  version table below before continuing."
    fi

    log_info "Manifest: ${#UPKG_VERSIONS[@]} module pin(s), ${UPKG_SHA_ENTRIES:-0} checksummed file(s)"
    return 0
}

# ---------------------------------------------------------------------------
# upkg_verify_file_checksums
#
# Every path in contents.sha256, re-hashed against the extracted tree. This is
# the check that catches a file swapped inside an otherwise-intact archive.
# A missing entry is fatal: the map is the statement of what the package IS.
# ---------------------------------------------------------------------------
upkg_verify_file_checksums() {
    [[ -f "$UPKG_MANIFEST" ]] || return 1
    [[ "${UPKG_SHA_ENTRIES:-0}" != "0" ]] || {
        # Not fatal on its own -- some legacy packages predate the map -- but
        # the operator should know the strongest check available did not run.
        log_warn "  manifest carries no per-file checksums; skipping file verification"
        return 0
    }

    local rc=0
    RUN_HEARTBEAT_QUIET=1 run_with_heartbeat "verifying file checksums" 900 \
        python3 - "$UPKG_MANIFEST" "$UPKG_DIR" <<'PY' || rc=$?
import hashlib, json, os, sys
from concurrent.futures import ThreadPoolExecutor

manifest, root = sys.argv[1], sys.argv[2]
m = json.load(open(manifest, encoding="utf-8"))
shas = (m.get("contents") or {}).get("sha256") or {}

# Threads, not processes: hashlib drops the GIL around the actual digest work,
# so this parallelises for real, and most of the wall-clock here is reading
# ~5.6 GB off disk anyway. Processes would mean pickling the work list and
# paying fork cost for no gain. Capped at 8 -- past that the disk, not the CPU,
# is the limit, and this runs on appliances whose cores are already committed
# to the containers still serving during the upgrade.
workers = min(8, (os.cpu_count() or 2))

def check(item):
    rel, want = item
    p = os.path.join(root, rel)
    if not os.path.isfile(p):
        return ("missing", rel)
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return ("ok", rel) if h.hexdigest() == want else ("bad", rel)

bad, missing, ok = [], [], 0
with ThreadPoolExecutor(max_workers=workers) as pool:
    for kind, rel in pool.map(check, shas.items()):
        if kind == "ok":
            ok += 1
        elif kind == "missing":
            missing.append(rel)
        else:
            bad.append(rel)

# Sorted so the sample an operator sees is the same on every run; completion
# order is nondeterministic once the work is spread across threads.
for rel in sorted(missing)[:10]:
    sys.stderr.write("  MISSING from package: %s\n" % rel)
for rel in sorted(bad)[:10]:
    sys.stderr.write("  CHECKSUM MISMATCH: %s\n" % rel)
if missing or bad:
    sys.stderr.write("  %d verified, %d missing, %d corrupt\n" % (ok, len(missing), len(bad)))
    raise SystemExit(1)
print("  %d file(s) verified against the manifest" % ok)
PY
    if (( rc != 0 )); then
        log_error "Package file verification FAILED — refusing to upgrade from it"
        return 1
    fi
    log_success "  package contents verified"
    return 0
}

# ---------------------------------------------------------------------------
# upkg_acquire <assets...> [--expect-sha256 <hex>]
#
# The whole pre-flight, in the order the checks have to happen: verify the
# bytes, refuse unsafe members, extract, read the manifest, verify the files.
#
# The file-verification step has two shapes, same reasoning as the
# upkg_extract_deferred header above: upkg_verify_file_checksums asserts over
# EVERY path the merged manifest describes, which is only valid when the tree
# it is checking is the WHOLE release. Two things can make it deliberately
# partial at this point: INTACT_RELEASE_ONLY_MODULES trimmed which assets were
# even downloaded (--only), or upkg_extract deferred some of them to their
# module's turn (INTACT_UPGRADE_LAZY_EXTRACT, left non-empty in UPKG_DEFERRED).
# Either way, files for modules not yet on disk are ABSENT ON PURPOSE, not
# missing, so the full-manifest check would fail every such run. Route through
# the scoped verifier instead, over every file this call actually extracted --
# each asset's own sha256 (checked above) already guarantees nothing inside it
# was truncated or swapped wholesale; this re-checks every file that landed on
# disk against the release's own per-file map, same guarantee, narrower scope.
# ---------------------------------------------------------------------------
upkg_acquire() {
    local expect="${UPGRADE_EXPECT_SHA256:-}"
    local assets=("$@") a

    log_info ""
    log_info "Verifying package…"
    for a in "${assets[@]}"; do
        upkg_verify_archive "$a" "${expect}" || return 1
        upkg_check_tar_slip "$a" || return 1
        # An --expect-sha256 anchors ONE archive; applying it to the second
        # asset would fail a perfectly good multi-asset package.
        expect=""
    done

    upkg_extract "${assets[@]}" || return 1
    upkg_read_manifest || return 1

    if [[ -n "${INTACT_RELEASE_ONLY_MODULES:-}" || -n "${UPKG_DEFERRED:-}" ]]; then
        local _acquired; _acquired="$(mktemp)"
        find "$UPKG_DIR" -type f -printf '%P\n' 2>/dev/null | sort > "$_acquired"
        upkg_verify_paths_against_manifest "$_acquired"
        local rc=$?
        rm -f "$_acquired"
        (( rc == 0 )) || return 1
        log_success "  package contents verified (partial fetch)"
    else
        upkg_verify_file_checksums || return 1
    fi
    return 0
}

# ---------------------------------------------------------------------------
# upkg_cleanup — remove every scratch dir this file created.
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# upkg_sweep_stale_scratch [hours]
#
# upkg_cleanup only ever removes what THIS process's own UPKG_SCRATCH
# remembers extracting -- in-memory state that a killed -9, an OOM, or a
# lost SSH session discards along with the process. A run that dies that way
# leaves its multi-GB extraction under data/tmp/ forever; nothing else ever
# looks at it again. This is the other half: an AGE-based sweep of the same
# naming conventions, run once at the START of the next invocation rather
# than relying on the previous one to have exited cleanly.
#
# 48h default: long enough that this never touches a scratch dir a slow
# but still-running upgrade legitimately owns (the flock in scripts/upgrade.sh
# is what actually prevents two runs colliding; this is just reclaiming
# space from ones that are definitely over).
#
# The patterns cover the INSTALL path too -- pkg-* (lib/package.sh), unwrap-*
# (lib/args.sh) and load-* (lib/package.sh's per-image load log). They were
# missing, so install leftovers were never reclaimed by anything: a 1.1 GB
# unwrap-jA2bY0 from an install two days earlier was still sitting in data/tmp
# on the dev box, alongside 2.2 GB of upgrade-dl-* that this sweep DID know
# about but which nothing had registered for cleanup (see scripts/upgrade.sh).
#
# Two names are deliberately absent and must stay that way:
#   import-pkg-*  a package staged by the dashboard's import flow. The sweep
#                 runs at the START of the next upgrade, so a name matched
#                 here could delete a staged package out from under a run that
#                 has not begun extracting yet. It is reclaimed on terminal
#                 state instead -- routes/upgrade_routes.py:355.
#   upgrade-*     too broad: upgrade-<run_id>.log and upgrade-<run_id>.done.json
#                 are the dashboard's run records and upgrade.lock is the live
#                 flock target. Only the three specific upgrade-{pkg,unwrap,dl}-*
#                 prefixes above are scratch.
# ---------------------------------------------------------------------------
upkg_sweep_stale_scratch() {
    local hours="${1:-48}"
    local dir="${SCRIPT_DIR}/data/tmp"
    [[ -d "$dir" ]] || return 0
    local n=0 d
    while IFS= read -r d; do
        [[ -n "$d" ]] || continue
        rm -rf "$d" 2>/dev/null && n=$((n + 1))
    done < <(find "$dir" -maxdepth 1 -mmin "+$((hours * 60))" \
                  \( -name 'upgrade-pkg-*' -o -name 'upgrade-unwrap-*' \
                     -o -name 'upgrade-dl-*' -o -name 'intact-rollback-*' \
                     -o -name 'velo-upgrade-*' -o -name 'dl-list-*' \
                     -o -name 'dl-status-*' \
                     -o -name 'pkg-*' -o -name 'unwrap-*' -o -name 'load-*' \) 2>/dev/null)
    (( n > 0 )) && log_info "  swept ${n} stale scratch item(s) left from an earlier run (older than ${hours}h)"
    return 0
}

upkg_cleanup() {
    local d
    for d in ${UPKG_SCRATCH}; do
        [[ -n "$d" && -d "$d" ]] || continue
        case "$d" in
            "${SCRIPT_DIR}/data/tmp/"*|/tmp/*) rm -rf "$d" ;;
            *) log_warn "refusing to remove unexpected scratch path: $d" ;;
        esac
    done
    UPKG_SCRATCH=""

    # Sweep rollback snapshots older than a week. A successful upgrade
    # discards its own backup immediately; these are the ones left behind by
    # a rollback, deliberately kept as evidence of what was restored. Without
    # a sweep they accumulate one per incident, forever, inside tracked
    # module directories.
    find "${SCRIPT_DIR}/modules" -maxdepth 2 -name '.env.upgrade-bak-*' \
         -type f -mtime +7 -delete 2>/dev/null
    return 0
}

# ---------------------------------------------------------------------------
# upkg_path_is_our_scratch <path>
#
# True only when <path> lives inside scratch THIS RUN created. The one thing
# standing between free-as-you-go (below) and deleting a customer's carry-in
# media, so it is default-deny: anything it cannot positively account for is
# left alone.
#
# `sudo bash scripts/upgrade.sh --package /media/usb/<tag>-package.tar`
# against an already-extracted tree makes UPKG_DIR the operator's own
# directory. Those files are frequently the only copy -- an air-gapped site
# carried them in physically -- so a wrong answer here is unrecoverable.
#
# UPKG_SCRATCH is the authority, not the path shape: upkg_extract registers
# $work BEFORE extracting into it (see above), and the stage-0 hop exports the
# variable across `exec` (scripts/upgrade.sh), so the process that actually
# loads the images still knows what it created.
#
# readlink -f BEFORE the prefix compare is not decoration. A plain string test
# would accept data/tmp/upgrade-pkg-XXXX/images when that directory is a
# symlink to /media/usb -- the prefix matches, the file does not live there,
# and the delete lands on the operator's media.
# ---------------------------------------------------------------------------
upkg_path_is_our_scratch() {
    local p="${1:-}" d rp
    [[ -n "$p" ]] || return 1
    rp="$(readlink -f -- "$p" 2>/dev/null)" || return 1
    [[ -n "$rp" ]] || return 1

    # 1. inside a directory this run registered.
    for d in ${UPKG_SCRATCH}; do
        [[ -n "$d" ]] || continue
        d="$(readlink -f -- "$d" 2>/dev/null)" || continue
        [[ -n "$d" ]] || continue
        [[ "$rp" == "$d"/* ]] && return 0
    done

    # 2. a hand retry against an extraction we made on an earlier run: our own
    #    naming, under our own data/tmp. Deliberately tighter than
    #    upkg_cleanup's `/tmp/*` arm -- that one only ever removes paths it had
    #    already registered, so it can afford to be loose. Here this IS the
    #    check, and a mktemp fallback landing in /tmp is covered by rule 1
    #    anyway (same process, or exported across the hop).
    case "$rp" in
        "${SCRIPT_DIR}/data/tmp/upgrade-pkg-"*|"${SCRIPT_DIR}/data/tmp/upgrade-unwrap-"*)
            return 0 ;;
    esac
    return 1
}

# ---------------------------------------------------------------------------
# upkg_release_loaded_tar <tar>
#
# Free an image tar whose layers are now in the docker store. The installer
# has done this since the 22 GB-scratch measurement (lib/package.sh); the
# upgrade path never did, so a full release held every extracted tar on disk
# until the run ended -- while plan_check_disk sized the run on the assumption
# that it did not.
#
# Callers MUST have confirmed the load succeeded AND the image is present. A
# tar whose load failed is the only copy of that image on an air-gapped box.
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Cross-subshell state.
#
# u_do runs every step through _u_run_with_deadline, which forks `( "$@" ) &`
# so it can kill a whole process group on timeout. A shell variable assigned
# inside that fork is gone the moment it exits -- so U_TARS_FREED never reached
# the report, and U_KEEP_SCRATCH never reached the EXIT trap. The second one
# matters: a FAILED image load could not mark the run, the trap reclaimed the
# extraction anyway, and the operator had to re-download several GB to retry --
# precisely what the flag exists to avoid. Files cross a fork; variables do not.
# Found on a live run 2026-08-13; the unit tests call these directly and so
# never saw it.
# ---------------------------------------------------------------------------
_upkg_state_dir() { printf '%s' "${SCRIPT_DIR}/data/tmp"; }
_upkg_tally_file() { printf '%s/.upgrade-tars-freed' "$(_upkg_state_dir)"; }
_upkg_keep_file()  { printf '%s/.upgrade-keep-scratch' "$(_upkg_state_dir)"; }

# Call instead of `U_KEEP_SCRATCH=1` so it survives u_do's fork.
u_mark_keep_scratch() {
    U_KEEP_SCRATCH=1
    mkdir -p "$(_upkg_state_dir)" 2>/dev/null
    : > "$(_upkg_keep_file)" 2>/dev/null || true
}
u_keep_scratch_requested() {
    [[ "${U_KEEP_SCRATCH:-0}" == "1" || -f "$(_upkg_keep_file)" ]]
}
# Total bytes freed this run, summed from the tally.
u_tars_freed_bytes() {
    local f; f="$(_upkg_tally_file)"
    [[ -f "$f" ]] || { printf '0'; return 0; }
    awk '{t+=$1} END{printf "%d", t+0}' "$f" 2>/dev/null || printf '0'
}
u_clear_run_state() {
    U_KEEP_SCRATCH=0
    rm -f "$(_upkg_tally_file)" "$(_upkg_keep_file)" 2>/dev/null
    return 0
}

upkg_release_loaded_tar() {
    local tar="${1:-}"
    [[ -n "$tar" && -f "$tar" ]] || return 0
    if [[ "${INTACT_UPGRADE_KEEP_TARS:-0}" == "1" ]]; then
        return 0
    fi
    if ! upkg_path_is_our_scratch "$tar"; then
        log_info "    keeping $(basename "$tar") — not inside scratch this run created"
        return 0
    fi
    local sz; sz="$(stat -c%s "$tar" 2>/dev/null || echo 0)"
    if rm -f -- "$tar" 2>/dev/null; then
        U_TARS_FREED=$(( ${U_TARS_FREED:-0} + sz ))
        # And to disk, because this usually runs inside u_do's forked subshell
        # where the variable above dies with the fork.
        mkdir -p "$(_upkg_state_dir)" 2>/dev/null
        printf '%s\n' "$sz" >> "$(_upkg_tally_file)" 2>/dev/null || true
    fi
    return 0
}
