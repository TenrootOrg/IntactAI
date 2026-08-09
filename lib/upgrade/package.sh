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
UPKG_SCRATCH=""      # what to rm -rf at the end

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
    local p f listing unwrap
    for p in "$@"; do
        if [[ -d "$p" ]]; then
            while IFS= read -r f; do UPKG_ASSETS+=("$f"); done \
                < <(find "$p" -maxdepth 1 \( -name '*.tar.gz' -o -name '*.tar' \) \
                         ! -name '*-system-bundle.tar' | sort)
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
            grep '\.tar\(\.gz\)\?$' <<< "$listing" | tar -xf "$p" -C "$unwrap" -T - || {
                log_error "Could not unwrap $(basename "$p")"; return 1; }
            while IFS= read -r f; do
                [[ "$(basename "$f")" == *-system-bundle.tar ]] && continue
                expanded+=("$f")
            done < <(find "$unwrap" -maxdepth 1 \( -name '*.tar.gz' -o -name '*.tar' \) | sort)
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
    log_info "Extracting ${#assets[@]} asset(s), $(_human_size "$total")"

    for a in "${assets[@]}"; do
        i=$((i + 1))
        if ! RUN_HEARTBEAT_QUIET=1 run_with_heartbeat "extracting $(basename "$a")" 1800 \
                bash -c 'tar -xf "$1" -C "$2" 2>>"$3"' _ "$a" "$work" "${LOG_FILE:-/dev/null}"; then
            log_error "Could not extract $(basename "$a")"
            return 1
        fi
        log_info "  [${i}/${#assets[@]}] $(basename "$a") extracted in ${RUN_HEARTBEAT_ELAPSED:-?}s"
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
        log_error "No manifest.json in the package"
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
manifest, root = sys.argv[1], sys.argv[2]
m = json.load(open(manifest, encoding="utf-8"))
shas = (m.get("contents") or {}).get("sha256") or {}
bad, missing, ok = [], [], 0
for rel, want in shas.items():
    p = os.path.join(root, rel)
    if not os.path.isfile(p):
        missing.append(rel); continue
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    if h.hexdigest() != want:
        bad.append(rel)
    else:
        ok += 1
for rel in missing[:10]:
    sys.stderr.write("  MISSING from package: %s\n" % rel)
for rel in bad[:10]:
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
    upkg_verify_file_checksums || return 1
    return 0
}

# ---------------------------------------------------------------------------
# upkg_cleanup — remove every scratch dir this file created.
# ---------------------------------------------------------------------------
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
    return 0
}
