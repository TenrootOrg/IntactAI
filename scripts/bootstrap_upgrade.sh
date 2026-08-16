#!/bin/bash
# Intact.AI — upgrade bootstrap (stage 1). FROZEN. DO NOT ADD FEATURES.
#
# ===========================================================================
# WHY THIS FILE EXISTS
# ===========================================================================
#
# The code that decides how to upgrade is the OLD release's code. Every format
# this file understands is therefore a contract with every future release, and
# a contract the future release has no way to renegotiate -- this copy is
# already installed on the box by the time anyone wants to change it.
#
# That is not theoretical. A release changed its package wrapper from .tar to
# .tar.gz and changed the dashboard flow, and boxes could not upgrade: to reach
# the new engine, the installed engine first had to parse the new package, and
# the package format was exactly what had changed. Circular, and unfixable from
# the new side.
#
# So this script's entire job is:
#
#     fetch the target release's engine -> verify it -> exec it
#
# and nothing else. It does not read a manifest. It does not unwrap a package.
# It does not sniff a tar. It does not know what a module is. Everything the
# upgrade actually does happens on the far side of the `exec`, in code that
# shipped WITH the release being installed -- so a future release can change
# its package format, its CLI, its module list or its whole engine, and this
# file still gets it running.
#
# ===========================================================================
# THE FROZEN CONTRACT -- changing any of this breaks every installed box
# ===========================================================================
#
#   Asset name      <tag>-engine.tar.gz          (+ .sha256 beside it)
#   Asset location  the release's download URL, and the top level of a
#                   prepare_package.sh wrapper
#   Layout inside   FLAT, no leading directory:
#                       BOOTSTRAP_PROTOCOL   -- an integer, currently 1
#                       VERSION
#                       install.sh
#                       lib/...
#                       scripts/...
#   Entry point     <extracted>/scripts/upgrade.sh
#   Handover        exec ... --root <appliance> --handoff <json> [--log <path>]
#
# BOOTSTRAP_PROTOCOL is the escape hatch. If a future release genuinely cannot
# be driven by this contract it ships a higher number, and this file refuses
# cleanly and names the release to land on first -- instead of misparsing and
# failing somewhere unrecognisable three steps later. That refusal is the whole
# reason the marker exists; it is what makes this file safe to freeze.
#
# DELIBERATELY NOT SOURCED: lib/*.sh. Those are the files being REPLACED. This
# script uses bash, curl, tar and sha256sum, all of which are on any box that
# could run the platform at all. Every line this file does not have is a line
# that cannot break a future upgrade. If you are about to add a feature here,
# add it to scripts/upgrade.sh instead -- that one ships with the release and
# can be changed freely.

set -o pipefail

# The highest BOOTSTRAP_PROTOCOL this copy knows how to drive.
_BOOTSTRAP_KNOWS=1

_ENGINE_NAME_FMT='%s-engine.tar.gz'

INTACT_REPO="${INTACT_REPO:-TenrootOrg/IntactAI}"
INTACT_GH_DL_BASE="${INTACT_GH_DL_BASE:-https://github.com}"

_say()  { printf '[%s] [INFO] %s\n'  "$(date '+%Y-%m-%d %H:%M:%S')" "$*"; }
_warn() { printf '[%s] [WARN] %s\n'  "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >&2; }
# "$1", not "$*": the optional second argument is the EXIT CODE, and $* would
# print it as part of the message ("... <args> 2").
_die()  { printf '[%s] [ERROR] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$1" >&2; exit "${2:-2}"; }

_usage() {
    cat <<'EOF'
Usage:
  bootstrap_upgrade.sh <tag> [--root <dir>] [passthrough args...]
  bootstrap_upgrade.sh --package <file|dir> [--engine <file>] [--root <dir>] [...]
  bootstrap_upgrade.sh <tag> --prepare [<output-dir>]

Fetches the target release's own code, verifies it, and hands over to it.
Every other flag is passed through untouched.

  --root <dir>     the appliance to act on (default: this script's checkout)
  --engine <file>  use this engine tarball instead of fetching one (air-gap)
  --prepare [dir]  build a carry-in package for <tag> using the TARGET
                   release's own prepare_package.sh, instead of upgrading

The air-gapped round trip, both halves running the target's code:

  # on a machine with internet -- needs no appliance
  bash bootstrap_upgrade.sh intact-20260813 --prepare /media/usb

  # on the air-gapped box
  sudo bash bootstrap_upgrade.sh --package /media/usb/intact-upgrade-intact-20260813.tar
EOF
}

# ---------------------------------------------------------------------------
# Argument scan.
#
# Deliberately NON-consuming: every argument is passed through to the target
# engine verbatim, and this only PEEKS at the few it needs to do its own job.
# Nothing is rejected as unknown -- an unknown flag is by definition a flag
# some future engine understands and this file does not, which is the normal
# case, not an error. Getting this wrong is how argv became a cross-release
# contract in the first place -- upgrade.sh used to carry an allowlist of
# flags it was safe to drop when handing to an older engine, which is now
# deleted along with the argv handover that needed it.
# ---------------------------------------------------------------------------
_TAG=""; _ROOT=""; _ENGINE=""; _PKG=""; _LOG=""
_PREPARE=0; _PREPARE_OUT=""
_ARGS=("$@")
_i=0
while (( _i < $# )); do
    _a="${_ARGS[$_i]}"
    case "$_a" in
        -h|--help)   _usage; exit 0 ;;
        # Build a package with the TARGET release's packager rather than with
        # whatever checkout the operator happens to be standing in. Same
        # argument as the upgrade itself: the package's shape is decided by the
        # release it is FOR, so the release it is for should be what writes it.
        # An optional value, because `--prepare` with no directory is the
        # common case and should not need a placeholder.
        --prepare)   _PREPARE=1
                     case "${_ARGS[$((_i+1))]:-}" in
                         ""|-*) : ;;
                         *) _PREPARE_OUT="${_ARGS[$((_i+1))]}"; _i=$((_i+1)) ;;
                     esac ;;
        --prepare=*) _PREPARE=1; _PREPARE_OUT="${_a#*=}" ;;
        --root)      _ROOT="${_ARGS[$((_i+1))]:-}"; _i=$((_i+1)) ;;
        --root=*)    _ROOT="${_a#*=}" ;;
        --engine)    _ENGINE="${_ARGS[$((_i+1))]:-}"; _i=$((_i+1)) ;;
        --engine=*)  _ENGINE="${_a#*=}" ;;
        --package)   _PKG="${_ARGS[$((_i+1))]:-}"; _i=$((_i+1)) ;;
        --package=*) _PKG="${_a#*=}" ;;
        --log)       _LOG="${_ARGS[$((_i+1))]:-}"; _i=$((_i+1)) ;;
        --log=*)     _LOG="${_a#*=}" ;;
        # Refused HERE, with the reason, rather than forwarded to the engine
        # for a generic "Unknown option" from a program the operator did not
        # invoke. It used to skip the sha256 check on code about to be run as
        # root; there is no version of that which is safe enough to keep.
        --no-verify) _die "--no-verify has been removed.
  The engine is verified against its published sha256 before it is run as root,
  and that is not optional. build_engine_asset.sh writes a .sha256 beside every
  asset it produces, so a locally built engine has one too." ;;
        -*)          : ;;                       # someone else's flag; pass it on
        *)           [[ -z "$_TAG" ]] && _TAG="$_a" ;;
    esac
    _i=$((_i+1))
done

# Strip only the flags THIS script owns and re-emits itself.
#
#   --engine                 ours alone; the target engine has never heard of
#                            it and exits 2 on "Unknown option".
#   --root / --handoff       we pass authoritative values below (--root is
#                            resolved here, including its default), so leaving
#                            the originals in would emit each flag twice.
#
# Everything else goes through untouched, including flags this copy has never
# heard of -- that is the entire point.
_FWD=()
_i=0
while (( _i < $# )); do
    _a="${_ARGS[$_i]}"
    case "$_a" in
        --engine|--root|--handoff)          _i=$((_i+1)) ;;   # skip it AND its value
        --engine=*|--root=*|--handoff=*)    : ;;
        # --prepare selects WHICH target script runs; it is never forwarded.
        # Its optional value is skipped only when it is actually a value.
        --prepare)   [[ "${_ARGS[$((_i+1))]:-}" != "" && "${_ARGS[$((_i+1))]:-}" != -* ]] && _i=$((_i+1)) ;;
        --prepare=*)                        : ;;
        *)                                  _FWD+=("$_a") ;;
    esac
    _i=$((_i+1))
done

# The appliance. Not the same thing as where this script lives -- after the
# handover the engine runs from an extracted tree under data/tmp, so it has to
# be told the appliance root explicitly or it would act on scratch.
if [[ -z "$_ROOT" ]]; then
    _self="${BASH_SOURCE[0]}"
    [[ -L "$_self" ]] && _self="$(readlink -f "$_self" 2>/dev/null || echo "$_self")"
    _ROOT="$(cd -P "$(dirname "$_self")/.." 2>/dev/null && pwd)"
fi
[[ -d "$_ROOT" ]] || _die "appliance root not found: ${_ROOT}"

# --prepare runs on a BUILD machine, which has no appliance and no reason to
# have one -- it is producing a file to carry elsewhere. Requiring config.yaml
# or a writable data/tmp there would make the connected half of the air-gapped
# round trip demand an installed platform it does not need.
# ---------------------------------------------------------------------------
# WHERE DOWNLOADS LAND, AND WHERE THE ENGINE IS EXTRACTED. These are different
# on purpose, and the second one is a security boundary.
#
# The appliance tree is OPERATOR-OWNED BY DESIGN -- lib/permissions.sh does
# `chown -R "${uid}:${gid}" "${SCRIPT_DIR}"`, so data/tmp is
# `drwxr-xr-x tenroot tenroot`. This script runs as root and execs what it
# extracts. Extracting into that tree means root executing code out of a
# directory an unprivileged user can write, and the extraction path is
# PREDICTABLE because it is keyed on the published release's digest -- so a
# local user could pre-create engine-<digest>/scripts/upgrade.sh and have it
# run as root.
#
# So the engine goes somewhere only root can write. Downloads may still land in
# the appliance tree: a tarball there is inert, and it is verified against its
# sha256 before anything is extracted from it.
# ROOT-ONLY WHEN WE ARE ROOT; PRIVATE-TEMP OTHERWISE.
#
# The hazard is specifically "root execs code out of a directory a lesser user
# can write". Running unprivileged -- which --prepare does, since packaging
# needs no root -- that hazard does not exist: the user is executing their own
# code either way, and demanding a root-only path would simply make the
# unprivileged paths fail. `mktemp -d` gives 0700 under an unpredictable name,
# so nobody else can pre-create or tamper with it; the cost is no reuse across
# calls, which is the right trade for a path that is not privileged.
if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
    _ENGINE_ROOT="/var/lib/intact/engine"
else
    _ENGINE_ROOT=""
fi

if (( _PREPARE )); then
    _TMP="$(mktemp -d 2>/dev/null)" || _die "cannot create a working directory"
    [[ -n "$_PREPARE_OUT" ]] || _PREPARE_OUT="$PWD"
    mkdir -p "$_PREPARE_OUT" 2>/dev/null || _die "cannot write ${_PREPARE_OUT}"
    _PREPARE_OUT="$(cd "$_PREPARE_OUT" && pwd)"
else
    [[ -f "${_ROOT}/config.yaml" ]] || _warn "no config.yaml under ${_ROOT} — is that the appliance root?"
    _TMP="${_ROOT}/data/tmp"
    mkdir -p "$_TMP" 2>/dev/null || _die "cannot write ${_TMP}"
fi

# 0700 root-only. `mkdir -m` sets the mode at creation rather than leaving a
# window where it is world-traversable, and the mode is re-asserted in case the
# directory already existed with something laxer.
if [[ -n "$_ENGINE_ROOT" ]]; then
    mkdir -p "$_ENGINE_ROOT" 2>/dev/null || _die "cannot create ${_ENGINE_ROOT}"
    chmod 700 "$_ENGINE_ROOT" 2>/dev/null || true
else
    _ENGINE_ROOT="$(mktemp -d 2>/dev/null)" \
        || _die "cannot create a private directory for the engine"
fi

# ---------------------------------------------------------------------------
# Locate the engine tarball. Three sources, in order of how explicit they are.
# ---------------------------------------------------------------------------
_find_engine() {
    # 1. Told exactly where it is.
    if [[ -n "$_ENGINE" ]]; then
        [[ -f "$_ENGINE" ]] || _die "no engine tarball at ${_ENGINE}"
        printf '%s' "$_ENGINE"; return 0
    fi

    # 2. Beside, or inside, the package being applied. prepare_package.sh puts
    #    the engine at the TOP LEVEL of the wrapper precisely so this can be a
    #    named extraction rather than a search -- a search is parsing, and
    #    parsing is what this file must not do.
    if [[ -n "$_PKG" ]]; then
        local dir name
        dir="$([[ -d "$_PKG" ]] && printf '%s' "$_PKG" || dirname "$_PKG")"
        for name in "$dir"/*-engine.tar.gz; do
            [[ -f "$name" ]] && { printf '%s' "$name"; return 0; }
        done
        if [[ -f "$_PKG" ]]; then
            local out="${_TMP}/engine-from-pkg.$$"
            mkdir -p "$out" 2>/dev/null
            # One named pattern, no listing, no format detection. tar reads
            # both .tar and .tar.gz wrappers on its own; if a future wrapper is
            # something else entirely this simply finds nothing and falls
            # through to the network, which is the correct outcome.
            if tar -xf "$_PKG" -C "$out" --wildcards '*-engine.tar.gz' '*-engine.tar.gz.sha256' 2>/dev/null; then
                for name in "$out"/*-engine.tar.gz "$out"/*/*-engine.tar.gz; do
                    [[ -f "$name" ]] && { printf '%s' "$name"; return 0; }
                done
            fi
        fi
    fi

    # 3. Fetch it. Fixed name, fixed URL shape, no index and no API call --
    #    those are formats, and formats change.
    [[ -n "$_TAG" ]] || return 1
    command -v curl >/dev/null 2>&1 || return 1
    local fname; fname="$(printf "$_ENGINE_NAME_FMT" "$_TAG")"
    local url="${INTACT_GH_DL_BASE}/${INTACT_REPO}/releases/download/${_TAG}/${fname}"
    local dest="${_TMP}/${fname}"
    _say "fetching the ${_TAG} upgrade engine (${fname})" >&2
    # 2>/dev/null: a missing engine asset is the EXPECTED answer for any release
    # published before this asset existed, and _fall_back_to_caller handles it
    # in a sentence. Letting curl print "Failed to connect" first makes a normal
    # fallback read like a fault.
    # --proto/--proto-redir '=https': -L will otherwise follow a redirect to
    # http/ftp/file. NOT pinning the redirect HOST -- GitHub redirects release
    # downloads to objects.githubusercontent.com, so a same-host rule would
    # break every online upgrade. Content is protected by the sha256 below;
    # this only stops a protocol downgrade.
    curl -fLsS --proto '=https' --proto-redir '=https' \
         --retry 3 --retry-delay 2 --max-time 300 -o "$dest" "$url" 2>/dev/null || return 1
    curl -fLsS --proto '=https' --proto-redir '=https' \
         --retry 3 --max-time 60 -o "${dest}.sha256" "${url}.sha256" 2>/dev/null \
        || _warn "could not fetch ${fname}.sha256 — verification below will refuse"
    printf '%s' "$dest"
}

# ---------------------------------------------------------------------------
# No engine to be had -> REFUSE. There is deliberately no fallback.
#
# The earlier draft fell back to running the appliance's own engine. That is
# precisely the behaviour this whole design exists to remove: the upgrade would
# then be driven by the code already on the box rather than by the code that
# shipped with the release being installed, and it would do so SILENTLY, which
# is the worst version -- an operator reading "upgrade complete" has no way to
# know which engine produced it.
#
# One mechanism, or two mechanisms to keep in agreement forever. Refusing here
# means the failure is loud, early, and nothing has been touched.
# ---------------------------------------------------------------------------
_no_engine() {
    _die "could not obtain the ${_TAG:+${_TAG} }upgrade engine.

  The upgrade must run the TARGET release's code, and that code could not be
  fetched or found. Nothing has been changed.

  Give it the engine directly:
    --engine <path to ${_TAG:-<tag>}-engine.tar.gz>

  Or extract it from the package you are applying and run it in place:
    tar -xf <package> '*-engine.tar.gz' && tar -xzf ${_TAG:-<tag>}-engine.tar.gz -C /tmp/engine
    sudo bash /tmp/engine/scripts/upgrade.sh --root ${_ROOT} <args>"
}

_ENGINE_TAR="$(_find_engine)" || _ENGINE_TAR=""
[[ -f "$_ENGINE_TAR" ]] || _no_engine

# ---------------------------------------------------------------------------
# Verify. This is about to be given root, so a missing checksum is a decision
# the operator makes explicitly, not a default.
# ---------------------------------------------------------------------------
# VERIFICATION IS NOT OPTIONAL. There used to be a --no-verify escape and a
# warn-and-continue path when no .sha256 was found. Both meant running
# downloaded code as root with no check, which is the one thing this script
# exists to avoid. build_engine_asset.sh writes a .sha256 beside every asset it
# produces, so even a locally built engine has one -- the escape bought nothing.
_sha_file=""
for _c in "${_ENGINE_TAR}.sha256" "$(dirname "$_ENGINE_TAR")/$(basename "$_ENGINE_TAR").sha256"; do
    [[ -f "$_c" ]] && { _sha_file="$_c"; break; }
done
command -v sha256sum >/dev/null 2>&1 \
    || _die "sha256sum is not available, so the engine cannot be verified.
  Refusing to run downloaded code as root unchecked."
[[ -n "$_sha_file" ]] || _die "no .sha256 beside ${_ENGINE_TAR}.
  The engine cannot be verified, and it is about to be run as root.
  Either re-download the release (the checksum is published beside the asset),
  or point --engine at an asset that has its .sha256 next to it."

_want="$(awk '{print $1; exit}' "$_sha_file" 2>/dev/null)"
_got="$(sha256sum "$_ENGINE_TAR" 2>/dev/null | awk '{print $1}')"
if [[ -z "$_want" || "$_want" != "$_got" ]]; then
    _die "engine checksum mismatch — refusing to run it.
  expected ${_want:-<unreadable>}
  got      ${_got:-<unreadable>}
  Re-download the release."
fi
_say "engine verified (sha256 ${_got:0:16}…)"

# ---------------------------------------------------------------------------
# Extract and check the protocol.
# ---------------------------------------------------------------------------
# CONTENT-ADDRESSED, not per-PID. The first draft keyed this on $$, so every
# invocation left an extracted engine behind -- and the dashboard calls this on
# every page render to ask what a package contains, so that leaks a directory
# per page view. Keying on the tarball's own digest means a repeat call reuses
# the extraction it already verified, and two different engines can never
# collide on one path.
_eng_id="$(sha256sum "$_ENGINE_TAR" 2>/dev/null | awk '{print substr($1,1,16)}')"
[[ -n "$_eng_id" ]] || _eng_id="${_TAG:-pkg}"
_DEST="${_ENGINE_ROOT}/engine-${_eng_id}"

# REUSE IS EARNED, NOT ASSUMED.
#
# The first version of this reused any directory whose NAME matched the digest:
#
#     if [[ -f "${_DEST}/scripts/upgrade.sh" ]]; then   # <- no verification
#
# A name is not a proof. The digest is the published release's, so the path is
# predictable, and anything able to create that directory could hand root a
# script of its choosing. What is actually being asserted is "root put this
# here and nobody else has touched it", so check exactly that: owned by uid 0,
# mode 0700, and the entry point not writable by group or other.
_engine_dir_is_trustworthy() {
    local d="$1" own mode
    [[ -d "$d" && -f "${d}/scripts/upgrade.sh" ]] || return 1
    own="$(stat -c '%u' "$d" 2>/dev/null)" || return 1
    # Must be owned by whoever is about to exec it. As root that means uid 0 --
    # the whole point. Unprivileged, the engine root is a fresh mktemp dir that
    # nothing else can reach, so "owned by me" is the same guarantee.
    [[ "$own" == "${EUID:-$(id -u)}" ]] || return 1
    mode="$(stat -c '%a' "$d" 2>/dev/null)" || return 1
    [[ "$mode" == "700" ]] || return 1
    mode="$(stat -c '%a' "${d}/scripts/upgrade.sh" 2>/dev/null)" || return 1
    [[ "$mode" =~ [2367]$|[2367][0-9]$ ]] && return 1
    return 0
}

if _engine_dir_is_trustworthy "$_DEST"; then
    _say "reusing the verified engine at ${_DEST}"
else
    # Anything that failed the test is replaced, not repaired: we did not put
    # it there, so we do not know what else is in it.
    rm -rf "$_DEST" 2>/dev/null
    # THE TARBALL DOES NOT GET TO DECIDE WHO OWNS THE ENGINE, OR ITS MODES.
    #
    # Extracting as root, tar defaults to --same-owner and restores the modes
    # stored in the archive, ignoring umask entirely. Both defaults are wrong
    # here. An archive whose entries carry a non-root uid -- including the "./"
    # entry, which re-chowns the destination directory itself -- would leave
    # root about to exec files an unprivileged user owns, and that user could
    # swap them between extraction and exec. Observed directly: a fixture built
    # by a normal user produced a tenroot-owned engine directory.
    #
    # --no-same-owner  -> everything lands root-owned
    # --no-same-permissions -> modes come from our umask, not the archive
    #
    # Done at extraction rather than by chmod/chown afterwards, because those
    # leave a window in which the files exist with the wrong owner or mode.
    ( umask 077
      mkdir -p "$_DEST" || exit 1
      tar --no-same-owner --no-same-permissions -xzf "$_ENGINE_TAR" -C "$_DEST" 2>/dev/null \
          || tar --no-same-owner --no-same-permissions -xf "$_ENGINE_TAR" -C "$_DEST" 2>/dev/null ) \
        || _die "could not extract ${_ENGINE_TAR} to ${_DEST}"
    chmod 700 "$_DEST" 2>/dev/null || true
    # Keep the few most recent and drop the rest, so a box that has upgraded a
    # dozen times is not storing a dozen engines. Best-effort by design: a
    # failure to prune must never fail an upgrade.
    ls -1dt "${_ENGINE_ROOT}"/engine-* 2>/dev/null | tail -n +4 | while read -r _old; do
        [[ "$_old" == "$_DEST" ]] || rm -rf "$_old" 2>/dev/null
    done
fi

# Which of the target's scripts we are here to run. Both come out of the same
# asset, so both are the target release's own code -- which is the whole point:
# the release decides its own package shape AND how that shape is applied, and
# neither decision is made by the box that happens to be typing the command.
if (( _PREPARE )); then
    _TARGET="${_DEST}/scripts/prepare_package.sh"
    [[ -f "$_TARGET" ]] || _die "the ${_TAG} engine has no scripts/prepare_package.sh;
  this release cannot build its own carry-in package."
else
    _TARGET="${_DEST}/scripts/upgrade.sh"
    [[ -f "$_TARGET" ]] || _die "the engine tarball has no scripts/upgrade.sh — it is not an Intact.AI engine asset"
fi

# Refuse LOUDLY and specifically, rather than misparsing. This is the one
# branch that makes freezing this file safe.
_proto=1
[[ -f "${_DEST}/BOOTSTRAP_PROTOCOL" ]] && _proto="$(tr -cd '0-9' < "${_DEST}/BOOTSTRAP_PROTOCOL")"
_proto="${_proto:-1}"
if (( _proto > _BOOTSTRAP_KNOWS )); then
    _die "This appliance's upgrade bootstrap speaks protocol ${_BOOTSTRAP_KNOWS};
  the ${_TAG:-target} release requires protocol ${_proto}.

  This box is too old to be upgraded directly by that release. Upgrade to an
  intermediate release first, or apply this one from a shell using the
  package's own engine:
    sudo bash ${_DEST}/scripts/upgrade.sh --root ${_ROOT} <args>" 2
fi

# NOTHING GROUP- OR WORLD-WRITABLE MAY BE EXEC'D.
#
# scripts/upgrade.sh applies the same rule to its own libs and `chmod`s the
# problem away ("a group-writable lib/ is a privilege-escalation path"). Here we
# extracted the tree ourselves, under umask 077, into a root-only directory --
# so a writable file means an assumption has already failed. Refuse; do not
# repair. Repairing would hide whatever put it there.
_offender=""
while IFS= read -r _f; do
    _m="$(stat -c '%a' "$_f" 2>/dev/null)" || continue
    if [[ "$_m" =~ [2367]$|[2367][0-9]$ ]]; then _offender="$_f"; break; fi
done < <(find "$_DEST" -type f -name '*.sh' 2>/dev/null)
[[ -z "$_offender" ]] || _die "the extracted engine has a group- or world-writable file:
    ${_offender}
  Refusing to run it as root. Remove ${_DEST} and retry."

# Syntax-check before handing over. Nothing on the appliance has been touched
# at this point -- only a download and an extraction -- so a broken engine is
# refused for free here, instead of dying mid-module with no rollback.
bash -n "$_TARGET" 2>/dev/null \
    || _die "the ${_TAG:-target} engine's upgrade.sh does not parse as bash.
  This is a corrupt or truncated release asset, not a problem with this box."

# ---------------------------------------------------------------------------
# Handoff. A versioned FILE, not argv.
#
# argv was the old handover mechanism and it is a cross-release contract that
# changes: adding --reinstall broke every import of an earlier package until an
# allowlist was bolted on. A JSON file with a schema integer is additive -- the
# engine reads the keys it knows and ignores the rest -- so neither side has to
# guess what the other understands. Args are STILL forwarded for compatibility
# with engines that predate the file; the file is what new engines should read.
# ---------------------------------------------------------------------------
_HANDOFF="${_TMP}/upgrade-handoff-$$.json"
{
    printf '{\n'
    printf '  "schema": 1,\n'
    printf '  "bootstrap_protocol": %s,\n' "$_BOOTSTRAP_KNOWS"
    printf '  "appliance_root": "%s",\n' "$_ROOT"
    printf '  "engine_dir": "%s",\n'     "$_DEST"
    printf '  "engine_tarball": "%s",\n' "$_ENGINE_TAR"
    printf '  "target_tag": "%s",\n'     "${_TAG}"
    printf '  "package": "%s",\n'        "${_PKG}"
    printf '  "verified": true\n'
    printf '}\n'
} > "$_HANDOFF" 2>/dev/null || _HANDOFF=""

# --prepare: hand to the target's packager. Its signature is
# `prepare_package.sh <tag> [output_dir] [modules_csv]` -- positional, and it
# knows nothing of --root/--handoff, so those are not passed. The engine
# tarball carries no modules/, which is exactly right here: prepare_package.sh
# fetches the release's assets itself.
if (( _PREPARE )); then
    [[ -n "$_TAG" ]] || _die "--prepare needs a release tag: bootstrap_upgrade.sh <tag> --prepare [dir]"
    _say "building a ${_TAG} package with that release's own packager"
    _say "  ${_TARGET}  ->  ${_PREPARE_OUT}"
    # POSITIONAL, and _FWD is deliberately NOT forwarded. _FWD still contains
    # the tag (it is a positional, not a flag), so forwarding it would land the
    # tag in prepare_package.sh's third slot -- modules_csv -- and quietly build
    # a package for a module named "intact-20260813". Module selection is not
    # plumbed through this path yet; run the target's prepare_package.sh
    # directly from ${_DEST} if you need it.
    exec bash "$_TARGET" "$_TAG" "$_PREPARE_OUT"
fi

_say "handing over to the ${_TAG:-target} release's own upgrade engine"
_say "  ${_TARGET}"

export INTACT_UPGRADE_REEXEC=1
# --handoff is passed as a FLAG, not also as an env var. It used to be both;
# since this exec's directly the environment would survive, so the pair was
# redundant. The flag wins because it is visible in `ps` and in the launcher's
# recorded command, which is where anyone debugging a run will look.

_exec=(bash "$_TARGET" --root "$_ROOT")
[[ -n "$_HANDOFF" ]] && _exec+=(--handoff "$_HANDOFF")
exec "${_exec[@]}" "${_FWD[@]}"
