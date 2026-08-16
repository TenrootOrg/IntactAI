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

Fetches the target release's upgrade engine, verifies it, and hands over to it.
Every other flag is passed through to that engine untouched.

  --root <dir>     the appliance to act on (default: this script's checkout)
  --engine <file>  use this engine tarball instead of fetching one (air-gap)
  --no-verify      skip the sha256 check. Only for a locally built engine.
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
# contract in the first place (see _U_DROPPABLE_OPTS in scripts/upgrade.sh).
# ---------------------------------------------------------------------------
_TAG=""; _ROOT=""; _ENGINE=""; _PKG=""; _LOG=""; _VERIFY=1
_ARGS=("$@")
_i=0
while (( _i < $# )); do
    _a="${_ARGS[$_i]}"
    case "$_a" in
        -h|--help)   _usage; exit 0 ;;
        --root)      _ROOT="${_ARGS[$((_i+1))]:-}"; _i=$((_i+1)) ;;
        --root=*)    _ROOT="${_a#*=}" ;;
        --engine)    _ENGINE="${_ARGS[$((_i+1))]:-}"; _i=$((_i+1)) ;;
        --engine=*)  _ENGINE="${_a#*=}" ;;
        --package)   _PKG="${_ARGS[$((_i+1))]:-}"; _i=$((_i+1)) ;;
        --package=*) _PKG="${_a#*=}" ;;
        --log)       _LOG="${_ARGS[$((_i+1))]:-}"; _i=$((_i+1)) ;;
        --log=*)     _LOG="${_a#*=}" ;;
        --no-verify) _VERIFY=0 ;;
        -*)          : ;;                       # someone else's flag; pass it on
        *)           [[ -z "$_TAG" ]] && _TAG="$_a" ;;
    esac
    _i=$((_i+1))
done

# Strip only the flags THIS script owns and re-emits itself.
#
#   --engine / --no-verify   ours alone; the target engine has never heard of
#                            them and exits 2 on "Unknown option".
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
        --no-verify)                        : ;;
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
[[ -f "${_ROOT}/config.yaml" ]] || _warn "no config.yaml under ${_ROOT} — is that the appliance root?"

_TMP="${_ROOT}/data/tmp"
mkdir -p "$_TMP" 2>/dev/null || _die "cannot write ${_TMP}"

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
    curl -fLsS --retry 3 --retry-delay 2 --max-time 300 -o "$dest" "$url" 2>/dev/null || return 1
    curl -fLsS --retry 3 --max-time 60 -o "${dest}.sha256" "${url}.sha256" 2>/dev/null \
        || _warn "no ${fname}.sha256 published; cannot verify what was downloaded"
    printf '%s' "$dest"
}

# ---------------------------------------------------------------------------
# No engine asset to be had -> hand straight back to the caller's own engine.
#
# Releases published before <tag>-engine.tar.gz existed have no such asset, and
# an air-gapped operator may be holding one of them on a USB stick for months.
# Refusing those would turn a design improvement into an outage, so the absence
# of the new asset is a fallback, not an error: the caller re-runs its own
# acquire + late-hop path, which is exactly what it did before this file
# existed. INTACT_UPGRADE_LEGACY is what stops it bouncing back here forever.
# ---------------------------------------------------------------------------
_fall_back_to_caller() {
    local caller="${INTACT_UPGRADE_CALLER:-}"
    [[ -f "$caller" ]] || _die "no ${_TAG:+${_TAG} }engine asset could be found or fetched,
  and there is no local upgrade engine to fall back to.
  Apply this release from a shell using its own checkout:
    sudo bash <checkout>/scripts/upgrade.sh ${_TAG}"

    _warn "no engine asset for ${_TAG:-this package} — it predates the split-out"
    _warn "  engine. Falling back to this appliance's own upgrade engine, which"
    _warn "  will hand over from inside the package as it did before."
    export INTACT_UPGRADE_LEGACY=1
    exec bash "$caller" --root "$_ROOT" "${_FWD[@]}"
}

_ENGINE_TAR="$(_find_engine)" || _ENGINE_TAR=""
[[ -f "$_ENGINE_TAR" ]] || _fall_back_to_caller

# ---------------------------------------------------------------------------
# Verify. This is about to be given root, so a missing checksum is a decision
# the operator makes explicitly, not a default.
# ---------------------------------------------------------------------------
if (( _VERIFY )); then
    _sha_file=""
    for _c in "${_ENGINE_TAR}.sha256" "$(dirname "$_ENGINE_TAR")/$(basename "$_ENGINE_TAR").sha256"; do
        [[ -f "$_c" ]] && { _sha_file="$_c"; break; }
    done
    if [[ -n "$_sha_file" ]] && command -v sha256sum >/dev/null 2>&1; then
        _want="$(awk '{print $1; exit}' "$_sha_file" 2>/dev/null)"
        _got="$(sha256sum "$_ENGINE_TAR" 2>/dev/null | awk '{print $1}')"
        if [[ -z "$_want" || "$_want" != "$_got" ]]; then
            _die "engine checksum mismatch — refusing to run it.
  expected ${_want:-<unreadable>}
  got      ${_got:-<unreadable>}
  Re-download the release, or pass --no-verify if you built this engine yourself."
        fi
        _say "engine verified (sha256 ${_got:0:16}…)"
    else
        _warn "no sha256 beside the engine tarball; running it unverified"
    fi
fi

# ---------------------------------------------------------------------------
# Extract and check the protocol.
# ---------------------------------------------------------------------------
_DEST="${_TMP}/engine-${_TAG:-pkg}.$$"
rm -rf "$_DEST" 2>/dev/null
mkdir -p "$_DEST" 2>/dev/null || _die "cannot create ${_DEST}"
tar -xzf "$_ENGINE_TAR" -C "$_DEST" 2>/dev/null \
    || tar -xf "$_ENGINE_TAR" -C "$_DEST" 2>/dev/null \
    || _die "could not extract ${_ENGINE_TAR}"

_TARGET="${_DEST}/scripts/upgrade.sh"
[[ -f "$_TARGET" ]] || _die "the engine tarball has no scripts/upgrade.sh — it is not an Intact.AI engine asset"

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
    printf '  "verified": %s\n'          "$( ((_VERIFY)) && echo true || echo false )"
    printf '}\n'
} > "$_HANDOFF" 2>/dev/null || _HANDOFF=""

_say "handing over to the ${_TAG:-target} release's own upgrade engine"
_say "  ${_TARGET}"

export INTACT_UPGRADE_REEXEC=1
export INTACT_UPGRADE_HANDOFF="$_HANDOFF"
export INTACT_UPGRADE_ENGINE_DIR="$_DEST"

_exec=(bash "$_TARGET" --root "$_ROOT")
[[ -n "$_HANDOFF" ]] && _exec+=(--handoff "$_HANDOFF")
exec "${_exec[@]}" "${_FWD[@]}"
