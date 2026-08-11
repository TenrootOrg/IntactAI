#!/bin/bash
# Intact.AI upgrade — command-line arguments.
#
# Sets, all deliberately global:
#   UPGRADE_TAG              release tag for an online upgrade ("" if air-gap)
#   UPGRADE_PACKAGE_ARGS     raw --package arguments
#   UPGRADE_ONLY             comma list, or ""
#   UPGRADE_SKIP             comma list, or ""
#   UPGRADE_REINSTALL        comma list of modules to re-apply even when they
#                            are already at the target version, or ""
#   UPGRADE_DRY_RUN          1 to verify and plan, then stop
#   UPGRADE_LIST             1 to list available releases and stop
#   UPGRADE_PLAN_TAG         release tag to plan against (cheap: manifest
#                            only), then stop -- "" for a real run
#   UPGRADE_JSON             1 to emit --list / --plan as JSON instead of
#                            the human table
#   UPGRADE_EXPECT_SHA256    operator-supplied digest anchor, or ""
#   UPGRADE_VELO_REFRESH_ONLY 1 to run only the Velociraptor refresh step
#   UPGRADE_PACKAGE_DIR      pre-extracted package (set by the stage-0 re-exec)

upgrade_usage() {
    cat <<'USAGE'
Usage:
  sudo bash scripts/upgrade.sh <tag>                    upgrade from a GitHub release
  sudo bash scripts/upgrade.sh --package <file|dir>...  upgrade from local assets
  sudo bash scripts/upgrade.sh --list                   show available releases
  sudo bash scripts/upgrade.sh --plan <tag>             show the plan for a release, cheaply

Options:
  --package <path>      A release asset, a directory of them, or a single-file
                        package. Repeatable. Implies no network access.
  --root <path>         The appliance to operate on. Defaults to wherever this
                        script itself lives. Only needed if you are running a
                        copy of upgrade.sh from somewhere other than the
                        appliance's own checkout -- the stage-0 hand-over uses
                        this internally; an operator normally never sets it.
  --dry-run             Verify the package and print the plan, change nothing.
  --plan <tag>          Fetch just the release's manifest (~0.2 MB, not the
                        payload) and print what --only/--skip would do to
                        each module without taking the upgrade lock. Only
                        works for a per-module release -- a legacy single-
                        bundle release embeds its manifest inside the
                        payload, so there is no cheap way to plan one.
  --json                With --list or --plan, print machine-readable JSON
                        instead of the human table.
  --only  <a,b>         Upgrade only these modules. Taken literally, including
                        when it omits 'intact' -- repairing or installing a
                        single module without touching the platform is a
                        legitimate thing to want from a shell. You are warned,
                        not overridden. The dashboard does NOT offer that
                        choice: it always includes intact.
  --skip  <a,b>         Upgrade everything except these.
  --reinstall <a,b>     Re-apply these modules even though they are already at
                        the target version. For repairing a module whose
                        upgrade half-landed, without moving any version.
                        Disjoint from the modules that are actually moving:
                        those need no flag, they are already in the plan.
  --expect-sha256 <hex> Refuse the package unless the archive matches.
  --velo-refresh        Run only the Velociraptor artifact/tool refresh step.
  --help                This text.

Modules: intact elk timesketch plaso iris velociraptor aws_sigma o365rc
         volweb portainer

Exit codes:
  0  everything upgraded cleanly (or there was nothing to do)
  1  at least one module was rolled back or needs manual repair
  2  refused before anything was touched
  3  everything applied, but at least one module is degraded
USAGE
}

parse_upgrade_args() {
    UPGRADE_TAG=""
    UPGRADE_PACKAGE_ARGS=()
    UPGRADE_ONLY=""
    UPGRADE_SKIP=""
    UPGRADE_REINSTALL=""
    UPGRADE_DRY_RUN=0
    UPGRADE_LIST=0
    UPGRADE_PLAN_TAG=""
    UPGRADE_JSON=0
    UPGRADE_EXPECT_SHA256=""
    UPGRADE_VELO_REFRESH_ONLY=0
    UPGRADE_PACKAGE_DIR=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --package)   UPGRADE_PACKAGE_ARGS+=("${2:-}"); shift 2 ;;
            --package=*) UPGRADE_PACKAGE_ARGS+=("${1#*=}"); shift ;;
            # Internal: the stage-0 re-exec hands the already-extracted tree to
            # the target release's own upgrade.sh so it is not re-downloaded,
            # re-verified and re-extracted a second time.
            --package-dir)   UPGRADE_PACKAGE_DIR="${2:-}"; shift 2 ;;
            --package-dir=*) UPGRADE_PACKAGE_DIR="${1#*=}"; shift ;;
            --log)       LOG_FILE="${2:-}"; shift 2 ;;
            --log=*)     LOG_FILE="${1#*=}"; shift ;;
            # Already consumed by the bootstrap's pre-scan (it has to resolve
            # SCRIPT_DIR before lib/upgrade/args.sh is even sourced). Accepted
            # here purely so it does not trip the -*) "Unknown option" case
            # below and does not get swallowed as the release tag.
            --root)      shift 2 ;;
            --root=*)    shift ;;
            --only)      UPGRADE_ONLY="${2:-}"; shift 2 ;;
            --only=*)    UPGRADE_ONLY="${1#*=}"; shift ;;
            --skip)      UPGRADE_SKIP="${2:-}"; shift 2 ;;
            --skip=*)    UPGRADE_SKIP="${1#*=}"; shift ;;
            --reinstall)   UPGRADE_REINSTALL="${2:-}"; shift 2 ;;
            --reinstall=*) UPGRADE_REINSTALL="${1#*=}"; shift ;;
            --expect-sha256)   UPGRADE_EXPECT_SHA256="${2:-}"; shift 2 ;;
            --expect-sha256=*) UPGRADE_EXPECT_SHA256="${1#*=}"; shift ;;
            --dry-run)      UPGRADE_DRY_RUN=1; shift ;;
            --list)         UPGRADE_LIST=1; shift ;;
            --plan)         UPGRADE_PLAN_TAG="${2:-}"; shift 2 ;;
            --plan=*)       UPGRADE_PLAN_TAG="${1#*=}"; shift ;;
            --json)         UPGRADE_JSON=1; shift ;;
            --velo-refresh) UPGRADE_VELO_REFRESH_ONLY=1; shift ;;
            # Recognized and ignored, not an error: this engine never
            # prompts (unlike install.sh, where --yes/-y suppresses a real
            # confirmation), so there is nothing for it to do -- but an
            # operator scripting `upgrade.sh --yes ...` out of install.sh
            # habit should not hit "Unknown option" for it.
            --yes|-y)       shift ;;
            --help|-h)      upgrade_usage; exit 0 ;;
            -*)
                echo "Unknown option: $1" >&2
                echo "Try: sudo bash scripts/upgrade.sh --help" >&2
                exit 2 ;;
            *)
                if [[ -n "$UPGRADE_TAG" ]]; then
                    echo "More than one release tag given: '${UPGRADE_TAG}' and '$1'" >&2
                    exit 2
                fi
                UPGRADE_TAG="$1"; shift ;;
        esac
    done

    # Normalise the module lists so plan.sh's ",${list}," membership test does
    # not have to cope with spaces after commas.
    UPGRADE_ONLY="$(tr -d '[:space:]' <<< "$UPGRADE_ONLY")"
    UPGRADE_SKIP="$(tr -d '[:space:]' <<< "$UPGRADE_SKIP")"
    UPGRADE_REINSTALL="$(tr -d '[:space:]' <<< "$UPGRADE_REINSTALL")"

    _validate_module_list "$UPGRADE_ONLY" --only || exit 2
    _validate_module_list "$UPGRADE_SKIP" --skip || exit 2
    _validate_module_list "$UPGRADE_REINSTALL" --reinstall || exit 2

    if (( UPGRADE_LIST )); then
        return 0
    fi
    if [[ -n "$UPGRADE_PLAN_TAG" ]]; then
        if [[ -n "$UPGRADE_TAG" || ${#UPGRADE_PACKAGE_ARGS[@]} -gt 0 ]]; then
            echo "--plan is its own read-only mode -- give it a tag, not a release tag or --package too." >&2
            exit 2
        fi
        return 0
    fi
    if (( UPGRADE_JSON )); then
        echo "--json only means something with --list or --plan." >&2
        exit 2
    fi
    if [[ -n "$UPGRADE_TAG" && ${#UPGRADE_PACKAGE_ARGS[@]} -gt 0 ]]; then
        echo "Give a release tag OR --package, not both." >&2
        exit 2
    fi
    if [[ -z "$UPGRADE_TAG" && ${#UPGRADE_PACKAGE_ARGS[@]} -eq 0 && -z "$UPGRADE_PACKAGE_DIR" ]]; then
        echo "Nothing to upgrade to: give a release tag or --package." >&2
        echo "Try: sudo bash scripts/upgrade.sh --list" >&2
        exit 2
    fi
    return 0
}

# A typo'd module name must not silently upgrade nothing. `--only timesketh`
# would otherwise produce a clean, honest-looking "nothing to do" run.
_validate_module_list() {
    local list="$1" flag="$2" m known
    [[ -n "$list" ]] || return 0
    local IFS=','
    for m in $list; do
        known=0
        for k in "${UPGRADE_ORDER[@]}"; do [[ "$m" == "$k" ]] && { known=1; break; }; done
        if (( ! known )); then
            echo "${flag}: unknown module '${m}'" >&2
            echo "Known modules: ${UPGRADE_ORDER[*]}" >&2
            return 1
        fi
    done
    return 0
}
