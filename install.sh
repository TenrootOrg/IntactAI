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

# Order matters only for the top-level VARIABLE definitions each file makes
# (INTACT_HOST_DEPS, INTACT_MIN_DOCKER_VERSION, INTACT_MODULE_DISPLAY, ...);
# bash resolves function calls at call time, so cross-file calls between these
# are fine in any direction.
source "${SCRIPT_DIR}/lib/common.sh"
source "${SCRIPT_DIR}/lib/config.sh"
source "${SCRIPT_DIR}/lib/deps.sh"
source "${SCRIPT_DIR}/lib/docker.sh"
source "${SCRIPT_DIR}/lib/modules.sh"
source "${SCRIPT_DIR}/lib/health.sh"
source "${SCRIPT_DIR}/lib/args.sh"
source "${SCRIPT_DIR}/lib/package.sh"
source "${SCRIPT_DIR}/lib/release.sh"
source "${SCRIPT_DIR}/lib/permissions.sh"

# ============================================================================
# Command Line
# ============================================================================

parse_install_args "$@"

# ============================================================================
# Main Installation Flow
# ============================================================================

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

    # -------------------------------------------------------------------------
    # Core Dependencies — network check, the release's Docker/dependency
    # bundle if it has one, and Docker itself. Runs BEFORE any image loading
    # below: this used to run after load_images_from_package(), so on a
    # genuinely fresh box (docker never installed), the early DOCKER_BIN
    # resolution above found nothing, "docker load" failed with "docker:
    # command not found", and the code that would have INSTALLED docker never
    # even ran yet. Extracted to lib/deps.sh so it can be driven by a test
    # across every online/air-gap/bundle-present/bundle-missing branch.
    # -------------------------------------------------------------------------
    ensure_core_dependencies

    # -------------------------------------------------------------------------
    # Release Assets — Docker is guaranteed present and verified above.
    # -------------------------------------------------------------------------
    if [[ "$INTACT_AIRGAP" == "1" ]]; then
        if ! load_images_from_package "${INTACT_PACKAGES[@]}"; then
            log_error "Could not load the release assets - aborting installation"
            exit 1
        fi
        # Copies we made while unwrapping a single-file package; the images are
        # in the docker store now. The operator's own file is left alone.
        if (( ${#INTACT_UNWRAP_DIRS[@]} > 0 )); then
            rm -rf "${INTACT_UNWRAP_DIRS[@]}" 2>/dev/null || true
        fi
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
