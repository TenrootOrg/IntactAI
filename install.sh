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
source "${SCRIPT_DIR}/lib/upgrade_check.sh"

# ============================================================================
# Main Installation Flow
# ============================================================================

# ---------------------------------------------------------------------------
# Air-gap: install from a release package instead of the internet.
#
#   sudo bash install.sh --package /path/to/intact-upgrade-<tag>-full.tar.gz
#
# The package carries every image this release needs as a tar. Loading them up
# front means _pull_image_with_retry finds each one already in the local store
# and skips the registry -- so every existing deploy_* path works offline with
# no changes of its own. That is the whole trick; there is no separate offline
# code path to keep in step with the online one.
#
# Use the FULL asset. A delta contains only the modules whose pins moved since
# the previous release, which is meaningless for a box that has nothing
# installed yet.
INTACT_PACKAGE=""
INTACT_AIRGAP=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --package)
            INTACT_PACKAGE="${2:-}"; INTACT_AIRGAP=1; shift 2 ;;
        --package=*)
            INTACT_PACKAGE="${1#*=}"; INTACT_AIRGAP=1; shift ;;
        --help|-h)
            echo "Usage: sudo bash install.sh [--package <full-release-package.tar.gz>]"
            echo ""
            echo "  --package  install offline from a release package; no registry"
            echo "             access is attempted. Use the -full asset, not -delta."
            exit 0 ;;
        *)
            echo "Unknown argument: $1" >&2
            echo "Usage: sudo bash install.sh [--package <package.tar.gz>]" >&2
            exit 2 ;;
    esac
done
export INTACT_AIRGAP

# Load every image out of the package into the local docker store.
#
# Idempotent and non-fatal per image: `docker load` on an image that is already
# present is a no-op, and one unreadable tar should not abort an install that
# may not even need that module. What DOES abort is a package that yields no
# images at all -- that is a wrong or corrupt file, and continuing would fall
# through to registry pulls that cannot work on an air-gapped box.
load_images_from_package() {
    local pkg="$1"
    if [[ ! -f "$pkg" ]]; then
        log_error "Package not found: $pkg"
        return 1
    fi
    log_info "Air-gapped install from $(basename "$pkg")"

    local kind
    kind="$(tar -xzOf "$pkg" --wildcards '*/manifest.json' 2>/dev/null \
            | python3 -c 'import json,sys;print((json.load(sys.stdin).get("contents") or {}).get("package_kind","full"))' 2>/dev/null || echo full)"
    if [[ "$kind" == "delta" ]]; then
        log_error "This is a DELTA package. It carries only the modules whose"
        log_error "versions moved since the previous release, so it cannot install"
        log_error "a box from scratch. Use the -full asset."
        return 1
    fi

    local work; work="$(mktemp -d)"
    log_info "  Extracting images (this takes a few minutes for a full package)..."
    if ! tar -xzf "$pkg" -C "$work" 2>>"$LOG_FILE"; then
        log_error "  Could not extract $pkg"
        rm -rf "$work"; return 1
    fi

    local loaded=0 failed=0 tar_file
    while IFS= read -r tar_file; do
        if docker load -i "$tar_file" >>"$LOG_FILE" 2>&1; then
            loaded=$((loaded + 1))
        else
            failed=$((failed + 1))
            log_warn "  Could not load $(basename "$tar_file")"
        fi
    done < <(find "$work" -type f -name '*.tar' 2>/dev/null)

    # Images are not the only thing an air-gapped box cannot fetch. The
    # installer also downloads Velociraptor binaries (current + legacy clients,
    # the offline collector) and clones SigmaHQ. Deliver whatever the package
    # carries so the download_* functions find their work already done; each of
    # them reports honestly if something is genuinely absent.
    local dl_dir="${SCRIPT_DIR}/modules/nginx/html/downloads"
    local staged_bin=0 bin
    mkdir -p "$dl_dir"
    while IFS= read -r bin; do
        if cp -n "$bin" "$dl_dir/" 2>/dev/null; then staged_bin=$((staged_bin + 1)); fi
    done < <(find "$work" -type d -name binaries -exec find {} -type f \; 2>/dev/null)
    if (( staged_bin > 0 )); then
        chmod 755 "$dl_dir"/* 2>/dev/null || true   # 755, not +x: umask filters symbolic modes
        log_success "  Staged $staged_bin Velociraptor binary/binaries from the package"
    fi

    local sigma_src
    sigma_src="$(find "$work" -type d -name 'sigma*' -maxdepth 4 2>/dev/null | head -1)"
    if [[ -n "$sigma_src" && ! -d /opt/sigma-rules/rules ]]; then
        mkdir -p /opt/sigma-rules
        cp -rn "$sigma_src"/. /opt/sigma-rules/ 2>/dev/null \
            && log_success "  Staged SIGMA rules from the package"
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
    # Loading is not installing. config.yaml's per-module `enabled` flag still
    # decides what gets deployed, exactly as on an online install -- a full
    # package deliberately carries images for modules this box has turned OFF,
    # so one can be enabled later and installed with no route to a registry.
    # Said out loud because "20 images loaded, 6 modules running" otherwise
    # reads as something having gone wrong.
    log_info "  Images are now local; config.yaml's enabled flags still decide"
    log_info "  which modules are deployed. Disabled modules keep their images"
    log_info "  on disk so they can be enabled later without internet access."
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
        if ! load_images_from_package "$INTACT_PACKAGE"; then
            log_error "Could not load the release package - aborting installation"
            exit 1
        fi
    elif ! check_network_connectivity; then
        log_error "Network connectivity check failed - aborting installation"
        exit 1
    fi

    # -------------------------------------------------------------------------
    # Optional: poll upstream for newer module releases and offer to bump
    # the pinned versions in config.yaml. Controlled by
    # options.check_module_updates in config.yaml; default false so an
    # unattended install never blocks on a prompt. Must run AFTER
    # check_config (config.yaml exists + parses) and AFTER the network
    # check (we're about to hit api.github.com), but BEFORE any module
    # is deployed, so the new pins drive the install.
    # -------------------------------------------------------------------------
    local check_updates_flag
    check_updates_flag=$(read_config "['options']['check_module_updates']")
    if [[ "$check_updates_flag" == "True" ]]; then
        # Pre-flight: check_module_updates polls api.github.com once
        # per pinned module (6 calls today). Refuse early if quota is
        # too low so the operator gets a clear "wait N minutes" message
        # instead of a confusing 403 mid-poll.
        if ! check_github_quota 6 "module update check"; then
            log_warn "  Skipping update check; install will proceed with pinned versions"
        else
            check_module_updates
        fi
        echo ""
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
    pull_dfir_o365rc_image
    generate_azure_certificate

    # -------------------------------------------------------------------------
    # AWS DFIR (CloudTrail + SIGMA) — native, no image to pull. boto3 is
    # installed into the backend by install_deps.py; the SIGMA AWS rule pack
    # is fetched by download_sigma_rules() above when the cloudtrail (or
    # azure) module is enabled in config.yaml.

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
    find "${SCRIPT_DIR}/modules" -type f \( -path "*/secrets/*" -o -name ".env" \) -exec chmod 600 {} \; 2>/dev/null || true
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
