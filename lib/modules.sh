#!/bin/bash
# Intact.AI Platform Installer - Module Deployment Functions
# Service startup and module management

# ============================================================================
# Security Credentials Generation
# ============================================================================

generate_iris_secrets() {
    # IRIS-disabled guard — without this, fresh installs with
    # `modules.iris.enabled: false` still write 5 secret files into
    # `modules/iris/secrets/` and pull config values for a module the
    # operator turned off. Same `is_enabled` pattern as the rest.
    local iris_enabled
    iris_enabled=$(read_config "['modules']['iris']['enabled']")
    if ! is_enabled "$iris_enabled"; then
        log_info "Generating IRIS secrets: SKIPPED (disabled in config)"
        return 0
    fi
    log_info "Generating IRIS secrets..."
    local secrets_dir="${SCRIPT_DIR}/modules/iris/secrets"
    mkdir -p "$secrets_dir"

    local secrets_created=false

    # IRIS_ADM_PASSWORD comes from config.yaml when the operator set one;
    # otherwise generate a random per-install password instead of shipping
    # the same fixed, publicly-documented string to every default install
    # (the same pattern used for the Portainer admin password below).
    if [[ ! -f "$secrets_dir/IRIS_ADM_PASSWORD" ]] || [[ ! -s "$secrets_dir/IRIS_ADM_PASSWORD" ]]; then
        local iris_password=$(read_config "['modules']['iris']['password']")
        if [[ -n "$iris_password" && "$iris_password" != "None" ]]; then
            echo -n "$iris_password" > "$secrets_dir/IRIS_ADM_PASSWORD"
            log_info "  Created IRIS_ADM_PASSWORD from config.yaml"
        else
            iris_password=$(openssl rand -hex 16)
            echo -n "$iris_password" > "$secrets_dir/IRIS_ADM_PASSWORD"
            log_warn "  No IRIS password set in config.yaml; generated a random one instead"
            log_warn "  Retrieve it with: cat ${secrets_dir}/IRIS_ADM_PASSWORD"
        fi
        secrets_created=true
    else
        log_info "  IRIS_ADM_PASSWORD exists, skipping"
    fi
    if [[ ! -f "$secrets_dir/IRIS_SECRET_KEY" ]] || [[ ! -s "$secrets_dir/IRIS_SECRET_KEY" ]]; then
        openssl rand -hex 32 > "$secrets_dir/IRIS_SECRET_KEY"
        log_info "  Created IRIS_SECRET_KEY"
        secrets_created=true
    fi
    if [[ ! -f "$secrets_dir/IRIS_SECURITY_PASSWORD_SALT" ]] || [[ ! -s "$secrets_dir/IRIS_SECURITY_PASSWORD_SALT" ]]; then
        openssl rand -hex 32 > "$secrets_dir/IRIS_SECURITY_PASSWORD_SALT"
        log_info "  Created IRIS_SECURITY_PASSWORD_SALT"
        secrets_created=true
    fi
    if [[ ! -f "$secrets_dir/POSTGRES_ADMIN_PASSWORD" ]] || [[ ! -s "$secrets_dir/POSTGRES_ADMIN_PASSWORD" ]]; then
        openssl rand -hex 32 > "$secrets_dir/POSTGRES_ADMIN_PASSWORD"
        log_info "  Created POSTGRES_ADMIN_PASSWORD"
        secrets_created=true
    fi
    if [[ ! -f "$secrets_dir/POSTGRES_PASSWORD" ]] || [[ ! -s "$secrets_dir/POSTGRES_PASSWORD" ]]; then
        openssl rand -hex 32 > "$secrets_dir/POSTGRES_PASSWORD"
        log_info "  Created POSTGRES_PASSWORD"
        secrets_created=true
    fi

    # Ensure all secrets are flushed to disk before containers try to read them
    if [[ "$secrets_created" == "true" ]]; then
        sync
        sleep 1
    fi

    # Verify all secrets exist and have content
    local all_ok=true
    for secret in IRIS_ADM_PASSWORD IRIS_SECRET_KEY IRIS_SECURITY_PASSWORD_SALT POSTGRES_ADMIN_PASSWORD POSTGRES_PASSWORD; do
        if [[ ! -s "$secrets_dir/$secret" ]]; then
            log_error "  Secret file missing or empty: $secret"
            all_ok=false
        fi
    done

    if [[ "$all_ok" == "true" ]]; then
        log_success "IRIS secrets ready"
    else
        log_error "IRIS secrets generation failed!"
        return 1
    fi
}

generate_portainer_secrets() {
    # Portainer CE locks itself after a 5-minute "initial setup" window if no
    # admin account is created. Seed the admin account via --admin-password-file
    # so the very first container boot skips the interactive setup entirely
    # and the install works unattended.
    log_info "Generating Portainer secrets..."
    local secrets_dir="${SCRIPT_DIR}/modules/portainer/secrets"
    mkdir -p "$secrets_dir"

    if [[ ! -s "$secrets_dir/admin_password" ]]; then
        local portainer_password
        portainer_password=$(read_config "['modules']['portainer']['password']")
        # Portainer enforces a 12-character minimum even when the password is
        # seeded via --admin-password-file. Short values silently cause the
        # admin user to never be created and the UI falls back to the
        # timed-out "initial setup" state — exactly what we're trying to avoid.
        if [[ -z "$portainer_password" || "$portainer_password" == "None" || ${#portainer_password} -lt 12 || "$portainer_password" == "1234qwer!@#\$" ]]; then
            # A hardcoded fallback here would ship the same publicly-known
            # password to every default install (the exact string is visible
            # in this open-source file) — generate a random one instead, the
            # same way every other auto-provisioned secret in this codebase
            # is handled (see IRIS_SECRET_KEY / POSTGRES_*_PASSWORD above).
            portainer_password=$(openssl rand -hex 16)
            log_warn "  Portainer password missing or < 12 chars in config.yaml; generated a random one instead"
            log_warn "  Retrieve it with: cat ${secrets_dir}/admin_password"
            log_warn "  Change it from the Portainer UI after first login (Settings -> Users)"
        fi
        printf '%s' "$portainer_password" > "$secrets_dir/admin_password"
        chmod 600 "$secrets_dir/admin_password"
        sync
        log_info "  Created Portainer admin password file"
    else
        log_info "  Portainer admin password file exists, skipping"
    fi

    log_success "Portainer secrets ready"
}

# Generates the HTTP Basic Auth credentials nginx.conf's server-level
# auth_basic gates the whole site with (dashboard, /api/, /api/uploads/,
# /velociraptor/ — see modules/nginx/config/nginx.conf). Without this, the
# entire backend API and the unauthenticated-tus-upload proxy are reachable
# by anyone who can route to the published port (CWE-306).
#
# The htpasswd file must be readable by the nginx WORKER process, which is
# what actually evaluates auth_basic per request. The nginx:alpine image is
# compiled with --user=nginx --group=nginx (uid/gid 101; verified via
# `nginx -V` / `id nginx` inside the image) and our custom nginx.conf never
# overrides `user`, so workers always run as uid/gid 101 regardless of who
# generated the file. Owning the file root:101 mode 640 (mirrors the
# root:33/640 pattern already used for the IRIS web TLS key, gid 33 being
# iris-nginx's www-data) lets the worker read it without making it
# world-readable on the host.
# Write the plaintext + htpasswd pair for one user/password.
#
# SHA-1 htpasswd format ("{SHA}<base64 of sha1 digest>") — supported
# natively by nginx's auth_basic module, no extra tooling needed beyond
# openssl (already a hard dependency of this installer). Piped via stdin so
# the plaintext password never appears as a process argument (visible to any
# local user via `ps`).
#
# Both files are written with `>` (truncate in place, same inode) because
# docker bind-mounts them BY PATH — replacing the inode would leave the
# running nginx pinned to the old file and the new password silently inert.
_write_nginx_htpasswd() {
    local user="$1" password="$2" password_file="$3" htpasswd_file="$4"

    printf '%s' "$password" > "$password_file"
    chmod 600 "$password_file"

    local sha1_b64
    sha1_b64=$(printf '%s' "$password" | openssl dgst -sha1 -binary | openssl base64 -A)
    printf '%s:{SHA}%s\n' "$user" "$sha1_b64" > "$htpasswd_file"
    chown root:101 "$htpasswd_file" 2>/dev/null || true
    chmod 640 "$htpasswd_file"
}

generate_nginx_secrets() {
    log_info "Generating Nginx Basic Auth secrets..."
    local secrets_dir="${SCRIPT_DIR}/modules/nginx/secrets"
    mkdir -p "$secrets_dir"
    local password_file="$secrets_dir/nginx_basic_auth_password"
    local htpasswd_file="$secrets_dir/htpasswd"

    # config.yaml is AUTHORITATIVE whenever the operator fills in
    # dashboard.password: the htpasswd is rewritten on EVERY run, so editing
    # config.yaml and re-running install/upgrade actually changes the login
    # (same contract as the IRIS admin password). Left empty — the shipped
    # default — we keep the previous behaviour: generate a random secret once
    # and never touch it again, so an existing box is never locked out by an
    # upgrade silently rotating its password.
    local dash_user dash_password
    dash_user=$(read_config "['dashboard']['id']")
    dash_password=$(read_config "['dashboard']['password']")
    [[ -z "$dash_user" || "$dash_user" == "None" ]] && dash_user="admin"
    [[ "$dash_password" == "None" ]] && dash_password=""

    if [[ -n "$dash_password" ]]; then
        _write_nginx_htpasswd "$dash_user" "$dash_password" "$password_file" "$htpasswd_file"
        log_info "  Nginx Basic Auth password set from config.yaml (username: ${dash_user})"
    elif [[ ! -s "$password_file" || ! -s "$htpasswd_file" ]]; then
        local nginx_password
        nginx_password=$(openssl rand -hex 16)
        _write_nginx_htpasswd "$dash_user" "$nginx_password" "$password_file" "$htpasswd_file"

        log_warn "  Generated a random Nginx dashboard/API Basic Auth password (username: ${dash_user})"
        log_warn "  Retrieve it with: cat ${password_file}"
        log_warn "  Set dashboard.password in config.yaml to choose your own instead."
    else
        log_info "  Nginx Basic Auth secrets exist, skipping"
        # Re-assert ownership/mode on every run — a prior fix_source_permissions
        # sweep (or a manually-copied file) could have left this owned by the
        # invoking user instead of root:101, which would 500 every request.
        chown root:101 "$htpasswd_file" 2>/dev/null || true
        chmod 640 "$htpasswd_file" 2>/dev/null || true
    fi

    log_success "Nginx Basic Auth secrets ready"
}

generate_certificates() {
    log_info "Generating SSL certificates..."
    local domain="${DOMAIN:-localhost}"

    # Nginx SSL
    local nginx_ssl="${SCRIPT_DIR}/modules/nginx/ssl"
    mkdir -p "$nginx_ssl"
    # FORCE_CERT_REGEN=1 (set by change_ip.sh) regenerates even when the cert
    # already exists. Critically, we regenerate IN PLACE: `openssl -out <file>`
    # truncates the existing file, keeping its inode — so containers that
    # bind-mount the cert file see the new content and pick it up on a plain
    # restart. If we instead `rm`+recreate (new inode), the bind mount stays
    # pinned to the deleted inode and a restart serves the OLD cert forever —
    # only a full container recreate would help. So change_ip MUST set
    # FORCE_CERT_REGEN=1 and must NOT `rm` the cert first.
    if [[ ! -f "$nginx_ssl/nginx-cert.crt" || "${FORCE_CERT_REGEN:-0}" == "1" ]]; then
        log_info "  Generating Nginx SSL certificate for domain: $domain"
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout "$nginx_ssl/nginx-cert.key" \
            -out "$nginx_ssl/nginx-cert.crt" \
            -subj "/CN=$domain/O=Intact.AI/C=US" 2>/dev/null
        log_success "  Generated Nginx SSL certificate"
    else
        log_info "  Nginx SSL certificate exists, skipping"
    fi
    # Make the key group-readable (640, group root/gid 0) so containers that
    # run as a non-root uid but are members of gid 0 — notably Kibana (uid
    # 1000) which serves HTTPS natively from this same shared cert — can read
    # it. Still NOT world-readable. openssl creates the key 600 by default, so
    # this must run on every (re)generation, including change_ip.sh's regen.
    [[ -f "$nginx_ssl/nginx-cert.key" ]] && chmod 640 "$nginx_ssl/nginx-cert.key" 2>/dev/null || true

    # IRIS Root CA + web cert sync — gated on iris.enabled so disabled
    # installs don't end up with a CA + a cert pair on disk for a module
    # they explicitly turned off. Nginx + Portainer cert generation above
    # stays unconditional.
    local iris_enabled
    iris_enabled=$(read_config "['modules']['iris']['enabled']")
    if is_enabled "$iris_enabled"; then
        local iris_ca="${SCRIPT_DIR}/modules/iris/config/certificates/rootCA"
        mkdir -p "$iris_ca"
        if [[ ! -f "$iris_ca/irisRootCACert.pem" ]]; then
            log_info "  Generating IRIS Root CA..."
            openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
                -keyout "$iris_ca/irisRootCAKey.pem" \
                -out "$iris_ca/irisRootCACert.pem" \
                -subj "/CN=IRIS Root CA/O=Intact.AI/C=US" 2>/dev/null
            log_success "  Generated IRIS Root CA"
        else
            log_info "  IRIS Root CA exists, skipping"
        fi

        # IRIS Web Cert — shared with Nginx (same cert, copied to IRIS path)
        local iris_web="${SCRIPT_DIR}/modules/iris/config/certificates/web_certificates"
        mkdir -p "$iris_web"
        if [[ -f "$nginx_ssl/nginx-cert.crt" ]]; then
            log_info "  Copying shared TLS certificate to IRIS..."
            cp "$nginx_ssl/nginx-cert.crt" "$iris_web/iris_dev_cert.pem"
            chmod 644 "$iris_web/iris_dev_cert.pem"
            cp "$nginx_ssl/nginx-cert.key" "$iris_web/iris_dev_key.pem"
            # iris-nginx (ghcr.io/dfir-iris/iriswebapp_nginx) runs as
            # www-data (uid/gid 33), not root, so it doesn't need — and must
            # not get — world-read access to this shared private key. Own it
            # root:33 and restrict to group-read (640), matching the
            # restriction already applied to the source nginx-cert.key.
            chown root:33 "$iris_web/iris_dev_key.pem" 2>/dev/null || true
            chmod 640 "$iris_web/iris_dev_key.pem"
            log_success "  IRIS web certificate synced with Nginx certificate"
        fi

        # Ensure IRIS certificates are readable (fix permissions if needed).
        # Cert stays world-readable; the private key stays group-restricted
        # to the iris-nginx container's gid (33), never world-readable.
        if [[ -d "$iris_web" ]]; then
            [[ -f "$iris_web/iris_dev_cert.pem" ]] && chmod 644 "$iris_web/iris_dev_cert.pem" 2>/dev/null || true
            if [[ -f "$iris_web/iris_dev_key.pem" ]]; then
                chown root:33 "$iris_web/iris_dev_key.pem" 2>/dev/null || true
                chmod 640 "$iris_web/iris_dev_key.pem" 2>/dev/null || true
            fi
        fi
    else
        log_info "  IRIS disabled — skipping IRIS Root CA + web cert sync"
    fi
}

# ============================================================================
# Helper: Show docker compose output with logging
# ============================================================================

run_docker_compose() {
    local action="$1"
    local module_name="$2"
    # Allow callers to override the build timeout per module. Default is
    # 1800s (30 min) — sized for slow-network customer installs where the
    # Backend image's ~200 MB of downloads (base image + 141 MB apt + pip)
    # can take 15+ min at 200 kB/s. Velociraptor's smaller surface still
    # passes its own 600s override.
    local build_timeout="${3:-1800}"

    log_info "  Running: docker compose $action"

    # Run docker compose with cleaner output (filter out noisy progress)
    if [[ "$action" == "build" ]]; then
        # Wrap with heartbeat + hard timeout. Catches the silent-stop failure
        # mode where a build hangs with no log output and the operator can't
        # tell whether the script froze or is making progress.
        local cwd="$PWD"
        run_with_heartbeat "${module_name} image build" "$build_timeout" \
            bash -c '
                cd "$1" || exit 2
                docker compose build 2>&1 | tee -a "$2" | while IFS= read -r line; do
                    if echo "$line" | grep -qE "^(Step [0-9]+|Successfully|Building|CACHED|\[.*/.*\])"; then
                        echo "    $line"
                    fi
                done
                rc="${PIPESTATUS[0]}"
                # Same failure-visibility pattern as the compose-up branch
                # below: on non-zero exit, surface the actual error instead
                # of forcing the operator to grep the log file.
                if [[ $rc -ne 0 ]]; then
                    echo ""
                    echo "    ============================================================"
                    echo "    docker compose build FAILED (exit $rc) — last 30 lines:"
                    echo "    ============================================================"
                    tail -30 "$2" | sed "s/^/      /"
                    echo "    ============================================================"
                fi
                exit "$rc"
            ' _ "$cwd" "$LOG_FILE"
        return $?
    else
        # For 'up -d': Filter repetitive download/extract progress, show key events
        # Keep: Image pulling, Container creating/starting, errors/warnings
        # Filter: "abc123 Downloading 4.194MB", "abc123 Extracting", "Download complete", etc.
        # Wrap in heartbeat too — Velociraptor's `up -d` triggers a local
        # build (image not on registry), and IRIS first-time DB init can
        # take 5+ min. Without heartbeat, those minutes look like a hang.
        local up_cwd="$PWD"
        run_with_heartbeat "${module_name} compose up" "$build_timeout" \
            bash -c '
                cd "$1" || exit 2
                docker compose up -d 2>&1 | tee -a "$2" | \
                    grep -vE "^\s*[0-9a-f]{12} (Downloading|Extracting|Waiting|Download complete|Pull complete|Pulling fs layer) " | \
                    while IFS= read -r line; do
                        if [[ -n "$line" ]]; then
                            echo "    $line"
                        fi
                    done
                rc="${PIPESTATUS[0]}"
                # On failure, dump the full last 30 lines from the log file to
                # the terminal so the operator sees the actual error
                # immediately, not just a generic "deploy failed" line. The log
                # file already has the full output via `tee -a "$2"` above —
                # this just makes it visible without forcing a hunt through
                # thousands of lines. Real-world bug: the volume-mount race
                # `failed to mkdir .../volweb_media/_data/symbols: file exists`
                # was buried in the install log on a fresh-machine install and
                # the operator could not tell why volweb deployment failed.
                if [[ $rc -ne 0 ]]; then
                    echo ""
                    echo "    ============================================================"
                    echo "    docker compose up FAILED (exit $rc) — last 30 lines of full output:"
                    echo "    ============================================================"
                    tail -30 "$2" | sed "s/^/      /"
                    echo "    ============================================================"
                    echo "    Full log: $2"
                    echo "    ============================================================"
                fi
                exit "$rc"
            ' _ "$up_cwd" "$LOG_FILE"
        return $?
    fi
}

# Pull a module's compose images with retry/backoff, separated from `up -d`.
# Pulls are by far the most common transient-failure point on real networks
# (registry rate-limits, IPv6 race on IPv4-only hosts, brief CDN hiccups).
# Doing the pull as a discrete, retryable step means a single bad DNS roll or
# 503 doesn't doom the whole module deploy. Subsequent `up -d` runs from
# run_docker_compose() find images locally and don't repeat the network risk.
# Same exponential-backoff cadence as _pull_image_with_retry() in docker.sh.
pull_compose_with_retry() {
    local module_name="$1"
    local max_attempts=3
    local delays=(5 15 45)
    local attempt=1
    # Track whether any earlier attempt failed, so a subsequent
    # successful attempt can leave a "↳ resolved" breadcrumb in
    # INSTALL_WARNINGS — operator sees inline that the warning is no
    # longer actionable, instead of having to reason about it.
    local had_failure=0

    while [[ $attempt -le $max_attempts ]]; do
        log_info "  Pulling images for ${module_name} (attempt ${attempt}/${max_attempts}) — this can take 5-15 min on first install for big images (ELK / IRIS)..."

        # Stream docker pull progress to BOTH the operator's terminal
        # and the log file. The previous version filtered the per-layer
        # progress lines (`<id> Downloading|Extracting|Pull complete …`)
        # and discarded everything to /dev/null, so an install that hung
        # for 10 minutes during a multi-GB pull looked completely silent
        # and operators thought it had crashed.
        #
        # `--progress=plain` is critical: docker's default `auto` mode
        # emits ANSI escape codes that overwrite the same terminal line.
        # That's nice on a TTY but fills the log file with garbage and
        # produces no useful output when install.sh's stdout is itself
        # piped/teed elsewhere. `plain` gives one-line-per-event output
        # that's readable both on screen and in install_*.log.
        #
        # PIPESTATUS[0] is the docker exit code (tee's success doesn't
        # mask a failed pull). Don't use `set -o pipefail` here — we
        # want to keep the existing per-attempt retry semantics.
        if docker compose --progress=plain pull 2>&1 | tee -a "$LOG_FILE"; then
            if [[ ${PIPESTATUS[0]} -eq 0 ]]; then
                if (( had_failure > 0 )); then
                    log_success "  ${module_name} pull succeeded on attempt ${attempt} (previous failure was transient)"
                    INSTALL_WARNINGS+=("  ↳ resolved: ${module_name} pull succeeded on attempt ${attempt}")
                else
                    log_success "  ${module_name} images pulled"
                fi
                return 0
            fi
        fi

        had_failure=1
        if [[ $attempt -lt $max_attempts ]]; then
            local delay=${delays[$((attempt - 1))]}
            log_warn "  ${module_name} pull attempt ${attempt} failed; retrying in ${delay}s..."
            sleep "$delay"
        fi
        ((attempt++))
    done

    log_error "  ${module_name} pull failed after ${max_attempts} attempts"
    return 1
}

# ============================================================================
# Resilience helpers (2026-06-15) — pre-flight host health, transient-error
# retry on compose-up, skip-already-installed detection, daemon-journal
# dump on failure. Added after the test-1 install hit a systemd-dbus /
# cgroup transient mid-deploy that the existing pull-only retry layer
# couldn't catch (the failure was in `docker compose up`, not in the pull).
# ============================================================================

# preflight_host_check — fast checks that determine if the host is in a
# state to safely run docker compose. Logs a warning + returns 0 for
# soft issues, returns non-zero only for hard blockers. Called BEFORE
# each module's deploy_* so we fail fast with a clear error instead of
# burning 90 s on image pulls only to crash at compose-up.
#
# Args: $1 = module name (for log lines)
# Returns: 0 OK, 1 hard blocker
preflight_host_check() {
    local module_name="$1"
    local rc=0

    # systemd status — `degraded` is OK (some unrelated unit failed), but
    # `offline` / `stopping` / no-systemd means cgroup-unit creation will
    # break compose-up the way it broke the 2026-06-15 test-1 install.
    if command -v systemctl >/dev/null 2>&1; then
        local sysd_state
        sysd_state=$(systemctl is-system-running 2>/dev/null || true)
        case "$sysd_state" in
            running|degraded|maintenance|starting)
                ;;
            "")
                # systemctl present but no reply — usually means systemd
                # itself is unhealthy; treat as soft warn.
                log_warn "  [preflight $module_name] systemctl returned no state — systemd may be unhappy"
                ;;
            *)
                log_error "  [preflight $module_name] systemd state = $sysd_state (cgroup-unit creation will fail)"
                rc=1
                ;;
        esac
    fi

    # Docker daemon reachable + responsive.
    if ! docker info >/dev/null 2>&1; then
        log_error "  [preflight $module_name] docker daemon not responding to 'docker info'"
        rc=1
    fi

    # DNS — only a warning. Some modules don't need internet (e.g. the
    # offline-apply path), so a broken /etc/resolv.conf shouldn't block
    # them. install.sh's online path needs github.com though.
    if ! getent hosts github.com >/dev/null 2>&1; then
        log_warn "  [preflight $module_name] DNS lookup for github.com failed — online image pulls may fail"
    fi

    # Memory — log only. The original cgroup-disconnect bug correlated with
    # back-to-back container creations exhausting systemd's request queue,
    # but free memory was fine; checking it would have been a red herring.
    # Surface it informationally so the operator can spot tight installs.
    if command -v free >/dev/null 2>&1; then
        local mem_free_mb
        mem_free_mb=$(free -m 2>/dev/null | awk '/^Mem:/ {print $7}')
        if [[ -n "$mem_free_mb" ]]; then
            log_info "  [preflight $module_name] available memory: ${mem_free_mb} MB"
        fi
    fi

    return $rc
}

# is_module_installed — returns 0 when the module's primary container
# already exists AND is running. Used by deploy_* to skip the heavy
# compose-up step on install.sh re-runs after a partial failure (the
# operator's typical recovery action is just `sudo bash install.sh`
# again; without this they re-pull every image and re-create every
# volume which sometimes makes things worse).
#
# Args: $1 = primary container name
# Returns: 0 already installed + running, 1 not installed / not running
is_module_installed() {
    local container_name="$1"
    local status
    status=$(docker inspect --format '{{.State.Status}}' "$container_name" 2>/dev/null || echo "")
    case "$status" in
        running)  return 0 ;;
        *)        return 1 ;;
    esac
}

# dump_docker_journal_on_failure — when compose-up fails, immediately
# dump the last 60 s of docker daemon logs to the install log. Gives the
# operator the daemon-side root cause (dbus disconnect, cgroup unit
# rejection, runc failure, etc.) without forcing them to SSH and grep
# journalctl themselves. Best-effort — silent no-op if journalctl isn't
# available (non-systemd hosts).
dump_docker_journal_on_failure() {
    local module_name="$1"
    if ! command -v journalctl >/dev/null 2>&1; then
        return 0
    fi
    log_info "  [diag $module_name] dumping last 60s of dockerd journal:"
    journalctl -u docker --since "60 seconds ago" --no-pager 2>/dev/null \
        | tail -50 \
        | sed 's/^/    [dockerd] /' \
        | tee -a "$LOG_FILE"
}

# run_compose_up_with_retry — retry the `docker compose up -d` call
# itself when it fails with a known-transient error pattern (dbus
# disconnect, cgroup-unit creation, port allocation race, daemon-too-
# busy). Today only image PULLS retry via pull_compose_with_retry; this
# closes the gap that bit the operator on 2026-06-15 (systemd-dbus
# disconnect during the cgroup-unit creation for intact_timesketch_web,
# 30 s of dbus calm would have cleared it).
#
# Permanent errors (no such image, port already allocated by a
# non-compose process, config error) fail-fast on the first try.
#
# Args: $1 = module name, $2 = build_timeout (passed to run_docker_compose)
# Returns: same as run_docker_compose
run_compose_up_with_retry() {
    local module_name="$1"
    local build_timeout="${2:-1800}"
    local max_attempts=3
    local delays=(15 45)
    local attempt=1
    local logfile_marker

    while [[ $attempt -le $max_attempts ]]; do
        # Record where we are in the log file so we can scan only THIS
        # attempt's output for transient-error patterns.
        logfile_marker=$(wc -c < "$LOG_FILE" 2>/dev/null || echo 0)

        if run_docker_compose "up -d" "$module_name" "$build_timeout"; then
            if (( attempt > 1 )); then
                log_success "  ${module_name} compose up succeeded on attempt ${attempt} (previous failure was transient)"
                INSTALL_WARNINGS+=("  ↳ resolved: ${module_name} compose up succeeded on attempt ${attempt}")
            fi
            return 0
        fi

        # Read just the new bytes added since logfile_marker
        local recent
        recent=$(tail -c +"$((logfile_marker + 1))" "$LOG_FILE" 2>/dev/null || true)

        # Classify: transient (worth retrying) vs permanent (don't bother)
        if echo "$recent" | grep -qiE 'disconnected from message bus|unable to apply cgroup configuration|unable to start unit "docker-.*\.scope"|temporary failure in name resolution|i/o timeout|connection refused|context deadline exceeded|failed to set up container networking|docker-credential-secretservice|too many open files'; then
            if [[ $attempt -lt $max_attempts ]]; then
                local delay=${delays[$((attempt - 1))]}
                log_warn "  ${module_name} compose up failed with TRANSIENT error pattern; retrying in ${delay}s..."
                dump_docker_journal_on_failure "$module_name"
                sleep "$delay"
                ((attempt++))
                continue
            fi
        elif echo "$recent" | grep -qiE 'no such image|port is already allocated|invalid reference format|pull access denied|manifest unknown|repository .* not found'; then
            log_error "  ${module_name} compose up failed with PERMANENT error pattern; not retrying"
            dump_docker_journal_on_failure "$module_name"
            return 1
        fi

        # Unknown error class — still retry once but don't loop forever.
        if [[ $attempt -lt $max_attempts ]]; then
            local delay=${delays[$((attempt - 1))]}
            log_warn "  ${module_name} compose up failed (unknown error class); retrying in ${delay}s..."
            dump_docker_journal_on_failure "$module_name"
            sleep "$delay"
        fi
        ((attempt++))
    done

    log_error "  ${module_name} compose up failed after ${max_attempts} attempts"
    dump_docker_journal_on_failure "$module_name"
    return 1
}


# ============================================================================
# Shared volumes — created BEFORE any compose runs so every module can
# treat them as `external: true` and nobody fights over ownership.
# ============================================================================

ensure_shared_volumes() {
    log_info "Ensuring shared docker volumes exist..."

    # intact_memory_dumps — shared between Velociraptor (writes the
    # acquired .raw at /data/memory_dumps), VolWeb backend + workers
    # (read the .raw at /home/app/web/media/staging), and intact_backend
    # (preflight + cleanup). Created once here so the per-module compose
    # files only need `external: true name: intact_memory_dumps`.
    if docker volume inspect intact_memory_dumps >/dev/null 2>&1; then
        log_info "  intact_memory_dumps: already exists"
    else
        if docker volume create intact_memory_dumps >/dev/null; then
            log_success "  intact_memory_dumps: created"
        else
            log_error "  intact_memory_dumps: docker volume create FAILED"
            track_module_failure "shared-volumes"
            return 1
        fi
    fi
}


# ============================================================================
# Helper: Show container status
# ============================================================================

show_container_status() {
    local container_name="$1"
    local status=$(docker ps --filter "name=$container_name" --format "{{.Status}}" 2>/dev/null | head -1)
    if [[ -n "$status" ]]; then
        log_info "  Container $container_name: $status"
    else
        log_warn "  Container $container_name: Not found"
    fi
}

# ============================================================================
# ELK Stack Module
# ============================================================================

deploy_elk() {
    local elk_enabled=$(read_config "['modules']['elk']['enabled']")
    if ! is_enabled "$elk_enabled"; then
        log_info "[1/8] ELK Stack: SKIPPED (disabled in config)"
        return
    fi

    if is_module_installed intact_elasticsearch; then
        log_info "[1/8] ELK Stack: already installed + running (skipping)"
        return 0
    fi

    log_info "[1/8] Starting ELK Stack..."
    log_info "  Directory: ${SCRIPT_DIR}/modules/elk"
    cd "${SCRIPT_DIR}/modules/elk"

    if ! preflight_host_check "ELK Stack"; then
        log_error "ELK Stack: host pre-flight FAILED — see warnings above"
        track_module_failure "ELK Stack"
        return 1
    fi

    # Show what images will be used
    local elk_version=$(read_config "['versions']['elk']")
    log_info "  Elasticsearch version: ${elk_version:-8.x}"

    if ! pull_compose_with_retry "ELK Stack"; then
        track_module_failure "ELK Stack"
        return 1
    fi
    if ! run_compose_up_with_retry "ELK"; then
        log_error "  Docker compose failed!"
        track_module_failure "ELK Stack"
        return 1
    fi

    # Show container status
    show_container_status "intact_elasticsearch"
    show_container_status "intact_kibana"

    # Wait for Elasticsearch to be ready
    log_info "  Waiting for Elasticsearch API (http://localhost:9200)..."
    local elk_user=$(read_config "['modules']['elk']['id']")
    local elk_pass=$(read_config "['modules']['elk']['password']")
    local es_wait=0
    local es_max_wait=90
    while [[ $es_wait -lt $es_max_wait ]]; do
        if curl -sf --max-time 5 -u "${elk_user:-elastic}:${elk_pass}" "http://localhost:9200/_cluster/health" > /dev/null 2>&1; then
            log_success "  Elasticsearch is ready! (${es_wait}s)"
            track_module_success "ELK Stack"
            return 0
        fi
        sleep 5
        ((es_wait+=5))
        log_info "  Waiting for Elasticsearch... (${es_wait}/${es_max_wait}s)"
    done

    log_error "  Elasticsearch failed to become ready after ${es_max_wait}s"
    capture_diagnostic_logs "ELK Stack (deploy timeout)" intact_elasticsearch
    track_module_failure "ELK Stack"
    return 1
}

# ============================================================================
# Shared: stamp transitive container pins from config.yaml into a module's .env
# ============================================================================

# Stamp transitive container version pins (POSTGRES_VERSION,
# OPENSEARCH_VERSION, RABBITMQ_VERSION, etc.) into a module's .env file
# from config.yaml's `versions:` block. Counterpart of the Python apply
# side's stamp_transitive_env_from_manifest — for the install.sh path
# that runs BEFORE any manifest exists.
#
# Args:
#   $1    module name (used as the modules/<name>/.env path)
#   $2..  one or more "ENV_VAR:config_key" pairs (config_key is the
#         flat key under versions: in config.yaml, e.g.
#         timesketch_postgres → versions.timesketch_postgres)
#
# Idempotent: rewrites any line that already starts with one of the
# named ENV_VARs; appends any missing ones. Other lines in .env (e.g.
# operator-set passwords) are untouched.
#
# Added 2026-06-14 alongside the move-pins-to-config.yaml refactor:
# install.sh's deploy_* now does the same thing the apply side has
# been doing all along, so install + upgrade converge on the same
# pins (single source of truth = config.yaml).
_stamp_transitive_env_from_config() {
    local module="$1"
    shift
    local env_file="${SCRIPT_DIR}/modules/${module}/.env"
    mkdir -p "$(dirname "$env_file")"
    touch "$env_file"

    local pair env_var config_key value tmp
    tmp="$(mktemp)"
    cp "$env_file" "$tmp"

    for pair in "$@"; do
        env_var="${pair%%:*}"
        config_key="${pair#*:}"
        value=$(read_config "['versions']['${config_key}']")
        if [[ -z "$value" || "$value" == "None" ]]; then
            log_warn "  [stamp] versions.${config_key} missing from config.yaml; ${env_var} will be unset (compose ${VAR:?...} will fail)"
            continue
        fi
        # Drop any existing line for this var, then append the new one.
        # `sed -E '/^ENV_VAR=/d'` handles commented or active lines.
        sed -i -E "/^[#[:space:]]*${env_var}[[:space:]]*=/d" "$tmp"
        echo "${env_var}=${value}" >> "$tmp"
    done
    mv "$tmp" "$env_file"
    log_info "  [stamp] modules/${module}/.env updated from config.yaml.versions"
}


# ============================================================================
# TimeSketch Module
# ============================================================================

deploy_timesketch() {
    local ts_enabled=$(read_config "['modules']['timesketch']['enabled']")
    if ! is_enabled "$ts_enabled"; then
        log_info "[2/8] TimeSketch: SKIPPED (disabled in config)"
        return
    fi

    # Skip-already-installed: install.sh re-runs after a partial failure
    # should reuse what's healthy instead of re-pulling + re-creating
    # everything from scratch (which sometimes makes the original
    # transient worse). intact_timesketch_web is the canary because it
    # comes up LAST among timesketch's containers; if it's running, the
    # whole stack is healthy.
    if is_module_installed intact_timesketch_web; then
        log_info "[2/8] TimeSketch: already installed + running (skipping)"
        return 0
    fi

    log_info "[2/8] Starting TimeSketch..."
    log_info "  Directory: ${SCRIPT_DIR}/modules/timesketch"
    cd "${SCRIPT_DIR}/modules/timesketch"

    # Pre-flight: if the host is in a broken state, fail fast instead of
    # burning 90 s on image pulls only to crash at compose-up time.
    if ! preflight_host_check "TimeSketch"; then
        log_error "TimeSketch: host pre-flight FAILED — see warnings above"
        track_module_failure "TimeSketch"
        return 1
    fi

    local ts_version=$(read_config "['versions']['timesketch']")
    log_info "  TimeSketch version: ${ts_version:-latest}"

    # Stamp transitive container pins from config.yaml into
    # modules/timesketch/.env BEFORE compose up. The compose file's
    # `${POSTGRES_VERSION:?...}` references will fail loudly without
    # this. 2026-06-14 refactor: pins moved from a live upstream scrape
    # into config.yaml's `versions.timesketch_<dep>` entries — same
    # source the apply-side stamper reads from the bundled manifest.
    _stamp_transitive_env_from_config "timesketch" \
        "OPENSEARCH_VERSION:timesketch_opensearch" \
        "POSTGRES_VERSION:timesketch_postgres" \
        "REDIS_VERSION:timesketch_redis" \
        "NGINX_VERSION:timesketch_nginx"

    # Copy timesketch.conf / timesketch_legacy.conf from templates BEFORE
    # docker compose up — the conf files are bind-mounted into the
    # containers, so they must exist by the time the containers come up.
    # Templates ship with empty api_key fields; the operator fills them in
    # via the dashboard Settings → Timesketch tab (no env var, no secret
    # baked into install). Idempotent: existing conf is preserved so
    # post-install edits (manual or via the Settings UI) survive re-runs.
    for base in timesketch.conf timesketch_legacy.conf; do
        local ts_template="${SCRIPT_DIR}/modules/timesketch/config/${base}.template"
        local ts_out="${SCRIPT_DIR}/modules/timesketch/config/${base}"
        if [[ -f "$ts_out" ]]; then
            log_info "  ${base} already present (skip)"
        elif [[ -f "$ts_template" ]]; then
            cp "$ts_template" "$ts_out"
            # SECRET_KEY signs Timesketch's Flask session cookies and CSRF
            # tokens — anyone with the value can forge any user's session,
            # so it must be unique per install. Templates ship with a
            # __SECRET_KEY__ placeholder; we replace it with 32 random
            # bytes here, mirroring the IRIS_SECRET_KEY pattern above.
            local random_key
            random_key=$(openssl rand -hex 32)
            sed -i "s|^SECRET_KEY = '[^']*'|SECRET_KEY = '${random_key}'|" "$ts_out"
            log_success "  ${base} created from template (api_key empty — set via Settings → Timesketch; SECRET_KEY randomized)"
        else
            log_warn "  Template missing: $ts_template"
        fi
    done

    if ! pull_compose_with_retry "TimeSketch"; then
        track_module_failure "TimeSketch"
        return 1
    fi
    if ! run_compose_up_with_retry "TimeSketch"; then
        log_error "  Docker compose failed!"
        track_module_failure "TimeSketch"
        return 1
    fi

    # Show container status
    show_container_status "intact_timesketch_web"
    show_container_status "intact_timesketch_worker"
    show_container_status "intact_timesketch_postgres"
    show_container_status "intact_timesketch_redis"
    show_container_status "intact_timesketch_opensearch"

    # Wait for TimeSketch web container to be ready
    log_info "  Waiting for TimeSketch container..."
    if ! wait_for_container "intact_timesketch_web" 60; then
        log_error "  TimeSketch web container failed to start"
        capture_diagnostic_logs "TimeSketch web (container start timeout)" \
            intact_timesketch_web intact_timesketch_postgres intact_timesketch_opensearch
        track_module_failure "TimeSketch"
        return 1
    fi

    # Wait for TimeSketch API to be ready (check from host, not container - no curl in container)
    log_info "  Waiting for TimeSketch API (https://localhost:5000)..."
    local ts_ready=false
    local ts_wait=0
    local ts_max_wait=90

    while [[ $ts_wait -lt $ts_max_wait ]]; do
        local http_code=$(curl -sk --max-time 5 "https://localhost:5000/" -o /dev/null -w "%{http_code}" 2>/dev/null)
        if [[ "$http_code" =~ ^(200|301|302|303|307|308)$ ]]; then
            ts_ready=true
            log_success "  TimeSketch API is ready! (HTTP $http_code, ${ts_wait}s)"
            break
        fi
        sleep 5
        ((ts_wait+=5))
        log_info "  Waiting for TimeSketch API... (${ts_wait}/${ts_max_wait}s)"
    done

    if [[ "$ts_ready" != "true" ]]; then
        log_warn "  TimeSketch API not responding after ${ts_max_wait}s"
        log_info "  Check logs: docker logs intact_timesketch_web"
        capture_diagnostic_logs "TimeSketch API (deploy timeout)" \
            intact_timesketch_nginx intact_timesketch_web intact_timesketch_worker
    fi

    # Create user
    local ts_user=$(read_config "['modules']['timesketch']['id']")
    local ts_pass=$(read_config "['modules']['timesketch']['password']")

    # STEP A — Wait until the postgres "user" table actually exists.
    # The Timesketch container image doesn't ship Alembic migrations
    # (no /migrations directory), so `tsctl db upgrade` is a no-op that
    # prints a misleading ERROR. The schema is auto-created by the web
    # container's own startup (SQLAlchemy create_all), so we just poll
    # until the user table is visible before attempting create-user.
    log_info "  Waiting for TimeSketch postgres 'user' table to materialize..."
    local table_wait=0
    local table_ready=false
    while (( table_wait < 60 )); do
        local has_table
        has_table=$(docker exec intact_timesketch_postgres psql -U timesketch -d timesketch -tAc \
            "SELECT to_regclass('public.\"user\"');" 2>/dev/null | tr -d '[:space:]')
        # to_regclass returns "user" when the table exists, empty/NULL when it doesn't.
        if [[ -n "$has_table" && "$has_table" != "NULL" ]]; then
            table_ready=true
            log_success "  TimeSketch 'user' table is present (${table_wait}s)"
            break
        fi
        sleep 2
        ((table_wait+=2))
    done
    if [[ "$table_ready" != "true" ]]; then
        log_error "  TimeSketch postgres 'user' table did not appear after 60s — schema auto-create may have failed"
        log_error "  Manual diagnosis: docker exec intact_timesketch_postgres psql -U timesketch -d timesketch -c \"SELECT to_regclass('public.\\\"user\\\"');\""
        capture_diagnostic_logs "TimeSketch schema bring-up" \
            intact_timesketch_web intact_timesketch_postgres
    fi

    log_info "  Creating TimeSketch user: ${ts_user}"

    # STEP C — Now create the user. With migrations already applied
    # this is no longer racing the schema. We still verify the row
    # actually persisted before trusting tsctl's exit code (belt-and-
    # suspenders — tsctl has been observed exiting 0 even when the
    # write was rolled back by a transient).
    local ts_user_created=false
    local ts_retry=0
    local ts_max_retry=5
    local ts_error=""

    while [[ $ts_retry -lt $ts_max_retry ]]; do
        ts_error=$(docker exec intact_timesketch_web tsctl create-user "${ts_user}" --password "${ts_pass}" 2>&1)
        local ts_exit_code=$?

        # tsctl said it worked OR said the user already exists — either
        # way, only believe it if the DB actually has the row.
        if [[ $ts_exit_code -eq 0 ]] || echo "$ts_error" | grep -qi "already exists"; then
            if verify_postgres_row intact_timesketch_postgres timesketch user "username='${ts_user}'"; then
                ts_user_created=true
                break
            fi
            log_info "  tsctl reported success but '${ts_user}' is not in postgres yet — retrying"
        fi

        ((ts_retry++))
        if [[ $ts_retry -lt $ts_max_retry ]]; then
            log_info "  Retrying user creation... (attempt ${ts_retry}/${ts_max_retry})"
            sleep 10
        fi
    done

    if [[ "$ts_user_created" == "true" ]]; then
        # STEP D — Enable + verify enable. enable-user can also silently
        # no-op when the row was just written and the cache is stale.
        docker exec intact_timesketch_web tsctl enable-user "${ts_user}" >/dev/null 2>&1 || true
        if verify_postgres_row intact_timesketch_postgres timesketch user "username='${ts_user}' AND active=true"; then
            log_success "  TimeSketch user '${ts_user}' ready (verified active in DB)"
        else
            log_warn "  TimeSketch user '${ts_user}' exists but is not marked active — sketches/uploads may be denied"
            log_warn "  Manual fix: docker exec intact_timesketch_web tsctl enable-user ${ts_user}"
        fi

        # Enable DFIQ after successful deployment.
        # (Historically also ran `tsctl db upgrade` here; the current
        # Timesketch image doesn't ship Alembic migrations, so the call
        # was a no-op and produced misleading errors. Removed.)
        log_info "  Enabling DFIQ..."
        sed -i 's/DFIQ_ENABLED = False/DFIQ_ENABLED = True/' "${SCRIPT_DIR}/modules/timesketch/config/timesketch.conf"
        log_success "  DFIQ enabled"

        # Populate /etc/timesketch/dfiq/ with the upstream Google DFIQ
        # YAML files. The Timesketch image does NOT ship these — the
        # DFIQ_ENABLED flag alone is useless without the 126 question /
        # facet / scenario YAMLs at DFIQ_PATH. Wiping the volume (e.g.
        # docker compose down -v) clears the rendered conf but the
        # bind-mounted config dir survives, so this only really runs on
        # first install or when /modules/timesketch/config/dfiq/ is empty.
        local dfiq_dir="${SCRIPT_DIR}/modules/timesketch/config/dfiq"
        if [[ ! -f "${dfiq_dir}/scenarios/$(ls "${dfiq_dir}/scenarios" 2>/dev/null | head -1)" || -z "$(ls "${dfiq_dir}/scenarios" 2>/dev/null)" ]]; then
            log_info "  Fetching DFIQ data from google/dfiq..."
            local _tmp
            _tmp="$(mktemp -d)"
            if git clone --depth 1 --quiet https://github.com/google/dfiq.git "${_tmp}/repo" 2>/dev/null; then
                rm -rf "${dfiq_dir}"
                mkdir -p "${dfiq_dir}"
                mv "${_tmp}/repo/dfiq/data"/* "${dfiq_dir}/"
                rm -rf "${_tmp}"
                local _yaml_count
                _yaml_count="$(find "${dfiq_dir}" -name '*.yaml' | wc -l)"
                log_success "  DFIQ data installed (${_yaml_count} YAML files in ${dfiq_dir})"
            else
                log_warn "  Could not clone google/dfiq (network?); DFIQ UI will be empty until you populate ${dfiq_dir} manually."
            fi
        else
            local _yaml_count
            _yaml_count="$(find "${dfiq_dir}" -name '*.yaml' | wc -l)"
            log_info "  DFIQ data already present (${_yaml_count} YAML files) — skipping clone."
        fi

        # Raise OpenSearch / import timeouts so large .plaso imports don't false-fail
        # (upstream defaults are 10s and 180s — too aggressive under disk/memory pressure)
        log_info "  Raising Timesketch OpenSearch/import timeouts..."
        local ts_conf="${SCRIPT_DIR}/modules/timesketch/config/timesketch.conf"
        sed -i 's/^OPENSEARCH_TIMEOUT = 10$/OPENSEARCH_TIMEOUT = 300/'                    "$ts_conf"
        sed -i 's/^OPENSEARCH_FLUSH_INTERVAL = 5000$/OPENSEARCH_FLUSH_INTERVAL = 10000/'  "$ts_conf"
        sed -i 's/^OPENSEARCH_INDEX_WAIT_TIMEOUT = 10$/OPENSEARCH_INDEX_WAIT_TIMEOUT = 300/' "$ts_conf"
        sed -i 's/^TIMEOUT_FOR_EVENT_IMPORT = 180$/TIMEOUT_FOR_EVENT_IMPORT = 600/'       "$ts_conf"
        log_success "  Timeouts raised (OpenSearch 10->300s, event import 180->600s)"

        # Restart the Timesketch containers that bind-mount timesketch.conf so both
        # DFIQ and the timeout bumps take effect. Worker + web_legacy matter too —
        # without this, indexing runs with the old timeouts until next reboot.
        docker restart intact_timesketch_web intact_timesketch_worker intact_timesketch_web_legacy >/dev/null 2>&1

        track_module_success "TimeSketch"
    else
        log_error "  TimeSketch user '${ts_user}' creation FAILED — DB row absent after ${ts_max_retry} attempts"
        log_error "  Last tsctl output: ${ts_error}"
        log_error "  Manual fix: docker exec intact_timesketch_web tsctl create-user ${ts_user} --password '<from config.yaml>'"
        log_error "  Then verify:  docker exec intact_timesketch_postgres psql -U timesketch -d timesketch -c 'SELECT id, username FROM \"user\";'"
        capture_diagnostic_logs "TimeSketch user creation" \
            intact_timesketch_web intact_timesketch_postgres
        track_module_failure "TimeSketch"
        return 1
    fi
}

# ============================================================================
# Velociraptor Module
# ============================================================================
#
# NOTE: /velociraptor is host-mounted at data/velociraptor/ (see the module's
# docker-compose.yaml). A FRESH install has no legacy named volume to migrate —
# the bind-mount starts empty and entrypoint.sh generates server.config.yaml
# into it. The named-volume → host-mount MIGRATION (which preserves the CA for
# older-release deployments) lives ONLY in the upgrade path
# (services/upgrade/velociraptor.migrate_velociraptor_config_to_host), since
# that's the only place a legacy volume exists.

deploy_velociraptor() {
    local velo_enabled=$(read_config "['modules']['velociraptor']['enabled']")
    if ! is_enabled "$velo_enabled"; then
        log_info "[3/8] Velociraptor: SKIPPED (disabled in config)"
        return
    fi

    if is_module_installed intact_velociraptor; then
        log_info "[3/8] Velociraptor: already installed + running (skipping)"
        return 0
    fi

    log_info "[3/8] Starting Velociraptor..."
    log_info "  Directory: ${SCRIPT_DIR}/modules/velociraptor"
    cd "${SCRIPT_DIR}/modules/velociraptor"

    if ! preflight_host_check "Velociraptor"; then
        log_error "Velociraptor: host pre-flight FAILED — see warnings above"
        track_module_failure "Velociraptor"
        return 1
    fi

    local velo_version=$(read_config "['versions']['velociraptor']")
    log_info "  Velociraptor version: ${velo_version:-latest}"

    # Pre-stage the four binaries (linux server + mac/win clients) that
    # the Dockerfile COPYs at build time. The Dockerfile no longer
    # curls during build — it expects these files already in the build
    # context, which is the contract for the offline-upgrade workflow.
    # Initial install needs internet here; same as before, just at a
    # different layer (host curl vs in-container curl).
    if ! stage_velociraptor_client_binaries "$velo_version" "${SCRIPT_DIR}/modules/velociraptor"; then
        log_error "  Failed to stage Velociraptor binaries — see warnings above."
        track_module_failure "Velociraptor"
        return 1
    fi

    if ! run_compose_up_with_retry "Velociraptor" 600; then
        log_error "  Docker compose failed!"
        track_module_failure "Velociraptor"
        return 1
    fi

    # Show container status
    show_container_status "intact_velociraptor"

    # Wait for container to be ready
    log_info "  Waiting for Velociraptor container..."
    if ! wait_for_container "intact_velociraptor" 60; then
        log_warn "  Velociraptor container may not be fully ready"
        capture_diagnostic_logs "Velociraptor (container start timeout)" intact_velociraptor
    fi

    # Wait for Velociraptor configuration to be generated
    log_info "  Waiting for Velociraptor configuration..."
    local velo_config_wait=0
    while [[ $velo_config_wait -lt 90 ]]; do
        if docker exec intact_velociraptor test -f /velociraptor/client.config.yaml 2>/dev/null; then
            log_success "  Velociraptor configuration ready (${velo_config_wait}s)"
            break
        fi
        sleep 5
        ((velo_config_wait+=5))
    done
    if [[ $velo_config_wait -ge 90 ]]; then
        log_warn "  Velociraptor configuration not ready after 90s"
        capture_diagnostic_logs "Velociraptor (config generation timeout)" intact_velociraptor
    fi

    # Generate client installers
    log_info "  Generating pre-configured client installers..."
    if [[ -f "${SCRIPT_DIR}/scripts/generate_clients.sh" ]]; then
        bash "${SCRIPT_DIR}/scripts/generate_clients.sh" 2>&1 | tee -a "$LOG_FILE"
        if [[ ${PIPESTATUS[0]} -ne 0 ]]; then
            log_warn "  Client installer generation had issues"
        fi
    else
        log_warn "  Client installer script not found, skipping"
    fi

    track_module_success "Velociraptor"
}

# ============================================================================
# IRIS Module
# ============================================================================

deploy_iris() {
    local iris_enabled=$(read_config "['modules']['iris']['enabled']")
    if ! is_enabled "$iris_enabled"; then
        log_info "[4/8] IRIS: SKIPPED (disabled in config)"
        return
    fi

    if is_module_installed intact_iris_app; then
        log_info "[4/8] IRIS: already installed + running (skipping)"
        return 0
    fi

    log_info "[4/8] Starting IRIS (Incident Response Platform)..."
    log_info "  Directory: ${SCRIPT_DIR}/modules/iris"
    cd "${SCRIPT_DIR}/modules/iris"

    if ! preflight_host_check "IRIS"; then
        log_error "IRIS: host pre-flight FAILED — see warnings above"
        track_module_failure "IRIS"
        return 1
    fi

    local iris_version=$(read_config "['versions']['iris']")
    log_info "  IRIS version: ${iris_version:-latest}"

    # Stamp transitive container pins from config.yaml. iris's compose
    # uses `${RABBITMQ_VERSION:?...}`; loud failure here is preferable
    # to a silent stale literal.
    _stamp_transitive_env_from_config "iris" \
        "RABBITMQ_VERSION:iris_rabbitmq"

    # Check if this is a fresh install (no existing database volume)
    local is_fresh_install=false
    if ! docker volume inspect modules_iris_db_data > /dev/null 2>&1 && \
       ! docker volume inspect iris_iris_db_data > /dev/null 2>&1; then
        is_fresh_install=true
        log_info "  Fresh IRIS installation detected (first-time setup will take longer)"
    fi

    if ! pull_compose_with_retry "IRIS"; then
        track_module_failure "IRIS"
        return 1
    fi
    if ! run_compose_up_with_retry "IRIS"; then
        log_error "  Docker compose failed!"
        track_module_failure "IRIS"
        return 1
    fi

    # Show container status (including nginx which serves port 8443)
    show_container_status "intact_iris_db"
    show_container_status "intact_iris_rabbitmq"
    show_container_status "intact_iris_app"
    show_container_status "intact_iris_worker"
    show_container_status "intact_iris_nginx"

    # Wait for database first
    log_info "  Waiting for IRIS database (PostgreSQL)..."
    local db_wait=0
    local db_max_wait=90
    local db_ready=false
    while [[ $db_wait -lt $db_max_wait ]]; do
        if docker exec intact_iris_db pg_isready -U postgres > /dev/null 2>&1; then
            log_success "  IRIS database is ready (${db_wait}s)"
            db_ready=true
            break
        fi
        sleep 5
        ((db_wait+=5))
        log_info "  Waiting for database... (${db_wait}/${db_max_wait}s)"
    done
    if [[ "$db_ready" != "true" ]]; then
        log_warn "  IRIS database did not become ready in ${db_max_wait}s"
        capture_diagnostic_logs "IRIS database (timeout)" intact_iris_db
    fi

    # Wait for RabbitMQ
    log_info "  Waiting for IRIS message queue (RabbitMQ)..."
    local mq_wait=0
    local mq_max_wait=60
    local mq_ready=false
    while [[ $mq_wait -lt $mq_max_wait ]]; do
        if docker exec intact_iris_rabbitmq rabbitmqctl status > /dev/null 2>&1; then
            log_success "  RabbitMQ is ready (${mq_wait}s)"
            mq_ready=true
            break
        fi
        sleep 5
        ((mq_wait+=5))
        log_info "  Waiting for RabbitMQ... (${mq_wait}/${mq_max_wait}s)"
    done
    if [[ "$mq_ready" != "true" ]]; then
        log_warn "  IRIS RabbitMQ did not become ready in ${mq_max_wait}s"
        capture_diagnostic_logs "IRIS RabbitMQ (timeout)" intact_iris_rabbitmq
    fi

    # Wait for IRIS app container
    log_info "  Waiting for IRIS app container..."
    if ! wait_for_container "intact_iris_app" 90; then
        log_warn "  IRIS app container not ready after 90s"
        capture_diagnostic_logs "IRIS app (container timeout)" intact_iris_app intact_iris_db intact_iris_rabbitmq
    fi

    # Wait for IRIS API to be accessible (HTTPS on port 8443)
    # Fresh installs need more time for database schema creation and seeding
    local iris_max_wait=180
    if [[ "$is_fresh_install" == "true" ]]; then
        iris_max_wait=300
        log_info "  Waiting for IRIS web interface (fresh install, up to 5 minutes)..."
    else
        log_info "  Waiting for IRIS web interface (https://localhost:8443)..."
    fi

    local iris_wait=0
    local iris_ready=false
    local last_status=""

    while [[ $iris_wait -lt $iris_max_wait ]]; do
        # Check for any HTTP response (IRIS returns 302 redirect when ready)
        local http_code=$(curl -sk --max-time 5 "https://localhost:8443/" -o /dev/null -w "%{http_code}" 2>/dev/null)
        if [[ "$http_code" =~ ^(200|301|302|303|307|308)$ ]]; then
            iris_ready=true
            log_success "  IRIS web interface is responding! (HTTP $http_code, ${iris_wait}s)"
            break
        fi

        # Show initialization progress by checking app logs
        local current_status=$(docker logs intact_iris_app 2>&1 | tail -1 | grep -oP '(?<=:: )[^:]+(?= ::)' | tail -1)
        if [[ -n "$current_status" && "$current_status" != "$last_status" ]]; then
            log_info "  IRIS status: $current_status"
            last_status="$current_status"
        fi

        sleep 5
        ((iris_wait+=5))
        # Only show periodic updates every 15 seconds to reduce noise
        if (( iris_wait % 15 == 0 )); then
            log_info "  Waiting for IRIS... (${iris_wait}/${iris_max_wait}s)"
        fi
    done

    if [[ "$iris_ready" == "true" ]]; then
        track_module_success "IRIS"
    else
        log_warn "  IRIS web interface not responding after ${iris_max_wait}s"
        log_info "  This may be normal for first-time installation"
        log_info "  Check logs: docker logs intact_iris_app"
        log_info "  IRIS should be accessible at https://localhost:8443 once ready"
        capture_diagnostic_logs "IRIS web (post-deploy timeout)" \
            intact_iris_nginx intact_iris_app intact_iris_db intact_iris_rabbitmq
        track_module_success "IRIS"
    fi

    # bootstrap_iris_api_key is intentionally NOT called here — it writes
    # via `docker exec intact_backend …`, but Backend is deployed AFTER
    # IRIS in start_services. Calling it here meant set_secret failed
    # 100% of the time on fresh installs ("no such container") and the
    # backend silently fell back to the slow runtime docker-exec lookup.
    # The bootstrap now runs from start_services, after deploy_backend.
}

bootstrap_iris_api_key() {
    # IRIS-disabled guard — added in the install-hardening pass after
    # the June 7 log showed 5 minutes of dead-wait polling for an
    # `intact_iris_db` container that never started because IRIS was
    # off. Mirrors the same pattern `deploy_iris` already uses.
    local iris_enabled
    iris_enabled=$(read_config "['modules']['iris']['enabled']")
    if ! is_enabled "$iris_enabled"; then
        log_info "  IRIS disabled — skipping API key bootstrap"
        return 0
    fi
    # Idempotent: skip if the secret is already in the backend DB. Doing
    # the check via the backend container guarantees we use the same
    # storage layer the runtime uses. If intact_backend isn't up yet we
    # fall through to the bootstrap (the secret simply doesn't exist).
    local existing
    existing=$(docker exec intact_backend python3 -c "
import sys; sys.path.insert(0, '/app')
from services.storage.secret_store import get_secret
v = get_secret('iris.administrator.api_key')
sys.stdout.write(v or '')
" 2>/dev/null || true)
    if [[ -n "$existing" ]]; then
        log_info "  IRIS API key already in backend secrets DB — skipping bootstrap"
        return 0
    fi

    log_info "  Bootstrapping IRIS API key into backend secrets DB..."

    # Wait for IRIS first-init to create the administrator row with a
    # non-NULL api_key. Up to 5 minutes; the DB itself comes up in
    # seconds but the IRIS web app populates the user table only after
    # alembic migrations + seed data finish.
    local api_key=""
    local attempts=0
    while (( attempts < 60 )); do
        api_key=$(docker exec intact_iris_db psql -U iris -d iris_db -tAc \
            "SELECT api_key FROM \"user\" WHERE name='administrator' AND api_key IS NOT NULL;" \
            2>/dev/null | tr -d '[:space:]')
        if [[ -n "$api_key" ]]; then
            break
        fi
        sleep 5
        ((attempts++))
        if (( attempts % 6 == 0 )); then
            log_info "  Still waiting for IRIS to create administrator key... ($((attempts * 5))s)"
        fi
    done

    if [[ -z "$api_key" ]]; then
        log_warn "  Could not retrieve IRIS API key from intact_iris_db after 5 minutes"
        log_warn "  Backend will fall back to the runtime docker-exec lookup."
        log_warn "  If that also fails, run this manually after IRIS is up:"
        log_warn "    docker exec intact_iris_db psql -U iris -d iris_db -tAc \\"
        log_warn "      \"SELECT api_key FROM \\\"user\\\" WHERE name='administrator';\""
        log_warn "  then store it via:"
        log_warn "    docker exec intact_backend python3 -c \"from services.storage.secret_store import set_secret; set_secret('iris.administrator.api_key', '<key>')\""
        return 0
    fi

    # Write to the backend's secrets table. The backend doesn't need to be
    # restarted — config.py reads on startup, but iris_service does its own
    # secret lookup on each call too. Worst case: a backend that started
    # before this writes will pick up the secret on the next IRIS request.
    if ! docker exec intact_backend python3 -c "
import sys; sys.path.insert(0, '/app')
from services.storage.secret_store import set_secret
ok = set_secret('iris.administrator.api_key', '$api_key')
sys.exit(0 if ok else 1)
" 2>/dev/null
    then
        log_warn "  Failed to write IRIS api_key into backend secrets DB"
        log_warn "  Backend will fall back to the runtime docker-exec lookup."
        return 0
    fi

    # Read-back verification — set_secret() can return 0 even when the
    # write is rolled back (locked SQLite, transient I/O). Re-query
    # via get_secret to confirm the value actually persisted, so a
    # silent failure here doesn't surface as a runtime IRIS-API error
    # weeks later.
    local persisted
    persisted=$(docker exec intact_backend python3 -c "
import sys; sys.path.insert(0, '/app')
from services.storage.secret_store import get_secret
v = get_secret('iris.administrator.api_key')
sys.stdout.write(v if v else '')
" 2>/dev/null)

    if [[ "$persisted" == "$api_key" ]]; then
        log_success "  IRIS API key persisted to backend secrets table (iris.administrator.api_key) — verified"
    else
        log_error "  IRIS api_key set_secret() returned OK but the read-back didn't match"
        log_error "  Manual fix: docker exec intact_backend python3 -c \"from services.storage.secret_store import set_secret; set_secret('iris.administrator.api_key', '<key>')\""
        capture_diagnostic_logs "Backend secret write" intact_backend
    fi
}

enforce_iris_admin_password() {
    # Make config.yaml the source of truth for the IRIS administrator password.
    # IRIS only honours IRIS_ADM_PASSWORD at FIRST init (post_init.py); on later
    # boots an existing admin keeps whatever it had. So if the secret wasn't
    # applied at first-init (e.g. an unreadable secret file -> IRIS fell back to
    # a RANDOM password), the documented config.yaml creds never work. Re-assert
    # them here using IRIS's own bcrypt hashing (flask-bcrypt), idempotently.

    # IRIS-disabled guard — mirrors bootstrap_iris_api_key. Without this, a
    # deselected IRIS still reached the app/db running-check below and logged a
    # misleading "IRIS app/db not running" WARNING on every install where IRIS
    # is off. Nothing to enforce when the module isn't installed.
    local iris_enabled
    iris_enabled=$(read_config "['modules']['iris']['enabled']")
    if ! is_enabled "$iris_enabled"; then
        log_info "  IRIS disabled — skipping admin-password enforcement"
        return 0
    fi

    local iris_user iris_pass
    iris_user=$(read_config "['modules']['iris']['id']"); [[ -z "$iris_user" ]] && iris_user="administrator"
    iris_pass=$(read_config "['modules']['iris']['password']")
    if [[ -z "$iris_pass" ]]; then
        log_warn "  IRIS password not set in config.yaml — skipping admin-password enforcement"
        return 0
    fi
    if ! docker ps --filter 'name=^intact_iris_app$' --format '{{.Names}}' 2>/dev/null | grep -q . \
       || ! docker ps --filter 'name=^intact_iris_db$' --format '{{.Names}}' 2>/dev/null | grep -q .; then
        log_warn "  IRIS app/db not running — skipping IRIS admin-password enforcement"
        return 0
    fi

    log_info "  Enforcing IRIS administrator password from config.yaml..."
    # Step 1: hash with IRIS's own flask-bcrypt, standalone (NO db access — a
    # fresh `docker exec` lacks the DB secret the entrypoint exports, so importing
    # `app` can't connect). Password comes from the container env, never the body.
    local hash
    hash=$(docker exec -e IRIS_RESET_PW="$iris_pass" intact_iris_app python3 -c \
        'import os;from flask_bcrypt import Bcrypt;print(Bcrypt().generate_password_hash(os.environ["IRIS_RESET_PW"].encode()).decode())' \
        2>/dev/null | tail -1)
    if [[ "$hash" != \$2* ]]; then
        log_warn "  Could not compute IRIS password hash — skipping"
        return 0
    fi
    # Step 2: write it straight into iris_db (psql authenticates locally). bcrypt
    # has no single quotes so the SQL literal is safe.
    local res
    res=$(docker exec intact_iris_db psql -U iris -d iris_db \
        -c "UPDATE \"user\" SET password='$hash' WHERE \"user\"='$iris_user';" 2>&1 | tail -1)
    if [[ "$res" == *"UPDATE 1"* ]]; then
        log_success "  IRIS administrator password set from config.yaml"
    elif [[ "$res" == *"UPDATE 0"* ]]; then
        log_warn "  IRIS administrator row not found — password not set"
    else
        log_warn "  Could not enforce IRIS admin password: $res"
    fi
    return 0
}

# ============================================================================
# Portainer Module
# ============================================================================

deploy_portainer() {
    local portainer_enabled=$(read_config "['modules']['portainer']['enabled']")
    if ! is_enabled "$portainer_enabled"; then
        log_info "[5/8] Portainer: SKIPPED (disabled in config)"
        return
    fi

    log_info "[5/8] Starting Portainer (Container Management)..."
    log_info "  Directory: ${SCRIPT_DIR}/modules/portainer"
    cd "${SCRIPT_DIR}/modules/portainer"

    # Portainer mounts the shared Nginx TLS cert via --tlscert/--tlskey so the
    # UI on :9443 presents the same certificate as the rest of the stack.
    # generate_certificates() runs before this step, so the cert should exist —
    # but bail out loud if it doesn't rather than letting Docker create empty
    # bind-mount dirs and Portainer fail to start with an unhelpful error.
    local nginx_ssl="${SCRIPT_DIR}/modules/nginx/ssl"
    if [[ ! -f "$nginx_ssl/nginx-cert.crt" ]] || [[ ! -f "$nginx_ssl/nginx-cert.key" ]]; then
        log_error "  Shared Nginx TLS cert not found at $nginx_ssl/"
        log_error "  Expected generate_certificates() to run before deploy_portainer()"
        track_module_failure "Portainer"
        return 1
    fi

    # Admin password file must exist; without it the first boot falls into the
    # 5-minute initial-setup window and times out before anyone can click.
    local portainer_secret="${SCRIPT_DIR}/modules/portainer/secrets/admin_password"
    if [[ ! -s "$portainer_secret" ]]; then
        log_error "  Portainer admin password file missing at $portainer_secret"
        log_error "  Expected generate_portainer_secrets() to run before deploy_portainer()"
        track_module_failure "Portainer"
        return 1
    fi

    local portainer_version=$(read_config "['versions']['portainer']")
    log_info "  Portainer version: ${portainer_version:-latest}"

    if ! pull_compose_with_retry "Portainer"; then
        track_module_failure "Portainer"
        return 1
    fi
    if ! run_compose_up_with_retry "Portainer"; then
        log_error "  Docker compose failed!"
        track_module_failure "Portainer"
        return 1
    fi

    # Show container status
    show_container_status "intact_portainer"

    # Wait for Portainer container
    log_info "  Waiting for Portainer container..."
    if wait_for_container "intact_portainer" 30; then
        log_success "  Portainer is ready"
        track_module_success "Portainer"
    else
        log_warn "  Portainer may not be fully ready"
        capture_diagnostic_logs "Portainer (container timeout)" intact_portainer
        track_module_success "Portainer"
    fi
}

# ============================================================================
# VolWeb Module (memory-forensics analysis stack)
# ============================================================================

deploy_volweb() {
    # Gate on the dedicated `modules.volweb.enabled` key (added in
    # commit 96b8a8f). Previously read `modules.memory.enabled`, which
    # silently coupled the backend Memory feature flag to the VolWeb
    # docker stack. Operators who want Memory without VolWeb (e.g.
    # using an external Volatility installation) had no way to express
    # that.
    local volweb_enabled
    volweb_enabled=$(read_config "['modules']['volweb']['enabled']")
    if ! is_enabled "$volweb_enabled"; then
        log_info "[6/8] VolWeb: SKIPPED (volweb disabled in config)"
        return
    fi

    if is_module_installed intact_volweb_backend; then
        log_info "[6/8] VolWeb: already installed + running (skipping)"
        return 0
    fi

    log_info "[6/8] Starting VolWeb (memory-forensics)..."
    log_info "  Directory: ${SCRIPT_DIR}/modules/volweb"
    cd "${SCRIPT_DIR}/modules/volweb"

    if ! preflight_host_check "VolWeb"; then
        log_error "VolWeb: host pre-flight FAILED — see warnings above"
        track_module_failure "VolWeb"
        return 1
    fi

    # Render modules/volweb/.env from the template + config.yaml pins.
    # Idempotent: existing .env is preserved across re-installs so the
    # operator's rotated DJANGO_SECRET + postgres password persist.
    local env_out="${SCRIPT_DIR}/modules/volweb/.env"
    local env_tmpl="${SCRIPT_DIR}/modules/volweb/.env.template"

    if [[ -f "$env_out" ]]; then
        log_info "  modules/volweb/.env already present (skip render — secrets preserved)"
    elif [[ -f "$env_tmpl" ]]; then
        # Single `versions.volweb` pin drives both backend + frontend
        # (forensicxlab releases them in lockstep). Postgres + Redis
        # are transitive deps — pulled from config.yaml's
        # `versions.volweb_postgres` + `versions.volweb_redis` via
        # the stamping helper BELOW (which also covers the upgrade
        # case where .env already exists — operator pin bumps
        # propagate on the next deploy without touching the .env by
        # hand).
        local volweb_ver=$(read_config "['versions']['volweb']")
        local domain=$(read_config "['domain']")
        # Per-install random secrets. Mirrors the IRIS_SECRET_KEY +
        # Timesketch SECRET_KEY pattern shipped earlier this session.
        local django_secret=$(openssl rand -hex 32)
        local pg_password=$(openssl rand -hex 24)
        # CSRF: the IntactAI dashboard hits VolWeb through intact_nginx
        # AND from the backend container. Cover both shapes.
        local csrf="https://${domain},http://intact_nginx,http://intact_backend:5001,http://intact_volweb_backend:8000"

        cp "$env_tmpl" "$env_out"
        sed -i \
            -e "s|__VOLWEB_BACKEND_VERSION__|${volweb_ver:-latest}|g" \
            -e "s|__VOLWEB_FRONTEND_VERSION__|${volweb_ver:-latest}|g" \
            -e "s|__VOLWEB_DJANGO_SECRET__|${django_secret}|g" \
            -e "s|__VOLWEB_POSTGRES_PASSWORD__|${pg_password}|g" \
            -e "s|__VOLWEB_CSRF_TRUSTED_ORIGINS__|${csrf}|g" \
            "$env_out"
        # Drop the old __VOLWEB_POSTGRES_VERSION__ / __VOLWEB_REDIS_VERSION__
        # placeholder lines — the stamping helper below writes the
        # real values from config.yaml. Tolerant if the template
        # doesn't ship those placeholders any more.
        sed -i \
            -e "s|^VOLWEB_POSTGRES_VERSION=__VOLWEB_POSTGRES_VERSION__||g" \
            -e "s|^VOLWEB_REDIS_VERSION=__VOLWEB_REDIS_VERSION__||g" \
            "$env_out"
        log_success "  modules/volweb/.env rendered (per-install secrets generated)"
    else
        log_warn "  modules/volweb/.env.template missing — skipping VolWeb"
        return 1
    fi

    # Stamp transitive container pins from config.yaml — always runs,
    # so an operator pin edit in config.yaml propagates on the next
    # deploy without manual .env surgery. Compose's
    # `${VOLWEB_POSTGRES_VERSION:?...}` would fail loudly otherwise.
    _stamp_transitive_env_from_config "volweb" \
        "VOLWEB_POSTGRES_VERSION:volweb_postgres" \
        "VOLWEB_REDIS_VERSION:volweb_redis"

    if ! pull_compose_with_retry "VolWeb"; then
        track_module_failure "VolWeb"
        return 1
    fi

    if ! run_compose_up_with_retry "VolWeb"; then
        log_error "  Docker compose failed!"
        track_module_failure "VolWeb"
        return 1
    fi

    # Wait for the backend's healthcheck endpoint. Daphne takes a few
    # seconds to bind after the container starts.
    log_info "  Waiting for VolWeb backend to be ready..."
    local volweb_wait=0
    while [[ $volweb_wait -lt 90 ]]; do
        if docker exec intact_volweb_backend curl -sf -o /dev/null \
            http://localhost:8000/api/health 2>/dev/null \
            || docker exec intact_volweb_backend curl -sI -o /dev/null \
            -w "%{http_code}" http://localhost:8000/ 2>/dev/null | grep -qE "^(200|301|302|404)$"; then
            log_success "  VolWeb backend ready (${volweb_wait}s)"
            break
        fi
        sleep 5
        ((volweb_wait+=5))
    done
    if [[ $volweb_wait -ge 90 ]]; then
        log_warn "  VolWeb backend not responding after 90s"
        capture_diagnostic_logs "VolWeb (backend start timeout)" intact_volweb_backend
    fi

    # Seed VolWeb admin user with the platform's tenroot credentials so
    # the IntactAI backend can auth without baking a second password
    # into ops. Idempotent — re-runs harmlessly skip.
    if ! seed_volweb_admin; then
        log_warn "  VolWeb admin seeding had issues — operator may need to do it manually"
    fi

    # Seed YARA rulesets via the VolWeb GitHub-import API. ~50 MB of
    # text into VolWeb's postgres; ~3 min on a fast link. Idempotent
    # — VolWeb dedupes on the (name, source) tuple.
    if ! seed_yara_rulesets; then
        log_warn "  YARA ruleset seeding had issues — refresh via Maintenance later"
    fi

    track_module_success "VolWeb"
}


# Ensures modules/volweb/secrets/ADMIN_PASSWORD exists and returns its
# content on stdout. Uses the operator's modules.volweb.password from
# config.yaml when set; otherwise generates a random per-install password
# instead of falling back to a fixed, publicly-documented string (same
# pattern as generate_iris_secrets' IRIS_ADM_PASSWORD / the Portainer admin
# password). Persisted so seed_volweb_admin() and seed_yara_rulesets()
# (which authenticates as the same user) always agree, and re-runs stay
# idempotent. Callers capture this via `$(get_volweb_admin_password)`, so
# any log output MUST go to stderr — only the password itself goes to
# stdout.
get_volweb_admin_password() {
    local secrets_dir="${SCRIPT_DIR}/modules/volweb/secrets"
    mkdir -p "$secrets_dir"
    local pass_file="$secrets_dir/ADMIN_PASSWORD"

    if [[ ! -s "$pass_file" ]]; then
        local volweb_pass
        volweb_pass=$(read_config "['modules']['volweb']['password']")
        if [[ -z "$volweb_pass" || "$volweb_pass" == "None" ]]; then
            volweb_pass=$(openssl rand -hex 16)
            {
                log_warn "  No VolWeb password set in config.yaml; generated a random one instead"
                log_warn "  Retrieve it with: cat ${pass_file}"
            } >&2
        fi
        printf '%s' "$volweb_pass" > "$pass_file"
        chmod 600 "$pass_file"
    fi
    cat "$pass_file"
}


seed_volweb_admin() {
    # Use the platform's VolWeb admin creds from config.yaml. Reads
    # ``modules.volweb.id`` for the username, and the persisted
    # admin password from get_volweb_admin_password() (config.yaml's
    # password when the operator set one, otherwise a random per-install
    # value generated on first run).
    local tenroot_user=$(read_config "['modules']['volweb']['id']")
    [[ -z "$tenroot_user" ]] && tenroot_user="tenroot"
    local tenroot_pass
    tenroot_pass=$(get_volweb_admin_password)

    log_info "  Seeding VolWeb admin user (${tenroot_user})..."
    docker exec --user app -w /home/app/web -i intact_volweb_backend python3 manage.py shell <<EOF 2>&1 | tail -3
from django.contrib.auth import get_user_model
U = get_user_model()
u, created = U.objects.get_or_create(username='${tenroot_user}', defaults={'is_superuser': True, 'is_staff': True})
u.is_superuser = True
u.is_staff = True
u.set_password('${tenroot_pass}')
u.save()
print('CREATED' if created else 'UPDATED', 'admin', u.username)
EOF
    return $?
}


seed_yara_rulesets() {
    # Three sources for the curated YARA corpus. Each is POSTed to
    # /api/yararulesets/import/github/ which clones the repo +
    # ingests every .yar / .yara file recursively.
    local volweb_user=$(read_config "['modules']['volweb']['id']")
    [[ -z "$volweb_user" ]] && volweb_user="tenroot"
    local volweb_pass
    volweb_pass=$(get_volweb_admin_password)

    log_info "  Seeding YARA rulesets (~3 min)..."

    # Get a JWT for the admin user we just seeded.
    local token=$(docker exec intact_volweb_backend curl -s -X POST \
        -H 'Content-Type: application/json' \
        -d "{\"username\":\"${volweb_user}\",\"password\":\"${volweb_pass}\"}" \
        http://localhost:8000/core/token/ \
        | python3 -c 'import sys,json; print(json.load(sys.stdin).get("access",""))' 2>/dev/null)
    if [[ -z "$token" ]]; then
        log_warn "    Could not get VolWeb JWT — skipping YARA seed"
        return 1
    fi

    # Tuples: name | github url | description
    local rulesets=(
        "Neo23x0 signature-base|https://github.com/Neo23x0/signature-base|Florian Roth's curated YARA rules (~749 active)"
        "Elastic protections|https://github.com/elastic/protections-artifacts|Elastic security YARA detection rules (~695 active)"
    )
    # NOTE: YARA-Forge was dropped here — its rules ship only as release
    # assets (the repo has zero .yar files), so import-from-github seeded
    # a single useless rule. The two curated repos above ship .yar files
    # in-tree and import natively. See routes/maintenance_routes.py +
    # upgrade/package.py.

    for entry in "${rulesets[@]}"; do
        local name="${entry%%|*}"
        local rest="${entry#*|}"
        local url="${rest%%|*}"
        local desc="${rest#*|}"

        log_info "    - ${name}..."
        local resp=$(docker exec intact_volweb_backend curl -s -X POST \
            -H "Authorization: Bearer ${token}" \
            -H 'Content-Type: application/json' \
            -d "{\"name\":\"${name}\",\"github_url\":\"${url}\",\"description\":\"${desc}\"}" \
            http://localhost:8000/api/yararulesets/import/github/)
        log_info "      ${resp:0:200}"
    done

    log_success "  YARA seeding dispatched (rule validation runs async in workers-yarascan)"
    return 0
}


# ============================================================================
# Backend API Module
# ============================================================================

deploy_backend() {
    log_info "[7/8] Starting Backend API..."
    log_info "  Directory: ${SCRIPT_DIR}/modules/backend"
    cd "${SCRIPT_DIR}/modules/backend"

    # Build
    log_info "  Building Backend Docker image..."
    if ! run_docker_compose "build" "Backend"; then
        log_error "  Failed to build Backend image"
        track_module_failure "Backend API"
        return 1
    fi
    log_success "  Backend image built successfully"

    # Start
    log_info "  Starting Backend container..."
    if ! run_compose_up_with_retry "Backend"; then
        log_error "  Failed to start Backend containers"
        track_module_failure "Backend API"
        return 1
    fi

    # Show container status
    show_container_status "intact_backend"

    # Wait for backend health endpoint
    log_info "  Waiting for Backend API health check (http://localhost:5001/api/health)..."
    local be_wait=0
    local be_max_wait=60
    local be_healthy=false
    while [[ $be_wait -lt $be_max_wait ]]; do
        if curl -sf --max-time 5 "http://localhost:5001/api/health" > /dev/null 2>&1; then
            log_success "  Backend API is healthy! (${be_wait}s)"
            be_healthy=true
            break
        fi
        sleep 5
        ((be_wait+=5))
        log_info "  Waiting for Backend API... (${be_wait}/${be_max_wait}s)"
    done

    if [[ "$be_healthy" != "true" ]]; then
        # Honest failure: the backend container started but its
        # /api/health endpoint never responded within 60s. Previously
        # this called `track_module_success "Backend API"` — a literal
        # falsehood that masked the failure and let install.sh print
        # "Installation Complete!" with exit 0 (see install_20260607
        # log). Switching to `track_module_failure` populates
        # FAILED_MODULES so the end-of-run summary in install.sh can
        # honestly report the install as failed and exit non-zero.
        log_error "  Backend API never responded to /api/health after 60s"
        capture_diagnostic_logs "Backend API (post-deploy timeout)" intact_backend
        track_module_failure "Backend API"
        return 1
    fi

    # ---- Bootstrap LLM model catalogs ----------------------------------
    # Persists each provider's model catalog to /app/data/<provider>_models.json
    # so the dashboard's model selector has results immediately on first
    # open. Best-effort: if a provider's API is unreachable (or the
    # operator hasn't configured an API key for that provider yet) the
    # bootstrap simply skips it and the on-demand fetch in the API
    # endpoint retries the next time Settings is opened. The maintenance
    # workflow refreshes all four catalogs later.
    #
    # Order matters: OpenRouter goes first because the three direct-
    # provider refreshes enrich their entries from the OpenRouter catalog.
    log_info "  Bootstrapping LLM model catalogs (best-effort)..."

    _bootstrap_one_catalog() {
        local label="$1"
        local route="$2"
        local resp count
        resp=$(curl -s --max-time 30 -X POST "http://localhost:5001${route}" 2>/dev/null)
        count=$(echo "$resp" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    print(d.get('model_count', 0) if d.get('success') else 0)
except Exception:
    print(0)
" 2>/dev/null)
        if [[ "${count:-0}" -gt 0 ]]; then
            log_success "    ${label}: ${count} models cached"
        else
            log_warn "    ${label}: deferred (no API key, network issue, or provider unreachable)"
        fi
    }

    # OpenRouter is the only catalog seeded at install — direct-provider
    # paths (Anthropic / OpenAI / Gemini) are gated behind the UI and
    # remain unused by default. Bootstrapping them produced "deferred"
    # warnings on every install since no API keys were configured.
    _bootstrap_one_catalog "OpenRouter" "/api/maintenance/refresh-openrouter-models"

    track_module_success "Backend API"
}

# ============================================================================
# Nginx Module
# ============================================================================

deploy_nginx() {
    log_info "[8/8] Starting Nginx (Web Server & Reverse Proxy)..."
    log_info "  Directory: ${SCRIPT_DIR}/modules/nginx"
    cd "${SCRIPT_DIR}/modules/nginx"

    if ! pull_compose_with_retry "Nginx"; then
        track_module_failure "Nginx"
        return 1
    fi
    if ! run_compose_up_with_retry "Nginx"; then
        log_error "  Docker compose failed!"
        track_module_failure "Nginx"
        return 1
    fi

    # Show container status
    show_container_status "intact_nginx"

    # Wait for Nginx
    log_info "  Waiting for Nginx container..."
    if wait_for_container "intact_nginx" 30; then
        log_success "  Nginx is ready"
        track_module_success "Nginx"
    else
        log_warn "  Nginx may not be fully ready"
        capture_diagnostic_logs "Nginx (container timeout)" intact_nginx
        track_module_success "Nginx"
    fi
}

# ============================================================================
# Main Service Deployment Orchestration
# ============================================================================

start_services() {
    log_info "=========================================="
    log_info "Starting Intact.AI Services"
    log_info "=========================================="
    echo ""

    cd "${SCRIPT_DIR}"

    # Generate secrets and certificates before starting services
    generate_iris_secrets
    echo ""
    generate_portainer_secrets
    echo ""
    generate_nginx_secrets
    echo ""
    generate_certificates
    echo ""
    ensure_shared_volumes
    echo ""

    # Deploy in order — 8 numbered steps [1/8]..[8/8]:
    # ELK, TimeSketch, Velociraptor, IRIS, Portainer, VolWeb, Backend, Nginx.
    deploy_elk
    echo ""
    deploy_timesketch
    echo ""
    deploy_velociraptor
    echo ""
    deploy_iris
    echo ""
    deploy_portainer
    echo ""
    deploy_volweb
    echo ""
    deploy_backend
    echo ""
    # IRIS api_key bootstrap — runs HERE (not inside deploy_iris) because
    # it writes into the backend container's SQLite secrets DB via
    # `docker exec intact_backend …`. Calling it before deploy_backend
    # meant intact_backend didn't exist yet and set_secret failed 100% of
    # the time on fresh installs. The IRIS-DB read inside the function
    # blocks until the admin row is populated, so it's safe to run here
    # even if IRIS's own migrations are still finishing.
    bootstrap_iris_api_key
    # Re-assert the IRIS admin password from config.yaml (IRIS only honours it at
    # first-init, so this fixes the "config password doesn't work" case).
    enforce_iris_admin_password
    echo ""
    deploy_nginx
    echo ""

    # Summary
    log_info "=========================================="
    log_info "Service deployment completed"
    log_info "=========================================="

    # Show all running containers
    echo ""
    log_info "Running Intact.AI containers:"
    docker ps --filter "name=intact_" --format "  {{.Names}}: {{.Status}}" 2>/dev/null

    cd "${SCRIPT_DIR}"
}
