#!/bin/bash
# Intact.AI Platform Installer — shared module-deployment plumbing.
#
# Cross-cutting helpers every deploy_<module> function in this directory
# relies on: docker compose wrappers with retry/heartbeat/timeout handling,
# host pre-flight checks, shared volume + certificate + dashboard-login
# bring-up, and the config.yaml -> .env transitive-pin stamper. Nothing in
# this file is specific to one module.
#
# Sibling files: one per module (elk.sh, timesketch.sh, velociraptor.sh,
# iris.sh, portainer.sh, volweb.sh, backend.sh, nginx.sh), and
# orchestrator.sh (start_services, plus the two secret-generation calls
# every module needs before deploy_* runs).

ensure_dashboard_login_is_reachable() {
    # Guard against a silent total lockout: config.yaml saying the login is
    # already set up (first_login: false) while the backend holds NO credential.
    # auth_service fails closed on that combination by design, so nobody can sign
    # in, and the only way out is knowing to set first_login: true by hand.
    #
    # It is easy to reach and gives no warning at install time:
    #   - restoring a config.yaml backup onto a fresh/wiped data/intact.db
    #     (exactly what happened on 2026-07-30 after a wipe-and-reinstall),
    #   - carrying config.yaml over to a rebuilt box,
    #   - any purge/restore that recreates the DB without the secrets table.
    #
    # Repairing it here beats handing back a finished install nobody can log in
    # to. It can only ever open setup on a box with NO credential at all, so it
    # cannot displace a working login.
    #
    # Deliberately NOT done from the app at runtime: the lockout path must never
    # auto-flip first_login, or an attacker fails 10 logins on purpose to claim
    # the setup page. An installer run is explicit and operator-initiated.

    local first_login
    first_login=$(read_config "['first_login']" 2>/dev/null)

    # Act only on an explicit false — absent or true already means setup mode.
    [[ "$first_login" == "False" || "$first_login" == "false" ]] || return 0

    # Ask the backend whether a credential actually exists.
    # Importing services.storage prints "[STORAGE] ..." banners to STDOUT, not
    # stderr, so the answer must be fished out by sentinel rather than read as
    # the whole of stdout — a plain capture yields banner text glued to the
    # answer and silently never matches.
    local has_cred
    has_cred=$(docker exec intact_backend python3 -c "
import sys; sys.path.insert(0,'/app')
from services.storage.secret_store import get_secret
print('INTACT_CRED:' + ('yes' if get_secret('auth_password_hash') else 'no'))
" 2>/dev/null | grep -o 'INTACT_CRED:[a-z]*' | tail -1)

    # Anything inconclusive (backend down, import failure, no sentinel) — leave
    # it alone rather than guess. Only a definite "no credential" repairs.
    [[ "$has_cred" == "INTACT_CRED:no" ]] || return 0

    log_warn "  Dashboard login: config.yaml says it is configured (first_login: false),"
    log_warn "  but no credential is stored — nobody would be able to sign in."
    log_warn "  Setting first_login: true so you can create one in the browser."

    # Truncate IN PLACE. config.yaml is bind-mounted into the backend BY INODE,
    # so write-temp-then-rename would leave the container's /app/config.yaml
    # pinned to the old bytes and it would read first_login: false forever.
    if python3 - "$CONFIG_FILE" <<'PYFIX'
import sys
p = sys.argv[1]
with open(p) as f:
    lines = f.read().splitlines(keepends=True)
hits = [i for i, l in enumerate(lines) if l.startswith("first_login:")]
if len(hits) != 1:
    sys.exit(1)
lines[hits[0]] = "first_login: true\n"
with open(p, "w") as f:          # truncate in place -- preserves the inode
    f.write("".join(lines))
PYFIX
    then
        log_warn "  Done — open the dashboard to set your username and password."
    else
        log_error "  Could not edit config.yaml; set 'first_login: true' there by hand."
    fi
}

generate_certificates() {
    log_info "Generating SSL certificates..."

    # DOMAIN is exported by exactly one thing in this repo: scripts/change_ip.sh.
    # install.sh never set it, so the old `${DOMAIN:-localhost}` meant EVERY
    # fresh install -- online and air-gapped alike -- issued CN=localhost for
    # the one cert that serves nginx (443), Kibana's native TLS (5601) and
    # IRIS's web cert. A name mismatch on every service, on a run that reports
    # SUCCESS. The 2026-08-16 air-gapped install logged, four lines apart:
    #     [INFO] Domain: 192.168.120.10
    #     [INFO]   Generating Nginx SSL certificate for domain: localhost
    # It stayed invisible because change_ip.sh DOES export DOMAIN and the
    # README recommends re-running it as the repair tool, so everyone who hit
    # this fixed it by accident.
    #
    # config.yaml is the same source lib/config.sh:386 already stamps
    # VELOX_PUBLIC_IP from, so the cert and Velociraptor now agree by
    # construction. change_ip.sh's export still takes precedence, so its
    # behaviour is unchanged.
    local domain="${DOMAIN:-$(read_config "['domain']")}"
    [[ -z "$domain" || "$domain" == "None" ]] && domain="localhost"

    # subjectAltName, not CN alone. Every current browser ignores CN for name
    # matching (RFC 2818 deprecated it; Chrome dropped the fallback in 58), so
    # a CN-only cert is rejected even when the CN is exactly right -- fixing
    # the CN above without this would swap one silent mismatch for another.
    #
    # localhost/127.0.0.1 are ALWAYS in the list alongside the real domain,
    # because the installer's own gates dial the loopback name:
    # "Waiting for TimeSketch API (https://localhost:5000)" and Kibana's
    # healthcheck on https://localhost:5601. Both pass -k today; keeping them
    # in the SAN means a later tightening cannot strand them.
    local san="DNS:localhost,IP:127.0.0.1"
    if [[ "$domain" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
        san="IP:${domain},${san}"
    elif [[ "$domain" != "localhost" ]]; then
        san="DNS:${domain},${san}"
    fi

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
        log_info "    subjectAltName: $san"
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout "$nginx_ssl/nginx-cert.key" \
            -out "$nginx_ssl/nginx-cert.crt" \
            -addext "subjectAltName=${san}" \
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
    # NEVER BUILD WHEN THE PACKAGE SUPPLIED THE IMAGES.
    #
    # Two reasons, and the second is the important one:
    #
    #  1. A build needs base layers -- python:3.11-slim for the backend,
    #     ubuntu:22.04 for velociraptor -- which the package does not carry, so
    #     on an air-gapped box the build simply cannot succeed.
    #  2. The package already contains the backend image CI built and tested.
    #     Building locally produces a DIFFERENT image under the same tag: same
    #     Dockerfile, different base digest, different wheel versions, different
    #     build date. Shipping a tested artifact and then quietly replacing it
    #     with an untested local rebuild is the exact class of divergence this
    #     whole change exists to end -- and it is invisible, because the tag
    #     looks right either way.
    #
    # The upgrade engine already refuses to build for the same reason
    # (ensure_backend_runtime_image: present -> load tar -> never build). This
    # brings install into line with it.
    #
    # THIS GUARD IS NOT SUFFICIENT ON ITS OWN and must not be mistaken for the
    # whole protection. It only short-circuits an EXPLICIT `build` action --
    # `docker compose up -d` still resolves a missing image by building it
    # (both the backend and velociraptor composes set `pull_policy: build`) or
    # by pulling it. That is exactly how a 20260804 install logged
    # "using the image from the release package (not rebuilding)" and then
    # rebuilt the backend from source on the very next line. The real guard is
    # the image-presence check in deploy_backend(); this stays as a cheap
    # second belt.
    if [[ "$action" == "build" && "${INTACT_FROM_PACKAGE:-0}" == "1" ]]; then
        log_info "  ${2:-module}: using the image from the release package (not rebuilding)"
        return 0
    fi
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
        # --no-build WHEN THE IMAGES CAME FROM THE PACKAGE.
        #
        # The `build`-action guard above is not enough on its own: both the
        # backend and velociraptor composes set `pull_policy: build`, which
        # makes `up -d` build the image REGARDLESS of whether it is already in
        # the local store. Observed 2026-08-04: the installer loaded the
        # shipped intact-backend:intact-20260804 (1.2 GB), deploy_backend
        # correctly logged "present ... not building", and `up -d` then rebuilt
        # it from source anyway over ~290 lines of live PyPI -- replacing the
        # tested artifact with an untested local build under the same tag, and
        # needing an internet connection to do it.
        #
        # deploy_backend has already asserted the image exists before we get
        # here, so --no-build cannot strand us: either the image is present and
        # is used, or compose fails loudly naming what is missing, which is the
        # outcome we want on an air-gapped box.
        #
        # --pull never IS THE OTHER HALF. Without it, a missing image is still
        # silently repaired by a registry pull -- which is how the platform's
        # own nginx went unbundled for as long as it did: on a connected box
        # `up -d` just fetched it, one line after the installer logged "images
        # already loaded from the package -- not pulling", and nothing was ever
        # wrong until someone tried it air-gapped.
        #
        # Held back until a release actually carried that image, because
        # turning it on earlier would have made [8/8] Nginx a hard failure on
        # every published release. intact-20260804 (rebuilt 2026-08-04 16:14)
        # ships images/intact-nginx-1.31.2-alpine.tar, and a clean-box install
        # verified it loads from the package -- so the flag can land.
        #
        # Together the two flags mean: after the download phase, a module
        # either deploys from what the package supplied or fails loudly naming
        # what is missing. It can no longer quietly reach the network, which is
        # the only property that makes an air-gapped install trustworthy.
        #
        # `--pull never` is checked for rather than assumed: it is Compose v2+
        # only, and a host with an older plugin should degrade to --no-build
        # rather than die on an unknown flag.
        local up_flags=()
        if [[ "${INTACT_FROM_PACKAGE:-0}" == "1" ]]; then
            up_flags+=(--no-build)
            if docker compose up --help 2>/dev/null | grep -q -- '--pull'; then
                up_flags+=(--pull never)
            else
                log_warn "  This docker compose has no 'up --pull' flag — a missing"
                log_warn "  image can still be pulled from a registry."
            fi
        fi
        run_with_heartbeat "${module_name} compose up" "$build_timeout" \
            bash -c '
                cd "$1" || exit 2
                # Bind the log path before shifting it away; everything after
                # the shift is the compose flag list ("$@").
                LOGF="$2"
                shift 2
                docker compose up -d "$@" 2>&1 | tee -a "$LOGF" | \
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
                # file already has the full output via `tee -a "$LOGF"` above —
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
                    tail -30 "$LOGF" | sed "s/^/      /"
                    echo "    ============================================================"
                    echo "    Full log: $LOGF"
                    echo "    ============================================================"
                fi
                exit "$rc"
            ' _ "$up_cwd" "$LOG_FILE" "${up_flags[@]}"
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
    # Installed from a package? Then every image this module needs is already in
    # the local store and `docker compose pull` has nothing to do but contact a
    # registry -- which is pointless online and impossible air-gapped. Skipping
    # here is what makes "install from the package" mean it: the per-image
    # helper already short-circuits, but compose pulls by service and would
    # otherwise still go out to the network for each one.
    if [[ "${INTACT_FROM_PACKAGE:-0}" == "1" ]]; then
        log_info "  ${module_name}: images already loaded from the package — not pulling"
        return 0
    fi
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
    # INSIDE A CONTAINER THIS CHECK CANNOT SEE WHAT IT IS ASKING ABOUT.
    #
    # The dashboard runs this engine in a helper container (upgrade_launcher.py:
    # `docker run -d --name intact-upgrade-runner-<run_id>`), and a container has
    # no systemd -- `systemctl is-system-running` answers "offline" there no
    # matter how healthy the host is. The question being asked is whether THE
    # HOST can create cgroup units, and the containers are created on the host
    # through the docker socket, so the host's systemd is what governs.
    #
    # Left as a hard failure, this made elk -- the only module that calls this --
    # roll back on EVERY dashboard-driven upgrade, while the same package applied
    # from a shell on the same box succeeded. Observed 2026-08-13:
    #   [preflight ELK Stack] systemd state = offline (cgroup-unit creation will fail)
    #   ↩ elk — host preflight (rc=1); restored to 9.4.2
    # with `systemctl is-system-running` reporting `running` on the host at the
    # same moment.
    #
    # So: skip the probe when we are demonstrably not on the host. Say so, rather
    # than passing silently -- an operator reading the log should know the check
    # was not performed instead of believing it passed.
    if [[ -f /.dockerenv ]] || grep -qa 'docker\|containerd' /proc/1/cgroup 2>/dev/null; then
        log_info "  [preflight $module_name] running in a container — skipping the systemd probe (the host's systemd governs, and it is not visible from here)"
    elif command -v systemctl >/dev/null 2>&1; then
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
    #
    # NOT ASKED AT ALL WHEN AIR-GAPPED. There is no internet by construction,
    # so "DNS lookup failed" is not a finding -- it is the premise. The
    # 2026-08-16 air-gapped install ended on 8 warnings of which FIVE were this
    # line, one per module, each printed immediately before that same module
    # logged "images already loaded from the package — not pulling". Warnings
    # that are always wrong train an operator to skim past the one that isn't.
    #
    # INTACT_AIRGAP is set by lib/args.sh (exported at :235) whenever --package
    # was given, and lib/deps.sh:536 already skips the connectivity check on
    # exactly this flag -- this is the same decision, one layer down. Say the
    # probe was skipped rather than passing silently, matching the convention
    # the systemd probe above already uses.
    if [[ "${INTACT_AIRGAP:-0}" == "1" ]]; then
        log_info "  [preflight $module_name] air-gapped — skipping the DNS probe (no registry or GitHub fetch will be attempted)"
    elif ! getent hosts github.com >/dev/null 2>&1; then
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
