#!/bin/bash
# Intact.AI Platform Installer - Source File Permissions
#
# The post-install ownership/mode sweep, plus the corrective hardening pass
# that re-tightens every secret the blanket sweep would otherwise leave
# world-readable.
#
# Split out of install.sh unchanged.

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
    #
    # IRIS's own 5 app/postgres secrets are EXCLUDED here on purpose --
    # see the dedicated 644 pass a few lines down for why. Every other
    # module's secrets/ and every .env still get the blanket 600.
    # find -L: FOLLOW SYMLINKS.
    #
    # lib/state_registry.sh relocates some per-box state into data/state/ and
    # leaves a symlink at the historical path -- modules/iris/secrets and
    # modules/timesketch/secrets are both directory symlinks on any box that
    # has upgraded. Plain `find` does not follow symlinks, not even as a
    # starting argument, so every file behind them was silently exempt from
    # this hardening sweep. Measured on a live box 2026-08-25: `find` saw 8
    # files under modules/*/secrets, `find -L` saw 15.
    #
    # Safe for the five IRIS secrets: they are excluded below and then
    # explicitly restored to 644 by the pass further down, so following the
    # symlink does not put them back to 600. The one file whose mode actually
    # changes is modules/timesketch/secrets/postgres.env (644 -> 600), which is
    # consumed via `env_file` -- read by the Docker daemon as root at container
    # create and injected as environment variables. Nothing mounts it and no
    # container process opens it, so the 65534-cannot-read failure described
    # below does not apply to it.
    find -L "${SCRIPT_DIR}/modules" -type f \( -path "*/secrets/*" -o -name ".env" \) \
        -not -path "*/modules/iris/secrets/IRIS_ADM_PASSWORD" \
        -not -path "*/modules/iris/secrets/IRIS_SECRET_KEY" \
        -not -path "*/modules/iris/secrets/IRIS_SECURITY_PASSWORD_SALT" \
        -not -path "*/modules/iris/secrets/POSTGRES_ADMIN_PASSWORD" \
        -not -path "*/modules/iris/secrets/POSTGRES_PASSWORD" \
        -exec chmod 600 {} \; 2>/dev/null || true
    # These 5 stay 644 (world-readable), matching
    # services/upgrade/iris.py:399-423's documented policy exactly --
    # iris_app and iris_worker run their gunicorn/celery processes as
    # `nobody` (uid 65534), and these secrets are bind-mounted into
    # /run/secrets/ owned by whatever this chown -R above just set
    # (this script's own uid, e.g. 1000). A 600 file owned by a UID that
    # isn't 65534 is unreadable to `nobody`; IRIS then reads an empty
    # password, connects with "", and its gunicorn workers crash-loop on
    # "password authentication failed for user postgres" the next time
    # intact_iris_app is recreated for ANY reason (upgrade, `docker
    # compose restart`, host reboot) -- NOT at first boot, which is why
    # this went unnoticed: generate_iris_secrets() (lib/modules/iris.sh)
    # creates these files at the default umask (644), so the FIRST
    # deploy_iris works fine, and only breaks on the next recreate after
    # THIS blanket 600 sweep has already reverted them. Confirmed live on
    # 2026-08-05: an online upgrade recreated intact_iris_app and it
    # crash-looped with exactly this error; restoring 644 fixed it
    # immediately, no data or credentials touched.
    # -L for the same reason as above: on a migrated box this path IS a symlink,
    # so without it this corrective 644 pass never ran at all -- the files kept
    # whatever mode generate_iris_secrets left them at (644, by umask) and were
    # correct only by accident.
    find -L "${SCRIPT_DIR}/modules/iris/secrets" -maxdepth 1 -type f \
        \( -name IRIS_ADM_PASSWORD -o -name IRIS_SECRET_KEY \
           -o -name IRIS_SECURITY_PASSWORD_SALT \
           -o -name POSTGRES_ADMIN_PASSWORD -o -name POSTGRES_PASSWORD \) \
        -exec chmod 644 {} \; 2>/dev/null || true
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
    # ...and the Python ones beside them. The globs here are per-extension, so
    # `scripts/*.sh` does not cover `scripts/*.py` -- which meant the 644 sweep
    # de-executed the first top-level Python script added to that directory
    # (make_single_package.py) on every install, and the repo showed a
    # permanently dirty mode change nobody could explain. scripts/migrate/*.py
    # below already had this line; the top level was simply missed.
    chmod +x "${SCRIPT_DIR}/scripts/"*.py 2>/dev/null || true
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
    # Same omission as scripts/*.py above, one directory over: `scripts/*.sh`
    # does not reach scripts/dev/, so the 644 sweep de-executed
    # build_local_release.sh on every install. The symptom is a permanently
    # dirty `git status` showing a mode-only 100755 -> 100644 change with no
    # content diff, which reads as leftover work-in-progress and isn't.
    chmod +x "${SCRIPT_DIR}/scripts/dev/"*.sh 2>/dev/null || true
    # tests/ is exercised by CI (tests/run_tests.sh invokes each suite as its
    # own bash subprocess, so this is cosmetic there) but a developer running
    # ./tests/test_foo.sh directly after an install gets "Permission denied".
    chmod +x "${SCRIPT_DIR}/tests/"*.sh 2>/dev/null || true
    chmod +x "${SCRIPT_DIR}/modules/elk/config/"*.sh 2>/dev/null || true
    chmod +x "${SCRIPT_DIR}/modules/nginx/build-tailwind.sh" 2>/dev/null || true

    log_info "Source file permissions fixed"
}
