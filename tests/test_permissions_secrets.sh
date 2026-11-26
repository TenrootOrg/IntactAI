#!/bin/bash
# lib/permissions.sh must not reopen secret material. Its blanket 755/644 sweep
# used to put every secrets/ dir back to 755 and every file outside a short
# exclusion list to 644 -- on every install and upgrade.
set -u
cd "$(dirname "${BASH_SOURCE[0]}")" || exit 1
source ./helpers.sh
LOG_FILE=/dev/null
source ../lib/common.sh
source ../lib/permissions.sh

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"; rm -f "${STUB_LOG}"' EXIT
SCRIPT_DIR="$WORK"

_mode() { stat -c %a "$WORK/$1"; }

test_sweep_keeps_secrets_private() {
    mkdir -p "$WORK"/modules/{elk,velociraptor,portainer}/secrets "$WORK/data/state/iris/secrets" \
             "$WORK/data/state/backend" "$WORK/data/tmp/intact-rollback-1/modules/elk" "$WORK/lib"
    ln -s ../../data/state/iris/secrets "$WORK/modules/iris/secrets" 2>/dev/null \
        || { mkdir -p "$WORK/modules/iris"; ln -s ../../data/state/iris/secrets "$WORK/modules/iris/secrets"; }
    echo x > "$WORK/modules/elk/secrets/creds.env"
    echo x > "$WORK/modules/velociraptor/secrets/creds.env"
    echo x > "$WORK/modules/portainer/secrets/admin_password"
    echo x > "$WORK/data/state/iris/secrets/IRIS_ADM_PASSWORD"
    echo x > "$WORK/data/state/iris/secrets/POSTGRES_PASSWORD"
    echo x > "$WORK/data/state/backend/setup_token"; chmod 600 "$WORK/data/state/backend/setup_token"
    echo x > "$WORK/data/state/default-passwords.json"
    # Upgrade backups: every old password the live files had.
    echo x > "$WORK/config.yaml.pre-upgrade-backup"
    echo x > "$WORK/config.yaml.pre-migration-backup"
    echo x > "$WORK/modules/elk/.env.upgrade-bak-20261101_101010"
    echo x > "$WORK/data/tmp/intact-rollback-1/backend.env.bak"
    mkdir -p "$WORK/modules/volweb" "$WORK/modules/nginx/html/js"
    echo x > "$WORK/modules/volweb/.env.template"
    echo x > "$WORK/modules/nginx/html/js/app.env.js"
    echo x > "$WORK/data/tmp/intact-rollback-1/modules/elk/.env"
    echo x > "$WORK/data/tmp/intact-rollback-1/config.yaml"
    echo x > "$WORK/lib/ordinary.sh"
    # The Timesketch SSO include: its header name signs a user in.
    mkdir -p "$WORK/modules/nginx/config/local"
    echo x > "$WORK/modules/nginx/config/local/timesketch-sso.conf"
    chmod -R a+rwX "$WORK/modules" "$WORK/data/tmp"
    chmod 666 "$WORK"/config.yaml.pre-* "$WORK/data/state/default-passwords.json"
    chmod 777 "$WORK/data/state/backend"

    fix_source_permissions >/dev/null 2>&1

    local d
    for d in modules/elk/secrets modules/velociraptor/secrets modules/portainer/secrets data/state/iris/secrets; do
        assert_eq "$(_mode "$d")" "700" "$d"
    done
    assert_eq "$(_mode modules/elk/secrets/creds.env)" "600" "elk creds.env"
    assert_eq "$(_mode modules/velociraptor/secrets/creds.env)" "600" "velociraptor creds.env"
    assert_eq "$(_mode modules/portainer/secrets/admin_password)" "600" "portainer admin_password"
    # IRIS reads these as uid 65534 through file bind mounts: 644 inside 700.
    assert_eq "$(_mode data/state/iris/secrets/IRIS_ADM_PASSWORD)" "644" "IRIS secret stays readable"
    assert_eq "$(_mode data/state/backend/setup_token)" "600" "setup token not reopened"
    assert_ne "$(_mode data/state/backend)" "755" "setup token dir not reopened"
    assert_eq "$(_mode data/state/default-passwords.json)" "600" "default-password marker"
    assert_eq "$(_mode config.yaml.pre-upgrade-backup)" "600" "config.yaml upgrade backup"
    assert_eq "$(_mode config.yaml.pre-migration-backup)" "600" "config.yaml migration backup"
    assert_eq "$(_mode modules/elk/.env.upgrade-bak-20261101_101010)" "600" ".env upgrade backup"
    assert_eq "$(_mode data/tmp/intact-rollback-1/backend.env.bak)" "600" "snapshot .env backup"
    assert_eq "$(_mode modules/volweb/.env.template)" "644" "template carries no secret, stays readable"
    assert_eq "$(_mode modules/nginx/html/js/app.env.js)" "644" "nginx keeps reading html/"
    assert_eq "$(_mode data/tmp/intact-rollback-1/modules/elk/.env)" "600" "snapshot .env"
    assert_eq "$(_mode data/tmp/intact-rollback-1/config.yaml)" "600" "snapshot config.yaml"
    assert_eq "$(_mode lib/ordinary.sh)" "755" "ordinary code still normalised (+x restored)"
    assert_eq "$(_mode modules/nginx/config/local/timesketch-sso.conf)" "600" "Timesketch SSO include private"
}

# The same backups must never reach git.
test_backups_are_gitignored() {
    git -C .. rev-parse --git-dir >/dev/null 2>&1 || { echo "  (skipped: not a git checkout)"; return 0; }
    local p
    for p in config.yaml.pre-upgrade-backup config.yaml.pre-migration-backup \
             modules/elk/.env.upgrade-bak-1 lib/upgrade/x.yaml.upgrade-bak-1; do
        assert_true git -C .. check-ignore -q "$p"
    done
    assert_false git -C .. check-ignore -q config.yaml       # the tracked template
}

run_all_tests
