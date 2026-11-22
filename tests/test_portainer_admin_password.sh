#!/usr/bin/env bash
# The Portainer admin password: nothing shipped, a usable one stored.
#
# History: config.yaml shipped `1234qwer!@#$`, then `Ch4nge-Me!Intact2026` --
# both public, both identical on every default install. It now ships an empty
# value, and the installer stores a password per box
# (ensure_module_credentials, lib/config.sh). Portainer enforces >= 12
# characters even via --admin-password-file; a shorter value leaves the admin
# silently uncreated and the UI stuck in its timed-out "initial setup". And it
# reads that file at FIRST start only, so a Portainer that already has data
# must never get a freshly minted one.
set -u
cd "$(dirname "${BASH_SOURCE[0]}")" || exit 1
source ./helpers.sh
ROOT="$(cd .. && pwd)"

LOG_FILE=/dev/null
source ../lib/common.sh
source ../lib/config.sh
source ../lib/modules/portainer.sh

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"; rm -f "${STUB_LOG}"' EXIT
SCRIPT_DIR="$WORK"
CONFIG_FILE="$WORK/config.yaml"
_cred_have_tty() { return 1; }
docker() { [[ "$*" == "volume inspect"* ]] && return 1; return 0; }   # no Portainer data
sync() { :; }

_config() {  # _config <password yaml value>
    rm -rf "$WORK/modules"
    printf "modules:\n  portainer:\n    enabled: true\n    id: admin\n    password: %s\n" "$1" > "$CONFIG_FILE"
}
_pw_file() { echo "$WORK/modules/portainer/secrets/admin_password"; }

test_the_repo_ships_no_portainer_password() {
    # The repo's config.yaml (sanitized on commit, blanked by every install).
    local shipped
    shipped="$(CONFIG_FILE="$ROOT/config.yaml" _config_password_raw portainer password)"
    assert_eq "$shipped" "" "modules.portainer.password ships empty"
}

test_empty_gives_a_stored_password_that_passes_the_rule() {
    _config "''"
    assert_true generate_portainer_secrets
    local pw; pw="$(cat "$(_pw_file)" 2>/dev/null)"
    assert_true secret_check "$pw"
    (( ${#pw} >= 12 )) || _fail "Portainer needs >= 12 characters, got ${#pw}"
    assert_eq "$(stat -c %a "$(_pw_file)")" "600" "admin_password is 0600"
    assert_eq "$(cut -c1-13 "$WORK/modules/portainer/secrets/agent.env")" "AGENT_SECRET=" "agent secret still made"
}

test_a_good_config_value_is_used_and_blanked() {
    _config "'Port1ainerPass9!'"
    assert_true generate_portainer_secrets
    assert_eq "$(cat "$(_pw_file)")" "Port1ainerPass9!" "operator's value seeds Portainer"
    assert_eq "$(_config_password_raw portainer password)" "" "and leaves config.yaml"
}

test_retired_and_short_values_are_refused_with_the_reason() {
    local v out
    for v in "'1234qwer!@#\$'" "'Ch4nge-Me!Intact2026'" "'Short1Aa'"; do
        _config "$v"
        out="$(ensure_module_credentials portainer 2>&1)"
        assert_false generate_portainer_secrets
        [[ -e "$(_pw_file)" ]] && _fail "stored a refused value ($v)"
        assert_contains "$out" "modules.portainer.password is not accepted" "names the key"
    done
    _config "'Short1Aa'"
    assert_contains "$(ensure_module_credentials portainer 2>&1)" "shorter than 12 characters" "names the condition"
}

# Existing data, nothing known: the install goes on with a placeholder file
# (Portainer ignores it after first start) marked so it is shown "unknown",
# never as a password that would not work.
test_existing_portainer_data_gets_a_marked_placeholder() {
    _config "''"
    docker() { [[ "$*" == "volume inspect portainer_portainer_data" ]] && return 0; [[ "$*" == "volume inspect"* ]] && return 1; return 0; }
    assert_true generate_portainer_secrets
    assert_true test -e "$(_pw_file).placeholder"
    assert_eq "$(cred_get portainer)" "unknown" "shown as unknown"
    docker() { [[ "$*" == "volume inspect"* ]] && return 1; return 0; }
}

test_aws_sigma_ships_enabled() {
    assert_eq "$(CONFIG_FILE="$ROOT/config.yaml" read_config "['modules']['aws_sigma']['enabled']")" "True" \
        "modules.aws_sigma.enabled is true in the repo config"
}

run_all_tests
