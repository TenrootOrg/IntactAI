#!/bin/bash
# lib/upgrade/plan.sh — what is installed, what the package offers, what to do.
#
# The comparator is the sharp edge here. A false "older" verdict lets a real
# downgrade through, and a downgrade is unrecoverable for the modules that
# matter: Elasticsearch refuses to open a data directory written by a newer
# version, and Postgres and OpenSearch forward-migrate their volumes on first
# boot with no way back. So the rule is conservative -- when the comparator
# cannot be sure, it must say "not older" and let the upgrade be refused
# elsewhere, never guess.

set -u
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./helpers.sh

LOG_FILE="$(mktemp)"
SCRIPT_DIR="$(mktemp -d)"
DOCKER_BIN=docker
source ../lib/common.sh
source ../lib/upgrade/core.sh
source ../lib/upgrade/health.sh
source ../lib/upgrade/plan.sh

log_info()    { echo "[INFO] $*" >> "$LOG_FILE"; }
log_success() { echo "[SUCCESS] $*" >> "$LOG_FILE"; }
log_warn()    { echo "[WARN] $*" >> "$LOG_FILE"; }
log_error()   { echo "[ERROR] $*" >> "$LOG_FILE"; }

_setup() {
    # `X=()` on a `declare -A` array silently converts it to an INDEXED array,
    # after which PLAN_ACTION[elk] evaluates 'elk' as arithmetic and dies under
    # set -u. Re-declare instead of clearing.
    unset PLAN_CURRENT PLAN_TARGET PLAN_ACTION UPKG_VERSIONS
    declare -gA PLAN_CURRENT=() PLAN_TARGET=() PLAN_ACTION=() UPKG_VERSIONS=()
    UPGRADE_ONLY=""; UPGRADE_SKIP=""
    : > "$LOG_FILE"
    # Everything enabled and installed unless a test says otherwise.
    read_config() { echo "True"; }
    _plan_module_enabled() { return 0; }
}

# ---------------------------------------------------------------------------
# The comparator
# ---------------------------------------------------------------------------

test_dotted_numeric_versions_compare_correctly() {
    _setup
    assert_true  _version_is_older 9.4.2 9.4.4
    assert_true  _version_is_older 9.4.4 9.5.0
    assert_true  _version_is_older 2.39.5 2.44.0
    assert_false _version_is_older 9.4.4 9.4.2
    assert_false _version_is_older 9.4.4 9.4.4
}

test_component_count_differences_are_handled() {
    # 2.39 vs 2.39.5 -- the missing component is zero, not "greater".
    _setup
    assert_true  _version_is_older 2.39 2.39.5
    assert_false _version_is_older 2.39.5 2.39
    assert_false _version_is_older 2.39 2.39.0
}

test_numeric_components_are_compared_as_numbers_not_strings() {
    # The one that bites: "10" < "9" lexically but 10 > 9 numerically.
    _setup
    assert_true  _version_is_older 9.9.9 9.10.0
    assert_false _version_is_older 9.10.0 9.9.9
    assert_true  _version_is_older 2.9.0 2.44.0
}

test_leading_zero_components_do_not_break_arithmetic() {
    # A bare 08 in $((...)) is an invalid octal literal and aborts the shell;
    # the comparator forces base 10.
    _setup
    assert_true  _version_is_older 2026.04 2026.08
    assert_false _version_is_older 2026.08 2026.04
    assert_true  _version_is_older 1.08.0 1.09.0
}

test_a_leading_v_is_ignored() {
    _setup
    assert_true  _version_is_older v2.4.26 v2.4.27
    assert_false _version_is_older v2.4.27 v2.4.26
    assert_true  _version_is_older v2.4.26 2.4.27
}

test_release_tags_compare_by_date() {
    _setup
    assert_true  _version_is_older intact-20260726 intact-20260809
    assert_false _version_is_older intact-20260809 intact-20260726
    assert_false _version_is_older intact-20260809 intact-20260809
}

test_timesketch_style_date_pins_compare_numerically() {
    _setup
    assert_true  _version_is_older 20260617 20260630
    assert_false _version_is_older 20260630 20260617
}

test_unorderable_versions_are_never_called_older() {
    # 'latest', a branch name, an alpine suffix, a git sha -- none of these
    # have an order. Saying nothing is the safe answer; saying "older" would
    # permit a downgrade.
    _setup
    assert_false _version_is_older latest 9.4.4
    assert_false _version_is_older 9.4.4 latest
    assert_false _version_is_older development intact-20260809
    assert_false _version_is_older 3-management-alpine 4-management-alpine
    assert_false _version_is_older 7.2.11-alpine 7.4.9-alpine
    assert_false _version_is_older "" 9.4.4
    assert_false _version_is_older 9.4.4 ""
}

# ---------------------------------------------------------------------------
# Downgrade refusal
# ---------------------------------------------------------------------------

test_a_downgrade_is_refused() {
    _setup
    PLAN_CURRENT[elk]=9.4.4; PLAN_TARGET[elk]=9.4.2; PLAN_ACTION[elk]=upgrade
    assert_false plan_reject_downgrades
    assert_contains "$(cat "$LOG_FILE")" "DOWNGRADE REFUSED: elk 9.4.4 -> 9.4.2"
}

test_every_downgrading_module_is_named_not_just_the_first() {
    # An operator who fixes only the module they were told about and re-runs
    # gets refused again. Name them all in one pass.
    _setup
    PLAN_CURRENT[elk]=9.4.4;    PLAN_TARGET[elk]=9.4.2;    PLAN_ACTION[elk]=upgrade
    PLAN_CURRENT[portainer]=2.39.5; PLAN_TARGET[portainer]=2.39.2; PLAN_ACTION[portainer]=upgrade
    assert_false plan_reject_downgrades
    assert_contains "$(cat "$LOG_FILE")" "elk 9.4.4 -> 9.4.2"
    assert_contains "$(cat "$LOG_FILE")" "portainer 2.39.5 -> 2.39.2"
}

test_a_genuine_upgrade_is_not_refused() {
    _setup
    PLAN_CURRENT[elk]=9.4.2; PLAN_TARGET[elk]=9.4.4; PLAN_ACTION[elk]=upgrade
    assert_true plan_reject_downgrades
}

test_modules_not_being_upgraded_are_not_downgrade_checked() {
    # A skipped or no-op module's target is irrelevant; checking it would
    # refuse the whole run over a module nothing is going to touch.
    _setup
    PLAN_CURRENT[elk]=9.4.4; PLAN_TARGET[elk]=9.4.2; PLAN_ACTION[elk]="skip:disabled in config.yaml"
    assert_true plan_reject_downgrades
}

# ---------------------------------------------------------------------------
# plan_build
# ---------------------------------------------------------------------------

test_same_version_is_a_noop() {
    _setup
    UPKG_VERSIONS[elk]=9.4.4; PLAN_CURRENT[elk]=9.4.4
    plan_build
    assert_contains "${PLAN_ACTION[elk]}" "noop"
}

test_a_module_absent_from_the_box_is_an_install() {
    _setup
    UPKG_VERSIONS[elk]=9.4.4; PLAN_CURRENT[elk]=""
    plan_build
    assert_eq "${PLAN_ACTION[elk]}" "install"
}

test_a_module_absent_from_the_package_is_skipped() {
    _setup
    PLAN_CURRENT[volweb]=3.16.0
    plan_build
    assert_contains "${PLAN_ACTION[volweb]}" "not in this package"
}

test_intact_is_never_a_noop_when_the_package_carries_it() {
    # A rolling tag can map to different commits, and skipping intact would
    # leave the box on the old backend code while every other module moved.
    _setup
    UPKG_VERSIONS[intact]=intact-20260809; PLAN_CURRENT[intact]=intact-20260809
    plan_build
    assert_eq "${PLAN_ACTION[intact]}" "upgrade"
}

test_only_restricts_the_set() {
    _setup
    UPKG_VERSIONS[elk]=9.4.5; PLAN_CURRENT[elk]=9.4.4
    UPKG_VERSIONS[iris]=v2.4.28; PLAN_CURRENT[iris]=v2.4.27
    UPGRADE_ONLY="elk"
    plan_build
    assert_eq "${PLAN_ACTION[elk]}" "upgrade"
    assert_contains "${PLAN_ACTION[iris]}" "excluded by --only"
}

test_skip_removes_from_the_set() {
    _setup
    UPKG_VERSIONS[elk]=9.4.5; PLAN_CURRENT[elk]=9.4.4
    UPKG_VERSIONS[iris]=v2.4.28; PLAN_CURRENT[iris]=v2.4.27
    UPGRADE_SKIP="elk"
    plan_build
    assert_contains "${PLAN_ACTION[elk]}" "excluded by --skip"
    assert_eq "${PLAN_ACTION[iris]}" "upgrade"
}

test_only_does_not_accidentally_match_a_substring() {
    # ",elk," inside ",velociraptor," must not match. The membership test is
    # comma-delimited for exactly this reason.
    _setup
    UPKG_VERSIONS[velociraptor]=0.77.1; PLAN_CURRENT[velociraptor]=0.76.6
    UPGRADE_ONLY="elk"
    plan_build
    assert_contains "${PLAN_ACTION[velociraptor]}" "excluded by --only"
}

test_a_disabled_module_is_skipped() {
    _setup
    _plan_module_enabled() { return 1; }
    UPKG_VERSIONS[elk]=9.4.5; PLAN_CURRENT[elk]=9.4.4
    plan_build
    assert_contains "${PLAN_ACTION[elk]}" "disabled in config.yaml"
}

test_a_module_with_no_enabled_key_defaults_to_enabled() {
    # Older config.yaml files predate several of these keys; defaulting them
    # off would silently skip a real upgrade.
    _setup
    read_config() { echo ""; }
    unset -f _plan_module_enabled
    source ../lib/upgrade/plan.sh
    read_config() { echo ""; }
    assert_true _plan_module_enabled elk
    read_config() { echo "None"; }
    assert_true _plan_module_enabled elk
    read_config() { echo "False"; }
    assert_false _plan_module_enabled elk
}

test_work_count_counts_only_real_work() {
    _setup
    PLAN_ACTION[elk]=upgrade
    PLAN_ACTION[iris]=install
    PLAN_ACTION[volweb]="noop:already at 3.16.0"
    PLAN_ACTION[portainer]="skip:disabled in config.yaml"
    assert_eq "$(plan_work_count)" "2"
}

test_intact_is_first_in_the_upgrade_order() {
    # It carries the new backend code, the sidecar compose files and the
    # config.yaml merge every later module reads its pins from.
    _setup
    assert_eq "${UPGRADE_ORDER[0]}" "intact"
}

test_every_module_in_the_order_has_a_pin_source() {
    # A module with no pin source reads as "not installed" forever and would
    # be reinstalled on every single upgrade.
    _setup
    local m
    for m in "${UPGRADE_ORDER[@]}"; do
        assert_ne "${_PIN_SOURCE[$m]:-}" "" "pin source for ${m}"
    done
}

run_all_tests
rm -f "$LOG_FILE"; rm -rf "$SCRIPT_DIR"
