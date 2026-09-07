#!/bin/bash
# scripts/adopt_velociraptor_identity.sh -- transplanting a risx-mssp
# Velociraptor identity onto an already-installed Intact box.
#
# WHY THIS FILE IS WORTH ITS LENGTH. The script's entire job is to be run ONCE,
# by an operator, against a customer's production fleet, with no rehearsal
# available to them. If it writes the wrong thing every deployed client goes
# silent -- and silently: a client that cannot verify the CA or match the nonce
# does not error anywhere the operator can see, it simply stops arriving.
#
# So the tests below run the real script rather than grepping it. A fake
# appliance root (config.yaml + compose file + the real lib/ and transform) is
# enough to exercise every guard through to --dry-run, which is the whole
# decision path: read both identities, judge reachability, warn, and stop.
#
# The three assertions that could not be executed offline -- backup-before-write,
# delete-the-derived-configs, --no-build -- are checked against the source, with
# the ordering that makes each one matter.

source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="${REPO}/scripts/adopt_velociraptor_identity.sh"

python3 -c 'import yaml' 2>/dev/null || {
    echo "$(basename "$0"): SKIP -- PyYAML not installed"; exit 0; }

# A fake appliance: just enough for the guards to pass, with the REAL lib/ and
# the REAL transform, so nothing under test is replaced by a stub.
_fake_root() {
    local root; root="$(mktemp -d)"
    mkdir -p "${root}/scripts" "${root}/modules/velociraptor" "${root}/data/velociraptor"
    cp "$SCRIPT" "${root}/scripts/"
    ln -s "${REPO}/lib" "${root}/lib"
    ln -s "${REPO}/scripts/migrate" "${root}/scripts/migrate"
    : > "${root}/modules/velociraptor/docker-compose.yaml"
    printf 'domain: 10.0.0.1\n' > "${root}/config.yaml"
    echo "$root"
}

# A config shaped like the one on the old risx box. Fake key material.
_legacy_config() {
    local path="$1" host="${2:-10.0.0.1}" nonce="${3:-SUPERSECRETNONCE=}"
    cat > "$path" <<YAML
version: {name: velociraptor, version: "0.74"}
Client:
  server_urls: ["https://${host}:8000/"]
  ca_certificate: "-----BEGIN CERTIFICATE-----\nFAKECA\n-----END CERTIFICATE-----"
  nonce: "${nonce}"
API: {bind_address: 127.0.0.1, bind_port: 8001}
GUI:
  bind_address: 127.0.0.1
  bind_port: 8889
  gw_certificate: GW
  gw_private_key: GWK
CA: {private_key: "-----BEGIN RSA PRIVATE KEY-----\nFAKEKEY\n-----END RSA PRIVATE KEY-----"}
Frontend:
  hostname: VelociraptorServer
  bind_address: 0.0.0.0
  bind_port: 8000
  certificate: FE
  private_key: FEK
  public_path: public
Datastore: {location: ".", filestore_directory: "."}
Logging: {output_directory: "."}
obfuscation_nonce: OBF
YAML
}

# --- the script answers for itself ------------------------------------------

test_help_explains_the_precondition_no_config_can_fix() {
    local out; out="$("$SCRIPT" --help 2>&1)"
    assert_contains "$out" "server_urls" "--help must name what pins a client"
    assert_contains "$out" "8000" "--help must name the port clients dial"
}

test_an_unknown_flag_is_refused_rather_than_ignored() {
    local rc=0; "$SCRIPT" --migrate-everything >/dev/null 2>&1 || rc=$?
    assert_eq "$rc" "2" "a typo'd flag must not fall through to a default"
}

test_it_refuses_to_run_outside_an_intact_checkout() {
    local root; root="$(mktemp -d)"
    mkdir -p "${root}/scripts"; cp "$SCRIPT" "${root}/scripts/"
    ln -s "${REPO}/lib" "${root}/lib"
    local out rc=0
    out="$("${root}/scripts/$(basename "$SCRIPT")" --dry-run --from /nonexistent 2>&1)" || rc=$?
    assert_ne "$rc" "0" "must not proceed without an appliance around it"
    assert_contains "$out" "not an Intact.AI appliance" "and must say so"
    rm -rf "$root"
}

test_from_is_required_because_there_is_no_sane_default() {
    local root out rc=0; root="$(_fake_root)"
    out="$("${root}/scripts/$(basename "$SCRIPT")" --dry-run 2>&1)" || rc=$?
    assert_ne "$rc" "0"
    assert_contains "$out" "--from is required"
    rm -rf "$root"
}

# --- the decision path, executed --------------------------------------------

test_a_dry_run_reports_the_identity_and_changes_nothing() {
    local root out rc=0; root="$(_fake_root)"
    _legacy_config "${root}/legacy.yaml" "10.0.0.1"
    out="$("${root}/scripts/$(basename "$SCRIPT")" --dry-run --from "${root}/legacy.yaml" 2>&1)" || rc=$?
    assert_eq "$rc" "0" "a dry run is not a failure"
    assert_contains "$out" "incoming CA" "it must show which identity it would adopt"
    assert_contains "$out" "nothing was changed"
    # THE POINT OF --dry-run: no config appeared.
    assert_false test -f "${root}/data/velociraptor/server.config.yaml"
    rm -rf "$root"
}

test_a_dry_run_says_it_would_clear_the_derived_configs() {
    # Not cosmetic: leaving a stale api.config.yaml hands the backend a file
    # signed by a CA the server no longer has, and the gRPC channel dies with
    # an error that names neither file.
    local root out; root="$(_fake_root)"
    _legacy_config "${root}/legacy.yaml"
    out="$("${root}/scripts/$(basename "$SCRIPT")" --dry-run --from "${root}/legacy.yaml" 2>&1)"
    assert_contains "$out" "client.config.yaml"
    assert_contains "$out" "api.config.yaml"
    rm -rf "$root"
}

test_it_warns_loudly_when_this_box_is_not_the_address_clients_dial() {
    # The one failure mode the script cannot repair, only report.
    local root out; root="$(_fake_root)"
    _legacy_config "${root}/legacy.yaml" "203.0.113.9"
    out="$("${root}/scripts/$(basename "$SCRIPT")" --dry-run --from "${root}/legacy.yaml" 2>&1)"
    assert_contains "$out" "203.0.113.9 AND THIS BOX IS NOT IT" \
        "a quiet note here loses the customer their fleet"
    assert_contains "$out" "DIVERGES"
    rm -rf "$root"
}

test_the_directory_form_of_from_finds_the_config() {
    # Operators will point at the folder they copied off the old box.
    local root out; root="$(_fake_root)"
    mkdir -p "${root}/old"
    _legacy_config "${root}/old/server.config.yaml"
    out="$("${root}/scripts/$(basename "$SCRIPT")" --dry-run --from "${root}/old" 2>&1)"
    assert_contains "$out" "incoming CA" "--from <dir> must resolve to server.config.yaml"
    rm -rf "$root"
}

test_adopting_an_identity_the_box_already_runs_is_a_no_op() {
    # Re-running after a partial failure must be safe: no stop, no swap.
    local root out rc=0; root="$(_fake_root)"
    _legacy_config "${root}/legacy.yaml"
    cp "${root}/legacy.yaml" "${root}/data/velociraptor/server.config.yaml"
    out="$("${root}/scripts/$(basename "$SCRIPT")" --dry-run --from "${root}/legacy.yaml" 2>&1)" || rc=$?
    assert_eq "$rc" "0"
    assert_contains "$out" "nothing to do"
    rm -rf "$root"
}

test_the_shared_secret_never_reaches_the_output_or_the_log() {
    # Client.nonce is the secret the server authenticates clients with, and this
    # script is run over someone's shoulder and its log attached to tickets.
    local root out; root="$(_fake_root)"
    _legacy_config "${root}/legacy.yaml" "10.0.0.1" "TOPSECRETNONCEVALUE="
    out="$("${root}/scripts/$(basename "$SCRIPT")" --dry-run --from "${root}/legacy.yaml" 2>&1)"
    assert_not_contains "$out" "TOPSECRETNONCEVALUE" "the nonce must never be printed"
    local logs; logs="$(cat "${root}"/*.log 2>/dev/null || true)"
    assert_not_contains "$logs" "TOPSECRETNONCEVALUE" "nor written to the log file"
    rm -rf "$root"
}

test_a_config_with_no_CA_is_refused_rather_than_guessed() {
    local root out rc=0; root="$(_fake_root)"
    printf 'Client:\n  server_urls: ["https://10.0.0.1:8000/"]\n' > "${root}/legacy.yaml"
    out="$("${root}/scripts/$(basename "$SCRIPT")" --dry-run --from "${root}/legacy.yaml" 2>&1)" || rc=$?
    assert_ne "$rc" "0"
    assert_contains "$out" "refusing to guess"
    rm -rf "$root"
}

test_a_real_run_needs_root() {
    if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then return 0; fi   # can't test as root
    local root out rc=0; root="$(_fake_root)"
    _legacy_config "${root}/legacy.yaml"
    out="$("${root}/scripts/$(basename "$SCRIPT")" -y --from "${root}/legacy.yaml" 2>&1)" || rc=$?
    assert_ne "$rc" "0" "writing the config and restarting the container needs root"
    assert_false test -f "${root}/data/velociraptor/server.config.yaml"
    rm -rf "$root"
}

# --- ordering, which only the source can show --------------------------------

_line_of() { grep -n -m1 -- "$1" "$SCRIPT" | cut -d: -f1; }

test_the_current_config_is_backed_up_before_anything_overwrites_it() {
    local backup write
    backup="$(_line_of 'velo-before-adopt-')"
    write="$(_line_of 'cp "$STAGED" "$HOST_CFG"')"
    assert_ne "$backup" "" "there must be a backup step"
    assert_ne "$write" "" "there must be a write step"
    assert_true test "$backup" -lt "$write"
}

test_the_transform_runs_before_the_container_is_stopped() {
    # A config the transform refuses must cost zero downtime.
    local xform stop
    xform="$(_line_of 'python3 "$TRANSFORM"')"
    stop="$(_line_of 'compose -f "$COMPOSE" stop')"
    assert_true test "$xform" -lt "$stop"
}

test_the_derived_configs_are_deleted_not_left_stale() {
    assert_true grep -q 'rm -f "${DATA}/client.config.yaml" "${DATA}/api.config.yaml"' "$SCRIPT"
}

test_restart_never_builds_or_pulls() {
    # Migrations run on air-gapped customer boxes; a pull is an outage.
    local n; n="$(grep -c -- '--no-build --pull never' "$SCRIPT")"
    assert_true test "$n" -ge 2   # the start path and the rollback path
    assert_false grep -q 'compose -f "$COMPOSE" up -d[^ ]*$' "$SCRIPT"
}

test_failure_after_the_swap_rolls_back() {
    assert_true grep -q '_rollback; _die' "$SCRIPT"
}

test_it_reuses_the_shared_transform_rather_than_reimplementing_it() {
    # Four places already implement this fingerprint/rewrite logic identically;
    # a fifth copy is how they drift apart.
    assert_true grep -q 'scripts/migrate/transform_config.py' "$SCRIPT"
    assert_false grep -q 'Datastore.*location.*=' "$SCRIPT"
}

run_all_tests
