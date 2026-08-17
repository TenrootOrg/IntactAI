#!/bin/bash
# Free-as-you-go on the upgrade path, and the guard that keeps it from
# deleting things it did not create.
#
# WHY. The installer has deleted each image tar the moment it loaded since the
# 22 GB-scratch measurement (lib/package.sh). The upgrade path never did, at
# any of its four `docker load` sites -- so a full release held every extracted
# tar on disk for the whole run, while plan_check_disk sized the run on the
# assumption that it did not. A customer box with 25 containers and 296 MiB of
# free memory sat on ~15 GB of tars it was never going to read again.
#
# The reason this needs a test suite rather than a one-line rm is that
# `--package /media/usb/<dir>` makes UPKG_DIR the OPERATOR'S OWN DIRECTORY.
# At an air-gapped site those files were carried in physically and are
# frequently the only copy in the building. Getting the guard wrong does not
# waste disk, it destroys a customer's media. Every assert below exists
# because of that, and the symlink one most of all.

source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Minimal logging shims -- the lib expects them, the suite does not need them.
_LOG=""
log_info()    { _LOG+="$*"$'\n'; }
log_warn()    { _LOG+="$*"$'\n'; }
log_error()   { _LOG+="$*"$'\n'; }
log_success() { _LOG+="$*"$'\n'; }

_human_size() { numfmt --to=iec "${1:-0}" 2>/dev/null || echo "${1:-0}B"; }
# upkg_extract wraps tar in run_with_heartbeat. The real one forks a heartbeat
# and uses `timeout --foreground`, whose signalling takes the test shell down
# with it -- and none of that is what these tests are about. Run the command.
run_with_heartbeat() { local d="$1" t="$2"; shift 2; "$@"; }
RUN_HEARTBEAT_ELAPSED=0

# Source only what we are testing. package.sh is self-contained for these two
# functions; sourcing the whole engine would drag in docker.
_setup() {
    _LOG=""
    SCRIPT_DIR="$(mktemp -d)"
    mkdir -p "${SCRIPT_DIR}/data/tmp"
    UPKG_SCRATCH=""
    U_TARS_FREED=0
    U_KEEP_SCRATCH=0
    unset _U_TAR_FREED; declare -gA _U_TAR_FREED
    INTACT_UPGRADE_KEEP_TARS=0
    INTACT_UPGRADE_LAZY_EXTRACT=0
    UPKG_DEFERRED=""; UPKG_DIR=""; UPKG_MANIFEST=""
    # shellcheck disable=SC1090
    source "${ROOT}/lib/upgrade/package.sh"
}
_teardown() { [[ -n "${SCRIPT_DIR:-}" && "$SCRIPT_DIR" == /tmp/* ]] && rm -rf "$SCRIPT_DIR"; }

# --- the guard ------------------------------------------------------------

test_a_tar_inside_registered_scratch_is_freed() {
    _setup
    local work="${SCRIPT_DIR}/data/tmp/upgrade-pkg-aaa"
    mkdir -p "${work}/intact-upgrade-t/images"
    local tar="${work}/intact-upgrade-t/images/elk.tar"
    echo body > "$tar"
    UPKG_SCRATCH="$work"
    assert_true upkg_path_is_our_scratch "$tar"
    upkg_release_loaded_tar "$tar"
    assert_false test -f "$tar"
    assert_ne "${U_TARS_FREED}" "0" "freed bytes must be counted"
    _teardown
}

test_a_tar_on_operator_media_is_never_freed() {
    _setup
    # The air-gap case: UPKG_SCRATCH is empty because nothing was extracted --
    # the operator handed us a tree they carried in.
    local media="${SCRIPT_DIR}/media/usb/intact-upgrade-t/images"
    mkdir -p "$media"
    local tar="${media}/elk.tar"
    echo body > "$tar"
    UPKG_SCRATCH=""
    assert_false upkg_path_is_our_scratch "$tar"
    upkg_release_loaded_tar "$tar"
    assert_true test -f "$tar"
    assert_contains "$_LOG" "not inside scratch this run created" "and say why"
    _teardown
}

test_a_symlink_out_of_scratch_is_not_followed_into_deletion() {
    _setup
    # The bug a string-prefix guard would have: images/ under our own scratch
    # name, but it is a symlink to the operator's media. The prefix matches;
    # the file does not live there.
    local media="${SCRIPT_DIR}/media/usb/images"
    mkdir -p "$media"
    local real="${media}/elk.tar"
    echo body > "$real"
    local work="${SCRIPT_DIR}/data/tmp/upgrade-pkg-bbb/intact-upgrade-t"
    mkdir -p "$work"
    ln -s "$media" "${work}/images"
    UPKG_SCRATCH="${SCRIPT_DIR}/data/tmp/upgrade-pkg-bbb"
    # The prefix matches but the file is elsewhere -- this must be refused.
    assert_false upkg_path_is_our_scratch "${work}/images/elk.tar"
    upkg_release_loaded_tar "${work}/images/elk.tar"
    assert_true test -f "$real"
    _teardown
}

test_an_unregistered_package_dir_keeps_its_tars() {
    _setup
    # `--package-dir` handed an ordinary directory (a hand retry against a tree
    # someone extracted themselves). Not our naming, not registered.
    local d="${SCRIPT_DIR}/somewhere/intact-upgrade-t/images"
    mkdir -p "$d"; echo body > "${d}/elk.tar"
    UPKG_SCRATCH=""
    upkg_release_loaded_tar "${d}/elk.tar"
    assert_true test -f "${d}/elk.tar"
    _teardown
}

test_a_retry_against_our_own_earlier_extraction_is_freed() {
    _setup
    # Rule 2: a later run, so UPKG_SCRATCH is empty, but the path is our own
    # naming under our own data/tmp -- we made it, we may free it.
    local d="${SCRIPT_DIR}/data/tmp/upgrade-pkg-ccc/intact-upgrade-t/images"
    mkdir -p "$d"; echo body > "${d}/elk.tar"
    UPKG_SCRATCH=""
    assert_true upkg_path_is_our_scratch "${d}/elk.tar"
    upkg_release_loaded_tar "${d}/elk.tar"
    assert_false test -f "${d}/elk.tar"
    _teardown
}

test_a_lookalike_directory_elsewhere_is_not_ours() {
    _setup
    # Same basename shape, wrong parent. Rule 2 is anchored to SCRIPT_DIR.
    local d="${SCRIPT_DIR}/elsewhere/upgrade-pkg-ddd/images"
    mkdir -p "$d"; echo body > "${d}/elk.tar"
    UPKG_SCRATCH=""
    # The name alone must not be enough -- it has to be under our data/tmp.
    assert_false upkg_path_is_our_scratch "${d}/elk.tar"
    _teardown
}

test_keep_tars_env_var_disables_freeing() {
    _setup
    local work="${SCRIPT_DIR}/data/tmp/upgrade-pkg-eee/images"
    mkdir -p "$work"; echo body > "${work}/elk.tar"
    UPKG_SCRATCH="${SCRIPT_DIR}/data/tmp/upgrade-pkg-eee"
    INTACT_UPGRADE_KEEP_TARS=1
    upkg_release_loaded_tar "${work}/elk.tar"
    assert_true test -f "${work}/elk.tar"
    _teardown
}

test_an_empty_or_missing_path_is_a_no_op() {
    _setup
    assert_true upkg_release_loaded_tar ""
    assert_true upkg_release_loaded_tar "/nonexistent/x.tar"
    assert_false upkg_path_is_our_scratch ""
    _teardown
}

# --- the call sites -------------------------------------------------------
# Structural asserts. A fifth `docker load` added later without going through
# the guard is exactly the regression this catches, and it cannot be caught by
# behaviour alone because the new site would simply never be called here.

test_every_upgrade_docker_load_frees_its_tar() {
    local f hits=0 miss=()
    while IFS= read -r f; do
        # Each load site must mention upkg_release_loaded_tar within 12 lines.
        local n; n="$(grep -n 'load -i' "$f" | cut -d: -f1 | head -1)"
        [[ -n "$n" ]] || continue
        hits=$((hits + 1))
        if ! sed -n "${n},$((n + 12))p" "$f" | grep -q 'upkg_release_loaded_tar'; then
            miss+=("$f")
        fi
    done < <(grep -rl 'load -i' "${ROOT}/lib/upgrade" --include='*.sh')
    assert_ne "$hits" "0" "should have found the docker load sites"
    assert_eq "${#miss[@]}" "0" "these load sites never free their tar: ${miss[*]:-}"
}

test_a_failed_load_keeps_scratch_for_retry() {
    # Every load site must set U_KEEP_SCRATCH on its failure path, so the EXIT
    # handler keeps the extraction instead of forcing a multi-GB re-download.
    local f miss=()
    for f in "${ROOT}/lib/upgrade/modules/shared.sh" \
             "${ROOT}/lib/upgrade/intact/image.sh" \
             "${ROOT}/lib/upgrade/velociraptor/image.sh"; do
        grep -q 'u_mark_keep_scratch' "$f" || miss+=("$(basename "$f")")
    done
    assert_eq "${#miss[@]}" "0" "no keep-on-failure in: ${miss[*]:-}"
}

# --- the sweeper ----------------------------------------------------------

test_the_sweeper_covers_install_path_names() {
    _setup
    local d="${SCRIPT_DIR}/data/tmp"
    mkdir -p "${d}/pkg-AAA" "${d}/unwrap-BBB" "${d}/upgrade-pkg-CCC"
    touch "${d}/load-DDD"
    touch -d '10 days ago' "${d}/pkg-AAA" "${d}/unwrap-BBB" "${d}/upgrade-pkg-CCC" "${d}/load-DDD"
    upkg_sweep_stale_scratch 48
    assert_false test -e "${d}/pkg-AAA"
    assert_false test -e "${d}/unwrap-BBB"
    assert_false test -e "${d}/upgrade-pkg-CCC"
    assert_false test -e "${d}/load-DDD"
    _teardown
}

test_the_sweeper_never_touches_run_records_or_the_lock() {
    _setup
    # This prevents a far worse bug than the one it tests for: a broad
    # `upgrade-*` pattern would eat the dashboard's run records and the live
    # flock target.
    local d="${SCRIPT_DIR}/data/tmp"
    mkdir -p "$d"
    touch "${d}/upgrade-run1.log" "${d}/upgrade-run1.done.json" "${d}/upgrade.lock"
    touch -d '10 days ago' "${d}/upgrade-run1.log" "${d}/upgrade-run1.done.json" "${d}/upgrade.lock"
    upkg_sweep_stale_scratch 48
    assert_true test -e "${d}/upgrade-run1.log"
    assert_true test -e "${d}/upgrade-run1.done.json"
    assert_true test -e "${d}/upgrade.lock"
    _teardown
}

test_the_sweeper_never_touches_a_staged_import() {
    _setup
    # import-pkg-* is deliberately absent from the patterns: the sweep runs at
    # the START of the next upgrade and would delete a staged package out from
    # under a run that has not begun extracting. See upgrade_routes.py.
    local d="${SCRIPT_DIR}/data/tmp"
    mkdir -p "${d}/import-pkg-run7"
    touch -d '10 days ago' "${d}/import-pkg-run7"
    upkg_sweep_stale_scratch 48
    assert_true test -e "${d}/import-pkg-run7"
    _teardown
}

test_the_download_dir_is_registered_for_cleanup() {
    # The leak: upgrade-dl-<TAG> was created but never registered, so
    # upkg_cleanup never removed it and only the 48h sweep ever did -- which is
    # why 2.2 GB of upgrade-dl-* was still on the dev box days later.
    local n
    n="$(grep -c 'UPKG_SCRATCH.*dl' "${ROOT}/scripts/upgrade.sh")"
    assert_ne "$n" "0" "the download dir must be registered in UPKG_SCRATCH"
}

# --- the EXIT trap --------------------------------------------------------

test_a_refused_precheck_leaves_no_scratch_behind() {
    _setup
    # The incident in lib/upgrade/interrupt.sh: a refusal for want of disk left
    # ~15 GB of extraction on the filesystem it had just measured, so the next
    # attempt was refused harder. Two cancelled runs took a 148 GB box from
    # 68 GB free to 4 GB.
    source "${ROOT}/lib/upgrade/interrupt.sh"
    local work="${SCRIPT_DIR}/data/tmp/upgrade-pkg-fff"
    mkdir -p "${work}/images"
    UPKG_SCRATCH="$work"
    U_KEEP_SCRATCH=0
    _u_exit_cleanup
    assert_false test -d "$work"
    _teardown
}

test_a_failed_load_keeps_the_extraction_and_prints_the_retry() {
    _setup
    source "${ROOT}/lib/upgrade/interrupt.sh"
    local work="${SCRIPT_DIR}/data/tmp/upgrade-pkg-ggg"
    mkdir -p "${work}/images"
    UPKG_SCRATCH="$work"; UPKG_DIR="$work"
    U_KEEP_SCRATCH=1
    _u_exit_cleanup
    assert_true test -d "$work"
    assert_contains "$_LOG" "--package-dir" "must print a runnable retry command"
    _teardown
}

test_the_exit_trap_preserves_the_exit_code() {
    _setup
    source "${ROOT}/lib/upgrade/interrupt.sh"
    UPKG_SCRATCH=""; U_KEEP_SCRATCH=0
    ( exit 7 ); _u_exit_cleanup
    assert_eq "$?" "7" "the trap must not swallow the run's exit status"
    _teardown
}

test_the_exit_trap_is_registered_after_the_stage0_hop() {
    # `exec` does not run EXIT traps, but registering BEFORE the hop would
    # still be wrong the day that changes -- the handing-over process must not
    # reclaim scratch the new one is about to read. Assert the ordering.
    #
    # The hop is now the exec into scripts/bootstrap_upgrade.sh, and it happens
    # BEFORE acquire rather than after it, so there is no extraction in flight
    # to protect at that point. The ordering assertion is kept anyway: it is
    # cheap, and "clean up only what this process owns" is the invariant, not
    # the particular hop it was written against.
    local hop trap_line
    hop="$(grep -n 'exec bash "$_boot"' "${ROOT}/scripts/upgrade.sh" | cut -d: -f1 | head -1)"
    trap_line="$(grep -n 'u_install_exit_cleanup_trap' "${ROOT}/scripts/upgrade.sh" | grep -v '^.*()' | cut -d: -f1 | tail -1)"
    assert_ne "$hop" "" "should find the stage-0 hop"
    assert_ne "$trap_line" "" "should find the trap registration"
    assert_true test "$trap_line" -gt "$hop"
}

# --- lazy (per-module) extraction ------------------------------------------
# Off by default. It moves WHEN verification happens, so it gets a real
# end-to-end exercise here rather than a grep.

_mkasset() {   # <dir> <tag> <module> <file>...  -> builds <tag>-<module>.tar
    local d="$1" tag="$2" mod="$3"; shift 3
    local stage; stage="$(mktemp -d)"
    mkdir -p "${stage}/intact-upgrade-${tag}/images"
    local f
    for f in "$@"; do printf '%s-payload' "$f" > "${stage}/intact-upgrade-${tag}/images/${f}"; done
    tar -cf "${d}/${tag}-${mod}.tar" -C "$stage" "intact-upgrade-${tag}"
    rm -rf "$stage"
}

test_asset_module_is_read_from_the_filename() {
    _setup
    UPGRADE_ORDER=(intact elk timesketch aws_sigma portainer)
    assert_eq "$(_upkg_asset_module /x/intact-20260813-elk.tar.gz)" "elk"
    assert_eq "$(_upkg_asset_module /x/intact-20260813-aws_sigma.tar)" "aws_sigma"
    assert_eq "$(_upkg_asset_module /x/intact-20260813-intact.tar)" "intact"
    # The legacy bundle ends in the tag, not a module, and must match nothing.
    assert_false _upkg_asset_module /x/intact-upgrade-intact-20260813.tar.gz
    _teardown
}

test_lazy_extraction_defers_everything_but_intact() {
    _setup
    UPGRADE_ORDER=(intact elk portainer)
    local d="${SCRIPT_DIR}/assets"; mkdir -p "$d"
    _mkasset "$d" t intact    backend.tar
    _mkasset "$d" t elk       elasticsearch.tar
    _mkasset "$d" t portainer portainer.tar
    INTACT_UPGRADE_LAZY_EXTRACT=1
    UPKG_DEFERRED=""
    upkg_extract "${d}/t-intact.tar" "${d}/t-elk.tar" "${d}/t-portainer.tar" >/dev/null 2>&1
    # intact is on disk; the other two are not.
    assert_true  test -f "${UPKG_DIR}/images/backend.tar"
    assert_false test -f "${UPKG_DIR}/images/elasticsearch.tar"
    assert_contains "${UPKG_DEFERRED}" "elk=" "elk must be deferred"
    assert_contains "${UPKG_DEFERRED}" "portainer=" "portainer must be deferred"
    assert_not_contains "${UPKG_DEFERRED}" "intact=" \
        "intact carries the engine the stage-0 hop execs into -- never deferred"
    _teardown
}

test_lazy_extraction_is_off_by_default() {
    _setup
    UPGRADE_ORDER=(intact elk)
    local d="${SCRIPT_DIR}/assets"; mkdir -p "$d"
    _mkasset "$d" t intact backend.tar
    _mkasset "$d" t elk    elasticsearch.tar
    UPKG_DEFERRED=""
    upkg_extract "${d}/t-intact.tar" "${d}/t-elk.tar" >/dev/null 2>&1
    assert_true test -f "${UPKG_DIR}/images/elasticsearch.tar"
    assert_eq "${UPKG_DEFERRED}" "" "nothing is deferred unless asked"
    _teardown
}

test_a_deferred_module_is_extracted_and_verified_at_its_turn() {
    _setup
    UPGRADE_ORDER=(intact elk)
    local d="${SCRIPT_DIR}/assets"; mkdir -p "$d"
    _mkasset "$d" t intact backend.tar
    _mkasset "$d" t elk    elasticsearch.tar
    INTACT_UPGRADE_LAZY_EXTRACT=1; UPKG_DEFERRED=""
    upkg_extract "${d}/t-intact.tar" "${d}/t-elk.tar" >/dev/null 2>&1
    # A manifest whose map covers the file elk will write.
    local sha; sha="$(sha256sum "${SCRIPT_DIR}/assets/../assets/t-elk.tar" >/dev/null 2>&1; printf '')"
    sha="$(printf 'elasticsearch.tar-payload' | sha256sum | cut -d' ' -f1)"
    printf '{"contents":{"sha256":{"images/elasticsearch.tar":"%s"}}}\n' "$sha" \
        > "${UPKG_DIR}/manifest.json"
    UPKG_MANIFEST="${UPKG_DIR}/manifest.json"
    assert_true upkg_extract_deferred elk
    assert_true test -f "${UPKG_DIR}/images/elasticsearch.tar"
    assert_not_contains "${UPKG_DEFERRED}" "elk=" "must drop off the deferred list once done"
    _teardown
}

test_a_deferred_module_whose_files_fail_the_manifest_is_refused() {
    _setup
    UPGRADE_ORDER=(intact elk)
    local d="${SCRIPT_DIR}/assets"; mkdir -p "$d"
    _mkasset "$d" t intact backend.tar
    _mkasset "$d" t elk    elasticsearch.tar
    INTACT_UPGRADE_LAZY_EXTRACT=1; UPKG_DEFERRED=""
    upkg_extract "${d}/t-intact.tar" "${d}/t-elk.tar" >/dev/null 2>&1
    # Map says a different hash: a swapped file inside an otherwise good asset.
    printf '{"contents":{"sha256":{"images/elasticsearch.tar":"%s"}}}\n' \
        "0000000000000000000000000000000000000000000000000000000000000000" \
        > "${UPKG_DIR}/manifest.json"
    UPKG_MANIFEST="${UPKG_DIR}/manifest.json"
    assert_false upkg_extract_deferred elk
    _teardown
}

test_a_file_absent_from_the_manifest_is_refused() {
    _setup
    UPGRADE_ORDER=(intact elk)
    local d="${SCRIPT_DIR}/assets"; mkdir -p "$d"
    _mkasset "$d" t intact backend.tar
    _mkasset "$d" t elk    elasticsearch.tar
    INTACT_UPGRADE_LAZY_EXTRACT=1; UPKG_DEFERRED=""
    upkg_extract "${d}/t-intact.tar" "${d}/t-elk.tar" >/dev/null 2>&1
    # An empty map: the scoped verifier's "unknown path" arm. A file the
    # release does not describe must never be silently accepted.
    printf '{"contents":{"sha256":{"images/something-else.tar":"aa"}}}\n' \
        > "${UPKG_DIR}/manifest.json"
    UPKG_MANIFEST="${UPKG_DIR}/manifest.json"
    assert_false upkg_extract_deferred elk
    _teardown
}

test_extract_deferred_is_a_noop_for_a_module_already_on_disk() {
    _setup
    UPKG_DEFERRED=""
    assert_true upkg_extract_deferred elk
    _teardown
}

test_the_deferred_map_does_not_need_to_cross_the_hop() {
    # It used to. The old hop fired AFTER acquire, so the re-exec'd process
    # skipped extraction entirely and had to inherit UPKG_DEFERRED or it would
    # reach each module's turn with nothing to extract -- upgrading nothing
    # while reporting success.
    #
    # The hop now fires BEFORE acquire, so the process that builds the deferred
    # map is the same one that consumes it. Exporting it across a hop that no
    # longer exists would be cargo cult; what matters is that acquire still
    # happens on the far side of the handover.
    local hop acquire
    hop="$(grep -n 'exec bash "$_boot"' "${ROOT}/scripts/upgrade.sh" | cut -d: -f1 | head -1)"
    acquire="$(grep -n -- '---------- acquire -----' "${ROOT}/scripts/upgrade.sh" | cut -d: -f1 | head -1)"
    assert_ne "$hop" "" "should find the stage-0 hop"
    assert_ne "$acquire" "" "should find the acquire phase"
    assert_true test "$acquire" -gt "$hop"
}

# --- state that must survive u_do's fork -----------------------------------
# u_do runs every step through _u_run_with_deadline, which forks `( "$@" ) &`.
# A shell variable set in that fork dies with it. The counter was merely
# cosmetic; U_KEEP_SCRATCH was not -- a FAILED image load could not mark the
# run, so the EXIT trap reclaimed the extraction anyway and the operator had to
# re-download several GB to retry, which is exactly what the flag prevents.
# Caught on a live run 2026-08-13, invisible to tests that call these directly.

test_freed_bytes_survive_a_subshell() {
    _setup
    local work="${SCRIPT_DIR}/data/tmp/upgrade-pkg-sub"
    mkdir -p "${work}/images"
    head -c 4096 /dev/zero > "${work}/images/x.tar"
    UPKG_SCRATCH="$work"
    # exactly how u_do invokes a step
    ( upkg_release_loaded_tar "${work}/images/x.tar" ) &
    wait
    assert_false test -f "${work}/images/x.tar"
    assert_ne "$(u_tars_freed_bytes)" "0" "the tally must cross the fork"
    _teardown
}

test_keep_scratch_survives_a_subshell() {
    _setup
    mkdir -p "${SCRIPT_DIR}/data/tmp"
    assert_false u_keep_scratch_requested
    ( u_mark_keep_scratch ) &
    wait
    assert_true u_keep_scratch_requested
    _teardown
}

test_every_keep_scratch_call_site_uses_the_helper() {
    # A bare `U_KEEP_SCRATCH=1` inside a step is silently lost. Assert none
    # remain in the module code.
    local hits
    # package.sh holds the helper (and its comment); everywhere else must call it.
    hits="$(grep -rn 'U_KEEP_SCRATCH=1' "${ROOT}/lib/upgrade" --include='*.sh' \
            | grep -v '/package\.sh:' || true)"
    assert_eq "${hits}" "" "these assign U_KEEP_SCRATCH directly and will not survive u_do's fork"
}

test_run_state_is_cleared() {
    _setup
    mkdir -p "${SCRIPT_DIR}/data/tmp"
    u_mark_keep_scratch
    printf '10\n' >> "$(_upkg_tally_file)"
    u_clear_run_state
    assert_false u_keep_scratch_requested
    assert_eq "$(u_tars_freed_bytes)" "0"
    _teardown
}

run_all_tests
