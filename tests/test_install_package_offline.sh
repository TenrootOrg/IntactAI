#!/bin/bash
# install.sh --package, the offline path, on synthetic packages (no docker, no
# network). One test group per audit fix (2026-11-24):
#   1. the package's manifest pins every module and sidecar in config.yaml,
#      not just the backend, so compose never looks for an image it lacks;
#   2. assets are checked against <tag>.index.json before extraction;
#   3. a directory --package joins split assets (*.tar.part-NN);
#   4. the unwrap scratch goes on ANY exit, a full disk is refused up front,
#      and gzip module assets are not decompressed just to probe them;
#   9. an older package never downgrades the Volatility symbol pack.

set -u
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./helpers.sh

LOG_FILE="$(mktemp)"
SCRIPT_DIR="$(mktemp -d)"
trap 'rm -rf "$SCRIPT_DIR" "$LOG_FILE"' EXIT
source ../lib/common.sh
source ../lib/config.sh
source ../lib/args.sh
source ../lib/package.sh
source ../lib/modules/volweb.sh
LOGGED="$(mktemp)"
log_info()    { echo "INFO $*" >> "$LOGGED"; }
log_warn()    { echo "WARN $*" >> "$LOGGED"; }
log_error()   { echo "ERROR $*" >> "$LOGGED"; }
log_success() { echo "OK $*" >> "$LOGGED"; }
# The real one leaves its heartbeat's `sleep 60` holding stdout, so a caller
# reading this suite through a pipe waits a minute for nothing.
run_with_heartbeat() { shift 2; "$@"; }

_sha() { sha256sum "$1" | awk '{print $1}'; }

# A module asset: a tar whose members share one top-level directory.
_asset() {   # <path> <module>
    local w; w="$(mktemp -d)"
    mkdir -p "$w/intact-upgrade-t1"
    echo "payload of $2" > "$w/intact-upgrade-t1/$2.marker"
    tar -cf "$1" -C "$w" intact-upgrade-t1
    rm -rf "$w"
}

# ---------------------------------------------------------------- fix 1
_pin_setup() {
    CONFIG_FILE="$(mktemp -p "$SCRIPT_DIR")"
    cat > "$CONFIG_FILE" <<'YAML'
versions:
  elk: '9.5.6'
  iris: v2.4.29
  velociraptor: '0.77.3'
  backend: 'intact-t0'
  timesketch_postgres:   '13.0-alpine'
  volweb_redis:          '7.4.9'
  nginx:                 '1.31.7-alpine'
  backend_tusd:          'v2.10.1'
YAML
    WORK="$(mktemp -d -p "$SCRIPT_DIR")"
    mkdir -p "$WORK/intact-upgrade-t1/manifests"
    # The root manifest is whichever asset extracted last: here it disagrees
    # with the elk sidecar, which must win for elk.
    cat > "$WORK/intact-upgrade-t1/manifest.json" <<'JSON'
{"versions": {"elk": "9.0.0", "intact": "intact-t1", "velociraptor": "0.77.4"},
 "contents": {"transitive_versions": {
     "timesketch": {"POSTGRES_VERSION": "15.6-alpine", "OPENSEARCH_VERSION": "2.19.5"},
     "volweb": {"VOLWEB_REDIS_VERSION": "7.4.9"}},
   "images": ["tusd-v2.11.0.tar", "intact-nginx-1.31.8-alpine.tar"]}}
JSON
    echo '{"versions": {"elk": "9.5.7"}}' > "$WORK/intact-upgrade-t1/manifests/elk.json"
    echo '{"versions": {"iris": "v2.4.29; rm -rf /"}}' > "$WORK/intact-upgrade-t1/manifests/iris.json"
}
_pin() { python3 -c "import yaml,sys; print(yaml.safe_load(open(sys.argv[1]))['versions'].get(sys.argv[2]))" "$CONFIG_FILE" "$1"; }

test_pins_follow_the_package_manifest() {
    _pin_setup
    local inode; inode="$(stat -c %i "$CONFIG_FILE")"
    _pkg_pin_versions_from_manifest "$WORK"
    assert_eq "$(_pin elk)" "9.5.7" "the module's own sidecar manifest wins over the root one"
    assert_eq "$(_pin velociraptor)" "0.77.4" "velociraptor follows the package (its .version check reads this)"
    assert_eq "$(_pin timesketch_postgres)" "15.6-alpine" "a transitive pin keyed by env var follows the package"
    assert_eq "$(_pin backend_tusd)" "v2.11.0" "tusd follows the image tar the package carries"
    assert_eq "$(_pin nginx)" "1.31.8-alpine" "the main nginx follows its image tar"
    assert_eq "$(_pin backend)" "intact-t0" "versions.backend is left to update_env_files"
    assert_eq "$(_pin iris)" "v2.4.29" "a value that is not a version is refused"
    assert_eq "$(_pin timesketch_opensearch)" "None" "a sidecar key config.yaml does not have is not invented"
    assert_eq "$(stat -c %i "$CONFIG_FILE")" "$inode" "config.yaml is edited in place (bind-mounted by inode)"
    assert_contains "$(cat "$LOGGED")" "versions.elk is '9.5.6' but the package carries 9.5.7" "each change is logged"
}

test_pins_untouched_when_they_already_match() {
    _pin_setup
    cat > "$WORK/intact-upgrade-t1/manifest.json" <<'JSON'
{"versions": {"elk": "9.5.6", "velociraptor": "0.77.3"}}
JSON
    rm -f "$WORK"/intact-upgrade-t1/manifests/*.json
    local before; before="$(cat "$CONFIG_FILE")"
    : > "$LOGGED"
    _pkg_pin_versions_from_manifest "$WORK"
    assert_eq "$(cat "$CONFIG_FILE")" "$before" "nothing to change, nothing written"
    assert_not_contains "$(cat "$LOGGED")" "pinning" "and nothing logged as changed"
}

test_an_older_package_never_pins_a_module_back() {
    _pin_setup
    cat > "$WORK/intact-upgrade-t1/manifest.json" <<'JSON'
{"versions": {"elk": "9.4.4", "velociraptor": "0.77.4"}}
JSON
    rm -f "$WORK"/intact-upgrade-t1/manifests/*.json
    : > "$LOGGED"
    _pkg_pin_versions_from_manifest "$WORK"
    assert_eq "$(_pin elk)" "9.5.6" "Elasticsearch cannot open data a newer version wrote"
    assert_eq "$(_pin velociraptor)" "0.77.4" "a newer version is still pinned"
    assert_contains "$(cat "$LOGGED")" "older than this box's 9.5.6" "and the refusal is logged"
}

test_the_upgrades_add_only_pass_never_stamps_airgap() {
    # upgrade.sh exports INTACT_AIRGAP=1 for any --package run; its add-only
    # re-render must not write it onto an online box (reviewer, 2026-11-24).
    local guard
    guard="$(grep -A1 'INTACT_AIRGAP:-}' ../lib/config.sh | tr -d '\n')"
    assert_contains "$guard" 'UPDATE_ENV_ADD_ONLY:-0}" != 1' "only an install decides the backend's INTACT_AIRGAP"
}

# ---------------------------------------------------------------- fix 2
_index() {   # <out> <asset>... : an index with the real sha256/size of each
    python3 - "$@" <<'PY'
import hashlib, json, os, sys
out, assets = sys.argv[1], sys.argv[2:]
idx = {"assets": {}}
for a in assets:
    idx["assets"][os.path.basename(a)] = {"asset": os.path.basename(a), "size": os.path.getsize(a),
        "sha256": hashlib.sha256(open(a, "rb").read()).hexdigest()}
json.dump(idx, open(out, "w"))
PY
}

test_index_verifies_good_assets() {
    local d; d="$(mktemp -d -p "$SCRIPT_DIR")"
    _asset "$d/t1-elk.tar" elk; _asset "$d/t1-iris.tar" iris
    _index "$d/t1.index.json" "$d/t1-elk.tar" "$d/t1-iris.tar"
    : > "$LOGGED"
    assert_true _pkg_verify_against_index "$d/t1.index.json" "$d/t1-elk.tar" "$d/t1-iris.tar"
    _pkg_verify_against_index "$d/t1.index.json" "$d/t1-elk.tar" "$d/t1-iris.tar"
    assert_contains "$(cat "$LOGGED")" "2 asset(s) checksum-verified"
}

test_index_refuses_a_damaged_asset() {
    local d; d="$(mktemp -d -p "$SCRIPT_DIR")"
    _asset "$d/t1-elk.tar" elk
    _index "$d/t1.index.json" "$d/t1-elk.tar"
    # Same size, different bytes: only the sha256 can tell.
    printf 'X' | dd of="$d/t1-elk.tar" bs=1 seek=600 conv=notrunc 2>/dev/null
    : > "$LOGGED"
    assert_false _pkg_verify_against_index "$d/t1.index.json" "$d/t1-elk.tar"
    assert_contains "$(cat "$LOGGED")" "t1-elk.tar FAILED its checksum"
}

test_index_refuses_a_truncated_asset() {
    local d; d="$(mktemp -d -p "$SCRIPT_DIR")"
    _asset "$d/t1-elk.tar" elk
    _index "$d/t1.index.json" "$d/t1-elk.tar"
    truncate -s 1024 "$d/t1-elk.tar"
    : > "$LOGGED"
    assert_false _pkg_verify_against_index "$d/t1.index.json" "$d/t1-elk.tar"
    assert_contains "$(cat "$LOGGED")" "truncated"
}

test_an_unindexed_asset_installs_with_a_warning() {
    local d; d="$(mktemp -d -p "$SCRIPT_DIR")"
    _asset "$d/t1-elk.tar" elk; _asset "$d/renamed.tar" iris
    _index "$d/t1.index.json" "$d/t1-elk.tar"
    : > "$LOGGED"
    assert_true _pkg_verify_against_index "$d/t1.index.json" "$d/t1-elk.tar" "$d/renamed.tar"
    assert_contains "$(cat "$LOGGED")" "renamed.tar: not in t1.index.json"
}

test_load_stops_before_extracting_a_damaged_asset() {
    local d; d="$(mktemp -d -p "$SCRIPT_DIR")"
    _asset "$d/t1-elk.tar" elk
    _index "$d/t1.index.json" "$d/t1-elk.tar"
    truncate -s 1024 "$d/t1-elk.tar"
    parse_install_args --package "$d"
    assert_eq "$INTACT_PACKAGE_INDEX" "$d/t1.index.json" "a directory's index is found"
    : > "$LOGGED"
    assert_false load_images_from_package "${INTACT_PACKAGES[@]}"
    assert_contains "$(cat "$LOGGED")" "truncated" "stopped by the index check, not by tar"
    assert_eq "$(find "$SCRIPT_DIR/data/tmp" -maxdepth 1 -name 'pkg-*' 2>/dev/null | wc -l)" "0" \
        "nothing was extracted"
}

test_a_wrapper_carries_its_index_in() {
    local w; w="$(mktemp -d -p "$SCRIPT_DIR")"
    _asset "$w/t1-elk.tar" elk
    _index "$w/t1.index.json" "$w/t1-elk.tar"
    tar -cf "$SCRIPT_DIR/t1-package.tar" -C "$w" t1.index.json t1-elk.tar
    parse_install_args --package "$SCRIPT_DIR/t1-package.tar"
    assert_contains "$INTACT_PACKAGE_INDEX" "/t1.index.json" "the index is unwrapped with the assets"
    assert_true _pkg_verify_against_index "$INTACT_PACKAGE_INDEX" "${INTACT_PACKAGES[@]}"
    rm -rf "${INTACT_UNWRAP_DIRS[@]}"
}

# ---------------------------------------------- disk peak (2026-11-24)
test_unpacked_size_reads_gzip_and_falls_back_when_wrapped() {
    local d; d="$(mktemp -d -p "$SCRIPT_DIR")"
    head -c 3000000 /dev/zero > "$d/raw"
    gzip -c "$d/raw" > "$d/a.tar.gz"
    assert_eq "$(_pkg_unpacked_size "$d/a.tar.gz")" "3000000" "gzip -l's unpacked size"
    assert_eq "$(_pkg_unpacked_size "$d/raw")" "3000000" "a plain tar is its own size"
    # A >4 GiB asset wraps the trailer's size: zero it, as if it had.
    printf '\0\0\0\0' | dd of="$d/a.tar.gz" bs=1 seek=$(( $(stat -c%s "$d/a.tar.gz") - 4 )) conv=notrunc 2>/dev/null
    assert_eq "$(_pkg_unpacked_size "$d/a.tar.gz")" "$(( $(stat -c%s "$d/a.tar.gz") * 3 ))" "a wrapped reading falls back to 3x"
}

test_extraction_checks_the_unpacked_size_and_drops_spent_copies() {
    local w; w="$(mktemp -d -p "$SCRIPT_DIR")"
    _asset "$w/t1-elk.tar" elk
    _asset "$w/t1-iris.tar" iris
    _index "$w/t1.index.json" "$w/t1-elk.tar" "$w/t1-iris.tar"
    tar -cf "$SCRIPT_DIR/t1-package.tar" -C "$w" t1.index.json t1-elk.tar t1-iris.tar
    parse_install_args --package "$SCRIPT_DIR/t1-package.tar"
    local need_seen=""
    _args_require_space() { need_seen="$2"; }
    load_images_from_package "${INTACT_PACKAGES[@]}" >/dev/null 2>&1 || true
    unset -f _args_require_space; source ../lib/args.sh
    assert_true test -n "$need_seen"
    assert_true test "$need_seen" -ge 1073741824
    assert_false test -e "${INTACT_PACKAGES[0]}"   # an unwrapped copy is deleted once extracted
    assert_true test -f "$SCRIPT_DIR/t1-package.tar"   # the operator's own package is never touched
    rm -rf "${INTACT_UNWRAP_DIRS[@]}" "$SCRIPT_DIR/t1-package.tar"
}

# ---------------------------------------------------------------- fix 3
test_split_assets_in_a_directory_are_joined() {
    local d; d="$(mktemp -d -p "$SCRIPT_DIR")"
    _asset "$SCRIPT_DIR/whole.tar" timesketch
    split -b 4096 -d -a 2 "$SCRIPT_DIR/whole.tar" "$d/t1-timesketch.tar.part-"
    _asset "$d/t1-elk.tar" elk
    _index "$d/t1.index.json" "$SCRIPT_DIR/whole.tar" "$d/t1-elk.tar"
    sed -i 's/whole\.tar/t1-timesketch.tar/g' "$d/t1.index.json"
    assert_true test -e "$d/t1-timesketch.tar.part-01"
    parse_install_args --package "$d"
    assert_eq "${#INTACT_PACKAGES[@]}" "2" "the joined asset is used alongside the whole one"
    local joined=""
    for p in "${INTACT_PACKAGES[@]}"; do [[ "$p" == */t1-timesketch.tar ]] && joined="$p"; done
    assert_ne "$joined" "" "the split asset is in the list, joined"
    assert_eq "$(_sha "$joined")" "$(_sha "$SCRIPT_DIR/whole.tar")" "the join is byte-identical"
    assert_not_contains "$joined" "$d" "joined into data/tmp, not the operator's folder"
    assert_true _pkg_verify_against_index "$INTACT_PACKAGE_INDEX" "${INTACT_PACKAGES[@]}"
    rm -rf "${INTACT_UNWRAP_DIRS[@]}"
}

test_parts_beside_their_whole_asset_are_not_joined_again() {
    local d; d="$(mktemp -d -p "$SCRIPT_DIR")"
    _asset "$d/t1-elk.tar" elk
    split -b 4096 -d -a 2 "$d/t1-elk.tar" "$d/t1-elk.tar.part-"
    parse_install_args --package "$d"
    assert_eq "${#INTACT_PACKAGES[@]}" "1"
    assert_eq "${INTACT_PACKAGES[0]}" "$d/t1-elk.tar"
}

# ---------------------------------------------------------------- fix 4
_wrapper() {
    local w; w="$(mktemp -d -p "$SCRIPT_DIR")"
    _asset "$w/t1-elk.tar" elk
    tar -cf "$SCRIPT_DIR/t1-package.tar" -C "$w" t1-elk.tar
}

test_scratch_goes_on_an_early_exit_and_the_old_trap_still_runs() {
    _wrapper
    local marker="$SCRIPT_DIR/earlier-trap-ran"
    local out
    out="$(
        # A fresh install.sh process. (A subshell's `trap -p` still prints the
        # parent's traps, which here delete SCRIPT_DIR: set our own first.)
        trap "touch '$marker'" EXIT
        _ARGS_EXIT_ARMED=""
        parse_install_args --package "$SCRIPT_DIR/t1-package.tar"
        mkdir -p "$SCRIPT_DIR/data/tmp/system-bundle-pkg/system-bundle"
        printf '%s\n' "${INTACT_UNWRAP_DIRS[@]}"
        exit 1                              # e.g. check_root, before any load
    )"
    assert_ne "$out" "" "the wrapper was unwrapped"
    assert_false test -e "$out"
    assert_false test -e "$SCRIPT_DIR/data/tmp/system-bundle-pkg"
    assert_true test -e "$marker"
}

test_a_full_disk_is_refused_before_unwrapping() {
    _wrapper
    local out rc=0
    out="$(
        trap - EXIT; _ARGS_EXIT_ARMED=""
        df() { printf 'Filesystem 1024-blocks Used Available Capacity Mounted\n/dev/x 100 99 1 99%% /\n'; }
        parse_install_args --package "$SCRIPT_DIR/t1-package.tar"
    )" || rc=$?
    assert_eq "$rc" "1" "the install stops"
    assert_contains "$(cat "$LOGGED")" "Not enough free space"
    assert_contains "$(cat "$LOGGED")" "needs 20K, 1.0K free" "says what it needs against what is free"
    assert_eq "$(find "$SCRIPT_DIR/data/tmp" -maxdepth 1 -name 'unwrap-*' | wc -l)" "0" "and leaves no scratch dir"
}

test_a_gzip_module_asset_is_not_probed() {
    local d; d="$(mktemp -d -p "$SCRIPT_DIR")"
    _asset "$d/t1-elk.tar" elk; gzip "$d/t1-elk.tar"
    local tar_calls="$SCRIPT_DIR/tar-calls"; : > "$tar_calls"
    tar() { echo "$*" >> "$tar_calls"; command tar "$@"; }
    parse_install_args --package "$d/t1-elk.tar.gz"
    unset -f tar
    assert_eq "${INTACT_PACKAGES[0]}" "$d/t1-elk.tar.gz"
    assert_not_contains "$(cat "$tar_calls")" "-tf" "no full decompress just to rule out a wrapper"
}

# ---------------------------------------------------------------- fix 9
_zip() {   # <path> <member date YYYY-MM-DD>
    python3 - "$@" <<'PY'
import sys, zipfile
y, m, d = map(int, sys.argv[2].split("-"))
with zipfile.ZipFile(sys.argv[1], "w") as z:
    z.writestr(zipfile.ZipInfo("windows/a.json.xz", (y, m, d, 0, 0, 0)), sys.argv[2])
PY
}

test_an_older_package_does_not_downgrade_the_symbol_pack() {
    local pkg dest
    pkg="$(mktemp -d -p "$SCRIPT_DIR")"; dest="$(mktemp -d -p "$SCRIPT_DIR")"
    _zip "$pkg/old.zip" 2026-01-01
    _zip "$dest/new.zip" 2026-10-01
    touch "$pkg/old.zip"                     # a fresh copy: its mtime says nothing
    assert_false _volweb_pack_is_newer "$(_volweb_pack_date "$pkg/old.zip")" "$(_volweb_pack_date "$dest/new.zip")"
    assert_true  _volweb_pack_is_newer "$(_volweb_pack_date "$dest/new.zip")" "$(_volweb_pack_date "$pkg/old.zip")"
    assert_true  _volweb_pack_is_newer "$(_volweb_pack_date "$pkg/old.zip")" "" "no pack in place: stage it"
}

test_package_staging_keeps_the_newer_pack() {
    local work; work="$(mktemp -d -p "$SCRIPT_DIR")"
    mkdir -p "$work/intact-upgrade-t1/volweb_symbols" "$SCRIPT_DIR/data/volweb-symbols"
    _zip "$work/intact-upgrade-t1/volweb_symbols/windows.zip" 2026-01-01
    _zip "$SCRIPT_DIR/data/volweb-symbols/windows.zip" 2026-10-01
    local before; before="$(_sha "$SCRIPT_DIR/data/volweb-symbols/windows.zip")"
    # Just the staging loop of load_images_from_package, on an extracted tree.
    eval "$(sed -n '/local _yara_seed=/,/^    done$/p' ../lib/package.sh)"
    assert_eq "$(_sha "$SCRIPT_DIR/data/volweb-symbols/windows.zip")" "$before" "the older pack did not replace it"
    _zip "$work/intact-upgrade-t1/volweb_symbols/windows.zip" 2026-11-01
    eval "$(sed -n '/local _yara_seed=/,/^    done$/p' ../lib/package.sh)"
    assert_eq "$(_sha "$SCRIPT_DIR/data/volweb-symbols/windows.zip")" \
              "$(_sha "$work/intact-upgrade-t1/volweb_symbols/windows.zip")" "a newer pack does"
}

run_all_tests; _rc=$?
rm -f "$LOGGED"
exit $_rc
