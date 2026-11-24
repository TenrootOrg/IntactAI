#!/bin/bash
# The two local release builders stage the source tree the packager reads. They
# rsynced the working tree minus .git (build_local_release.sh) or minus .git,
# data/ and backups/ (build_local_release_assets.sh), and on a box the working
# tree is the live install: config.yaml.pre-upgrade-backup (the GitHub token and
# module passwords), the install/upgrade logs, modules/nginx/html/downloads and
# modules/velociraptor/clients would all have been packaged. Both now stage
# TRACKED files only, with config.yaml and modules/*/.env taken from HEAD.
#
# Runs both real scripts from a throwaway git repo with docker and sudo stubbed
# on PATH. The stub fails the first packager call, so each script stops right
# after staging and the staged tree is inspected. No docker, nothing built.
set -u
cd "$(dirname "${BASH_SOURCE[0]}")" || exit 1
source ./helpers.sh
ROOT="$(cd .. && pwd)"

T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
BIN="$T/bin"; REPO="$T/repo"; BOX="$T/boxdata"
mkdir -p "$BIN" "$REPO/scripts/dev" "$BOX"

cat > "$BIN/docker" <<'EOF'
#!/bin/bash
case "$1 $2" in
    "image ls")      echo "intact-backend:intact-20260101" ;;
    "image inspect") exit 0 ;;
    inspect*)        [[ "$*" == *--format* ]] && echo "$FAKE_BOXDATA"; exit 0 ;;
    exec*|run*)      echo "stub: stop after staging" >&2; exit 1 ;;
esac
exit 0
EOF
printf '#!/bin/bash\nexec "$@"\n' > "$BIN/sudo"
chmod +x "$BIN/docker" "$BIN/sudo"

cp "$ROOT/scripts/dev/build_local_release.sh" "$ROOT/scripts/dev/build_local_release_assets.sh" \
   "$ROOT/scripts/dev/check_cached_pins.py" "$REPO/scripts/dev/"
mkdir -p "$REPO/modules/elk" "$REPO/data" "$REPO/lib"
printf 'github:\n  token: ""\nversions:\n  elk: 9.0.0\n' > "$REPO/config.yaml"
echo "ELASTIC_PASSWORD=" > "$REPO/modules/elk/.env"
echo "tools: []" > "$REPO/data/tools_inventory.yaml"
echo "keep" > "$REPO/lib/common.sh"
echo "gone" > "$REPO/lib/deleted.sh"
_g() { git -C "$REPO" -c user.email=t@example.invalid -c user.name=t -c core.hooksPath=/dev/null "$@"; }
_g init -q && _g add -A && _g commit -qm init

# The box's live state on top of that commit.
printf 'github:\n  token: "LIVE-TOKEN"\nversions:\n  elk: 9.9.9\n' > "$REPO/config.yaml"
echo "ELASTIC_PASSWORD=LIVE-PASS" > "$REPO/modules/elk/.env"
rm "$REPO/lib/deleted.sh"
echo "token: LIVE-TOKEN" > "$REPO/config.yaml.pre-upgrade-backup"
echo "log" > "$REPO/install_20261117.log"
mkdir -p "$REPO/modules/nginx/html/downloads" "$REPO/modules/velociraptor/clients/linux" \
         "$REPO/data/state" "$REPO/data/yara-seed"
echo bin > "$REPO/modules/nginx/html/downloads/velociraptor"
echo bin > "$REPO/modules/velociraptor/clients/linux/velociraptor"
echo ca  > "$REPO/data/state/ca.key"
echo rule > "$REPO/data/yara-seed/r.yar"

# What every staged tree must and must not hold.
_check_stage() {
    local s="$1"
    assert_true  test -f "$s/lib/common.sh"
    assert_true  test -f "$s/data/tools_inventory.yaml"
    assert_false test -e "$s/lib/deleted.sh"
    assert_false test -e "$s/config.yaml.pre-upgrade-backup"
    assert_false test -e "$s/install_20261117.log"
    assert_false test -e "$s/modules/nginx/html/downloads"
    assert_false test -e "$s/modules/velociraptor/clients"
    assert_false test -e "$s/data/state"
    assert_not_contains "$(cat "$s/config.yaml")" "LIVE-TOKEN"
    assert_contains     "$(cat "$s/config.yaml")" "elk: 9.0.0"
    assert_eq "$(cat "$s/modules/elk/.env")" "ELASTIC_PASSWORD="
}

test_assets_builder_stages_tracked_files_only() {
    PATH="$BIN:$PATH" INTACT_LOCAL_BUILD_ROOT="$T/build" \
        bash "$REPO/scripts/dev/build_local_release_assets.sh" faketag "$T/out" elk >/dev/null 2>&1
    local s="$T/build/faketag/src"
    assert_true test -d "$s"
    _check_stage "$s"
    # Untracked, but a build input the script copies on purpose.
    assert_true test -f "$s/data/yara-seed/r.yar"
}

test_local_release_stages_tracked_files_only_and_passes_commit() {
    mkdir -p "$T/cache/faketag" "$T/idx"
    echo '{"assets": {"elk": {"version": "9.0.0"}}}' > "$T/idx/faketag.index.json"
    tar -cf "$T/cache/faketag/subset.tar" -C "$T/idx" faketag.index.json
    local out
    out="$(PATH="$BIN:$PATH" FAKE_BOXDATA="$BOX" INTACT_LOCAL_RELEASE_CACHE="$T/cache" \
        INTACT_LOCAL_RELEASE_MODULES=elk \
        bash "$REPO/scripts/dev/build_local_release.sh" faketag "$T/out2" 2>&1)"
    # The cache holds elk 9.0.0, and only HEAD's config.yaml pins that: the
    # pin check must read the file the package is built from, not the box's.
    assert_not_contains "$out" "not at this checkout's config.yaml pins"
    local s="$BOX/.local_release_src"
    assert_true test -d "$s"
    _check_stage "$s"
    assert_contains "$(cat "$REPO/scripts/dev/build_local_release.sh")" \
        '--commit "$(git -C "$REPO_DIR" rev-parse HEAD)"'
}

run_all_tests
