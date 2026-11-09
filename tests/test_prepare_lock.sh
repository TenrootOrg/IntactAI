#!/bin/bash
# scripts/prepare_package.sh: one prepare per output dir, and the wrap is
# written as .partial and renamed only once verified.
#
# The incident: a second Prepare (double-click, two tabs) ran the start-up
# reaper and rm -rf'd the FIRST run's live .intact-prepare-* staging; and a
# backend killed mid-wrap left a truncated <tag>-package.tar under the real
# name, which the Apply picker then listed as a package.
#
# Same fake-GitHub approach as test_prepare_package.sh: stub binaries first on
# PATH, so they reach the script's subshells and xargs fan-out.

set -u
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./helpers.sh
ROOT="$(cd .. && pwd)"
SCRIPT="${ROOT}/scripts/prepare_package.sh"

WORK="$(mktemp -d)"
FIX="${WORK}/fixtures"
BIN="${WORK}/bin"
mkdir -p "$FIX" "$BIN"
trap 'rm -rf "$WORK"' EXIT

TAG="locktag"

if ! command -v flock >/dev/null 2>&1; then
    echo "  SKIP: no flock on this host (the script runs unguarded there)"
    exit 0
fi

# --- a minimal well-formed release: one module, index, manifest, engine -----
mkdir -p "${FIX}/mod-src" "${FIX}/eng-src/scripts"
echo data > "${FIX}/mod-src/marker"
tar -cf "${FIX}/${TAG}-elk.tar" -C "${FIX}/mod-src" marker
printf '#!/bin/bash\n' > "${FIX}/eng-src/scripts/upgrade.sh"
tar -czf "${FIX}/${TAG}-engine.tar.gz" -C "${FIX}/eng-src" .
( cd "$FIX" && sha256sum "${TAG}-engine.tar.gz" > "${TAG}-engine.tar.gz.sha256" )
cat > "${FIX}/index.json" <<JSON
{"assets": {"elk": {"asset": "${TAG}-elk.tar", "sha256": "$(sha256sum "${FIX}/${TAG}-elk.tar" | awk '{print $1}')", "size": $(stat -c%s "${FIX}/${TAG}-elk.tar")}}}
JSON
echo '{"package_version": "1.0", "versions": {"elk": "8"}, "contents": {"sha256": {}}}' > "${FIX}/manifest.json"
cat > "${FIX}/release.json" <<JSON
{"tag_name": "${TAG}", "assets": [
  {"name": "${TAG}.index.json", "url": "https://api.github.com/fake/asset/index"},
  {"name": "${TAG}.manifest.json", "url": "https://api.github.com/fake/asset/manifest"},
  {"name": "${TAG}-elk.tar", "url": "https://api.github.com/fake/asset/elk", "size": $(stat -c%s "${FIX}/${TAG}-elk.tar")}
]}
JSON

# Logs every URL it is asked for, so a refused run can be shown to have fetched
# nothing at all.
cat > "${BIN}/curl" <<CURL
#!/bin/bash
url="\${@: -1}"; out=""; prev=""
for a in "\$@"; do [[ "\$prev" == "-o" ]] && out="\$a"; prev="\$a"; done
echo "\$url" >> "${WORK}/curl.log"
case "\$url" in
    */releases/tags/*) cat "${FIX}/release.json" ;;
    */fake/asset/index) cp "${FIX}/index.json" "\$out" ;;
    */fake/asset/manifest) cp "${FIX}/manifest.json" "\$out" ;;
    */fake/asset/elk) cp "${FIX}/${TAG}-elk.tar" "\$out" ;;
    */${TAG}-engine.tar.gz.sha256) cp "${FIX}/${TAG}-engine.tar.gz.sha256" "\$out" ;;
    */${TAG}-engine.tar.gz) cp "${FIX}/${TAG}-engine.tar.gz" "\$out" ;;
    *) exit 22 ;;
esac
CURL
chmod +x "${BIN}/curl"

# Passes through to the real tar, but records each -cf target and can be told
# to fail the -tf readback (a disk that filled at the last block).
REAL_TAR="$(command -v tar)"
cat > "${BIN}/tar" <<TAR
#!/bin/bash
if [[ "\${1:-}" == "-cf" ]]; then echo "\$2" >> "${WORK}/tar-cf.log"; fi
if [[ "\${1:-}" == "-tf" && -n "\${FAKE_TAR_TF_FAIL:-}" ]]; then exit 2; fi
exec "$REAL_TAR" "\$@"
TAR
chmod +x "${BIN}/tar"

_run() {  # _run <out_dir> -> rc; stdout/stderr in $WORK/run.{out,err}
    PATH="${BIN}:${PATH}" GITHUB_TOKEN="" bash "$SCRIPT" "$TAG" "$1" \
        > "${WORK}/run.out" 2> "${WORK}/run.err"
}

test_a_second_prepare_refuses_and_leaves_the_first_runs_staging() {
    local out="${WORK}/busy"; mkdir -p "$out/.intact-prepare-live"
    echo partial > "$out/.intact-prepare-live/elk.tar"
    : > "${WORK}/curl.log"
    # Stand-in for the first run: hold the same lock it takes.
    exec 8>"$out/.intact-prepare.lock"
    flock -n 8
    _run "$out"; local rc=$?
    exec 8>&-
    assert_ne "$rc" "0" "a prepare into a busy output dir must refuse"
    assert_contains "$(cat "${WORK}/run.err")" "another prepare is already running"
    assert_true test -f "$out/.intact-prepare-live/elk.tar"
    assert_eq "$(cat "${WORK}/curl.log")" "" "a refused run must not start downloading"
}

test_once_free_the_reaper_clears_debris_and_the_tar_lands_via_partial() {
    local out="${WORK}/free"; mkdir -p "$out/.intact-prepare-dead"
    echo junk > "$out/${TAG}-package.tar.partial"   # a SIGKILLed wrap
    : > "${WORK}/tar-cf.log"
    _run "$out"; local rc=$?
    [[ "$rc" -eq 0 ]] || cat "${WORK}/run.err" >&2
    assert_eq "$rc" "0" "an uncontended prepare must succeed"
    assert_true test ! -e "$out/.intact-prepare-dead"
    assert_true test ! -e "$out/${TAG}-package.tar.partial"
    assert_true test -f "$out/${TAG}-package.tar"
    assert_eq "$(tail -1 "${WORK}/run.out")" "$out/${TAG}-package.tar" \
        "the last stdout line is still the final (non-.partial) path"
    assert_eq "$(cat "${WORK}/tar-cf.log")" "$out/${TAG}-package.tar.partial" \
        "the wrap must be written under .partial, never the real name"
    assert_contains "$(tar -tf "$out/${TAG}-package.tar")" "${TAG}-elk.tar"
}

test_a_failed_wrap_leaves_no_partial_and_keeps_the_previous_package() {
    local out="${WORK}/fail"; mkdir -p "$out"
    echo "previous good package" > "$out/${TAG}-package.tar"
    FAKE_TAR_TF_FAIL=1 _run "$out"; local rc=$?
    assert_ne "$rc" "0" "a wrap that fails its readback must fail the run"
    assert_true test ! -e "$out/${TAG}-package.tar.partial"
    assert_eq "$(cat "$out/${TAG}-package.tar")" "previous good package" \
        "a failed run must not destroy the last good package"
}

run_all_tests
