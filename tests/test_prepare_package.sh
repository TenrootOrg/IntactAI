#!/bin/bash
# scripts/prepare_package.sh: end-to-end, against a fake GitHub. Not sourced
# (that script is a real CLI, not a library of functions like lib/*.sh) --
# instead a fake `curl` is placed first on PATH, since every curl call in
# the script is an external command invocation, which a PATH override
# reaches correctly even through the script's xargs -P fan-out and
# background watcher subshell (a shell FUNCTION stub would not cross those
# process boundaries reliably; a PATH binary does).
#
# Covers defect (1) from the plan: prepare_package.sh used to build its
# single-file air-gap package strictly from the per-module index, silently
# omitting the Docker/dependency bundle -- so the flagship way a bundle
# reaches an air-gapped site carried no bundle at all.

set -u
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./helpers.sh

WORK="$(mktemp -d)"
FIX="${WORK}/fixtures"
BIN="${WORK}/bin"
mkdir -p "$FIX" "$BIN"
trap 'rm -rf "$WORK"' EXIT

TAG="testtag"

# ---------------------------------------------------------------------------
# Fixture assets: one tiny module asset + the system bundle + its sha256.
# ---------------------------------------------------------------------------
mkdir -p "${FIX}/mod-src"
echo "fake velociraptor image data" > "${FIX}/mod-src/marker"
tar -cf "${FIX}/${TAG}-velociraptor.tar" -C "${FIX}/mod-src" marker

mkdir -p "${FIX}/bundle-src"
echo "24.04" > "${FIX}/bundle-src/ubuntu-version"
echo "fake deb" > "${FIX}/bundle-src/pkg.deb"
tar -cf "${FIX}/${TAG}-system-bundle.tar" -C "${FIX}/bundle-src" .
sha256sum "${FIX}/${TAG}-system-bundle.tar" | awk '{print $1}' > "${FIX}/${TAG}-system-bundle.tar.sha256"

cat > "${FIX}/index.json" <<JSON
{
  "assets": {
    "velociraptor": {"asset": "${TAG}-velociraptor.tar", "sha256": "$(sha256sum "${FIX}/${TAG}-velociraptor.tar" | awk '{print $1}')", "size": $(stat -c%s "${FIX}/${TAG}-velociraptor.tar")}
  }
}
JSON

cat > "${FIX}/release.json" <<JSON
{
  "tag_name": "${TAG}",
  "assets": [
    {"name": "${TAG}.index.json", "url": "https://api.github.com/fake/asset/index"},
    {"name": "${TAG}-velociraptor.tar", "url": "https://api.github.com/fake/asset/velociraptor", "size": $(stat -c%s "${FIX}/${TAG}-velociraptor.tar")},
    {"name": "${TAG}-system-bundle.tar", "url": "https://api.github.com/fake/asset/bundle", "size": $(stat -c%s "${FIX}/${TAG}-system-bundle.tar")},
    {"name": "${TAG}-system-bundle.tar.sha256", "url": "https://api.github.com/fake/asset/bundle-sha"}
  ]
}
JSON

# ---------------------------------------------------------------------------
# Fake curl: every call in prepare_package.sh puts the URL as the last
# argument and an output path (if any) after "-o". Route by URL substring.
# ---------------------------------------------------------------------------
cat > "${BIN}/curl" <<CURL
#!/bin/bash
url="\${@: -1}"
out=""
prev=""
for a in "\$@"; do
    [[ "\$prev" == "-o" ]] && out="\$a"
    prev="\$a"
done
case "\$url" in
    */releases/tags/*) cat "${FIX}/release.json" ;;
    */fake/asset/index) cp "${FIX}/index.json" "\$out" ;;
    */fake/asset/velociraptor) cp "${FIX}/${TAG}-velociraptor.tar" "\$out" ;;
    */fake/asset/bundle-sha) cp "${FIX}/${TAG}-system-bundle.tar.sha256" "\$out" ;;
    */fake/asset/bundle) cp "${FIX}/${TAG}-system-bundle.tar" "\$out" ;;
    *) echo "fake curl: unrecognised URL: \$url" >&2; exit 1 ;;
esac
exit 0
CURL
chmod +x "${BIN}/curl"

test_wrapper_includes_the_system_bundle() {
    local out_dir="${WORK}/out"
    mkdir -p "$out_dir"
    local result
    result="$(PATH="${BIN}:${PATH}" GITHUB_TOKEN="" bash ../scripts/prepare_package.sh "$TAG" "$out_dir" 2>"${WORK}/stderr.log")"
    local rc=$?
    if [[ "$rc" -ne 0 ]]; then
        echo "  prepare_package.sh exited $rc, stderr:" >&2
        cat "${WORK}/stderr.log" >&2
    fi
    assert_eq "$rc" "0" "prepare_package.sh must succeed against a well-formed fake release"

    local wrapper; wrapper="$(tail -1 <<< "$result")"
    # NOTE: assert_true runs its full argument list as the command under
    # test -- no separate description slot, unlike assert_eq/assert_contains.
    assert_true test -f "$wrapper"

    local listing; listing="$(tar -tf "$wrapper" 2>/dev/null)"
    assert_contains "$listing" "${TAG}-velociraptor.tar" "module asset must be in the wrapper"
    assert_contains "$listing" "${TAG}.index.json" "index must be in the wrapper"
    assert_contains "$listing" "${TAG}-system-bundle.tar" \
        "defect (1): the wrapper must carry the system bundle, not just module assets"

    # Extract and confirm the bundled bundle really is the one served, not a
    # placeholder / zero-byte member.
    local extract="${WORK}/extract"
    mkdir -p "$extract"
    tar -xf "$wrapper" -C "$extract" "${TAG}-system-bundle.tar"
    local extracted_listing; extracted_listing="$(tar -tf "${extract}/${TAG}-system-bundle.tar")"
    assert_contains "$extracted_listing" "ubuntu-version" \
        "the packaged bundle must be the real bundle contents, not empty"
}

test_bad_bundle_checksum_aborts_the_run() {
    # Corrupt the sha256 sidecar so the bundle's checksum verification fails
    # -- must refuse to package rather than silently ship a bad bundle.
    echo "0000000000000000000000000000000000000000000000000000000000000000" \
        > "${FIX}/${TAG}-system-bundle.tar.sha256"
    local out_dir="${WORK}/out2"
    mkdir -p "$out_dir"
    PATH="${BIN}:${PATH}" GITHUB_TOKEN="" bash ../scripts/prepare_package.sh "$TAG" "$out_dir" \
        > "${WORK}/stdout2.log" 2>"${WORK}/stderr2.log"
    local rc=$?
    assert_ne "$rc" "0" "a bundle that fails its checksum must abort the run, not ship anyway"
    assert_contains "$(cat "${WORK}/stderr2.log")" "checksum" \
        "the failure must be attributed to the checksum, not a generic error"
    assert_true test ! -f "${out_dir}/intact-upgrade-${TAG}.tar"
    # restore the good checksum for any test that runs after this one
    sha256sum "${FIX}/${TAG}-system-bundle.tar" | awk '{print $1}' \
        > "${FIX}/${TAG}-system-bundle.tar.sha256"
}

run_all_tests
