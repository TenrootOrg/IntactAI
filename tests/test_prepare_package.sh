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
ROOT="$(cd .. && pwd)"

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

# The upgrade engine. prepare_package.sh REQUIRES this: it has to travel inside
# the package, because the box that applies one has no network and the
# bootstrap refuses rather than fall back to that box's own older engine. A
# package without it cannot be applied, so building one is a hard failure --
# which means this fixture has to publish it, exactly as a real release does.
mkdir -p "${FIX}/eng-src/scripts" "${FIX}/eng-src/lib"
printf '#!/bin/bash\necho engine\n' > "${FIX}/eng-src/scripts/upgrade.sh"
: > "${FIX}/eng-src/lib/common.sh"; : > "${FIX}/eng-src/install.sh"
echo 1 > "${FIX}/eng-src/BOOTSTRAP_PROTOCOL"
tar -czf "${FIX}/${TAG}-engine.tar.gz" -C "${FIX}/eng-src" .
( cd "${FIX}" && sha256sum "${TAG}-engine.tar.gz" > "${TAG}-engine.tar.gz.sha256" )

cat > "${FIX}/index.json" <<JSON
{
  "assets": {
    "velociraptor": {"asset": "${TAG}-velociraptor.tar", "sha256": "$(sha256sum "${FIX}/${TAG}-velociraptor.tar" | awk '{print $1}')", "size": $(stat -c%s "${FIX}/${TAG}-velociraptor.tar")}
  }
}
JSON

# The MERGED root manifest, published by CI's `index` job. prepare_package.sh
# must wrap it: without it the apply side refuses the package outright
# ("per-module manifests but no merged manifest.json"), which is what made
# every hand-carried air-gap package fail on arrival at the offline site.
cat > "${FIX}/merged-manifest.json" <<JSON
{
  "package_version": "1.0",
  "versions": {"velociraptor": "0.77.1"},
  "contents": {"release_tag": "${TAG}", "sha256": {}}
}
JSON

cat > "${FIX}/release.json" <<JSON
{
  "tag_name": "${TAG}",
  "assets": [
    {"name": "${TAG}.index.json", "url": "https://api.github.com/fake/asset/index"},
    {"name": "${TAG}.manifest.json", "url": "https://api.github.com/fake/asset/manifest"},
    {"name": "${TAG}-velociraptor.tar", "url": "https://api.github.com/fake/asset/velociraptor", "size": $(stat -c%s "${FIX}/${TAG}-velociraptor.tar")},
    {"name": "${TAG}-system-bundle.tar", "url": "https://api.github.com/fake/asset/bundle", "size": $(stat -c%s "${FIX}/${TAG}-system-bundle.tar")},
    {"name": "${TAG}-system-bundle.tar.sha256", "url": "https://api.github.com/fake/asset/bundle-sha"}
  ]
}
JSON

# ---------------------------------------------------------------------------
# Fake curl: every call in prepare_package.sh puts the URL as the last
# argument and an output path (if any) after "-o". Route by URL substring.
#
# IT ALSO HONOURS `Accept:`, and that is the whole point of it now.
#
# GitHub serves /releases/assets/<id> content-negotiated: with
# `Accept: application/octet-stream` you get the asset's BYTES, without it you
# get the asset's JSON METADATA -- and 200 either way, so `curl -f` succeeds
# and the file on disk is a pretty-printed object. prepare_package.sh lost that
# header on exactly one fetch (the system-bundle .sha256 sidecar) and every real
# release with a published sidecar refused to package, reporting it as a
# corrupt bundle:
#
#   dependency bundle FAILED its checksum (want {
#   "url":
#   "id":
#   "..., got 1cee8a822b4cea98...)
#
# This stub used to ignore headers entirely, so it handed back sidecar CONTENT
# regardless -- which is why test_bad_bundle_checksum_aborts_the_run passed
# against the broken code for as long as the bug existed. A stub that cannot
# express the failure cannot test for it.
# ---------------------------------------------------------------------------
cat > "${BIN}/curl" <<CURL
#!/bin/bash
url="\${@: -1}"
out=""
prev=""
want_bytes=0
for a in "\$@"; do
    [[ "\$prev" == "-o" ]] && out="\$a"
    [[ "\$a" == "Accept: application/octet-stream" ]] && want_bytes=1
    prev="\$a"
done
# An API asset URL without the octet-stream Accept returns METADATA, not bytes.
# The tags endpoint is genuinely JSON and is not content-negotiated.
if [[ "\$want_bytes" == "0" && "\$url" == */fake/asset/* ]]; then
    meta='{
  "url": "https://api.github.com/repos/O/R/releases/assets/123",
  "id": 123456789,
  "node_id": "RA_kwDO",
  "name": "asset",
  "content_type": "application/octet-stream"
}'
    if [[ -n "\$out" ]]; then printf '%s\\n' "\$meta" > "\$out"; else printf '%s\\n' "\$meta"; fi
    exit 0
fi
case "\$url" in
    */releases/tags/*) cat "${FIX}/release.json" ;;
    */fake/asset/index) cp "${FIX}/index.json" "\$out" ;;
    */fake/asset/manifest) cp "${FIX}/merged-manifest.json" "\$out" ;;
    */fake/asset/velociraptor) cp "${FIX}/${TAG}-velociraptor.tar" "\$out" ;;
    */fake/asset/bundle-sha) cp "${FIX}/${TAG}-system-bundle.tar.sha256" "\$out" ;;
    */fake/asset/bundle) cp "${FIX}/${TAG}-system-bundle.tar" "\$out" ;;
    */${TAG}-engine.tar.gz.sha256) cp "${FIX}/${TAG}-engine.tar.gz.sha256" "\$out" ;;
    */${TAG}-engine.tar.gz) cp "${FIX}/${TAG}-engine.tar.gz" "\$out" ;;
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
    # The merged manifest. Without it upkg_read_manifest refuses the package on
    # the target with "per-module manifests but no merged manifest.json" -- the
    # wrapper looks fine locally and only fails once it has been carried to the
    # air-gapped site, which is the worst place to find out.
    assert_contains "$listing" "${TAG}.manifest.json" \
        "the wrapper must carry the merged manifest, or the target refuses the package"
    # The engine, at the TOP LEVEL of the wrapper (bootstrap_upgrade.sh pulls
    # it out with one named `tar -xf --wildcards`). The fixture exists so the
    # build doesn't abort; this asserts it actually made it INTO the wrapper --
    # an engine-less wrapper is unappliable on any box with the bootstrap.
    assert_contains "$listing" "${TAG}-engine.tar.gz" \
        "the wrapper must carry the engine, or the bootstrap refuses the package"
    assert_contains "$listing" "${TAG}-engine.tar.gz.sha256" \
        "the engine's checksum must travel with it"

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

test_a_release_without_the_merged_manifest_is_refused() {
    # A per-module release that publishes no <tag>.manifest.json cannot produce
    # a usable package: the apply side needs that file and every per-module
    # asset carries only its own manifests/<module>.json. Fail HERE, on the
    # connected machine where it costs nothing, rather than shipping a wrapper
    # that is refused after it has been carried to the offline site.
    local saved="${WORK}/release-with-manifest.json"
    cp "${FIX}/release.json" "$saved"
    grep -v "${TAG}.manifest.json" "$saved" \
        | sed 's/{"name": "'"${TAG}"'.index.json", "url": "https:\/\/api.github.com\/fake\/asset\/index"},/{"name": "'"${TAG}"'.index.json", "url": "https:\/\/api.github.com\/fake\/asset\/index"},/' \
        > "${FIX}/release.json"

    local out_dir="${WORK}/out3"
    mkdir -p "$out_dir"
    PATH="${BIN}:${PATH}" GITHUB_TOKEN="" bash ../scripts/prepare_package.sh "$TAG" "$out_dir" \
        > "${WORK}/stdout3.log" 2>"${WORK}/stderr3.log"
    local rc=$?

    cp "$saved" "${FIX}/release.json"   # restore for any later test

    assert_ne "$rc" "0" "a release with no merged manifest must be refused, not packaged"
    assert_contains "$(cat "${WORK}/stderr3.log")" "manifest.json" \
        "the failure must name the missing manifest"
    assert_true test ! -f "${out_dir}/intact-upgrade-${TAG}.tar"
}

test_the_sidecar_fetch_asks_for_bytes_not_metadata() {
    # The failure this guards is silent and total: GitHub answers 200 either
    # way, so curl -f succeeds and the "checksum" on disk is a JSON object.
    # Assert the header directly, so a regression says WHY rather than surfacing
    # three lines later as "the wrapper has no system bundle".
    local f="${ROOT}/scripts/prepare_package.sh"
    local n bad=0
    # Every hdrs=( assignment in the file must carry the octet-stream Accept.
    while IFS=: read -r n line; do
        [[ "$line" == *"Accept: application/octet-stream"* ]] || { bad=1; echo "    line ${n} lacks Accept: ${line}" >&2; }
    done < <(grep -n 'hdrs=(' "$f")
    assert_eq "$bad" "0" "every API-asset curl must send Accept: application/octet-stream"
}

test_a_sidecar_that_is_not_a_digest_is_named_as_such() {
    # A sidecar that parses to something which is not 64 hex chars is a BROKEN
    # FETCH, not a corrupt download. Conflating the two is what made this read
    # as "the bundle is corrupt" for an entire release.
    assert_true grep -q "is not a sha256" "${ROOT}/scripts/prepare_package.sh"
}

run_all_tests
