#!/bin/bash
# download_system_bundle() (lib/release.sh): its 0/1/2 return-code contract
# is load-bearing -- ensure_core_dependencies() branches "genuinely no
# bundle, fall through" (1) vs "fatal, no online fallback" (2) directly on
# it. Covers the fix for the defect found while raising this past 60%
# confidence: a failed/empty/unparseable GitHub API response used to return
# 1 (indistinguishable from "old release, no bundle") instead of 2.

set -u
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./helpers.sh

LOG_FILE="$(mktemp)"
trap 'rm -f "$LOG_FILE"' EXIT
source ../lib/common.sh   # real log_info/log_error/log_success
source ../lib/release.sh

DEST="$(mktemp -d)"
trap 'rm -rf "$DEST"' EXIT

_valid_release_json() {
    # Minimal but real: an "assets" array, optionally containing the bundle.
    cat <<JSON
{"tag_name":"testtag","assets":[$1]}
JSON
}

_asset_entry() {
    printf '{"name":"%s","url":"https://example/%s"}' "$1" "$1"
}

test_curl_transport_failure_is_fatal() {
    curl() { return 7; }  # CURLE_COULDNT_CONNECT
    download_system_bundle testtag "$DEST"
    assert_eq "$?" "2" "curl itself failing must be fatal (2), not 'no bundle' (1)"
}

test_empty_api_response_is_fatal() {
    curl() { :; }  # exits 0, prints nothing
    download_system_bundle testtag "$DEST"
    assert_eq "$?" "2" "an empty API response must be fatal (2)"
}

test_unparseable_json_is_fatal() {
    # What GitHub actually sends when the token is rate-limited/invalid --
    # no "assets" array, but not empty and curl succeeded.
    curl() { echo '{"message":"API rate limit exceeded"}'; }
    download_system_bundle testtag "$DEST"
    assert_eq "$?" "2" "a non-release JSON body (rate limit, error page) must be fatal (2)"
}

test_valid_release_without_bundle_is_not_an_error() {
    curl() { _valid_release_json "$(_asset_entry intact-upgrade-testtag.tar)"; }
    download_system_bundle testtag "$DEST"
    assert_eq "$?" "1" "a real release that simply predates this feature is rc=1, not fatal"
}

test_bundle_advertised_but_download_fails_is_fatal() {
    curl() {
        for a in "$@"; do
            case "$a" in
                *api.github.com*) _valid_release_json "$(_asset_entry testtag-system-bundle.tar)"; return 0 ;;
            esac
        done
        return 22  # the download-the-asset call fails
    }
    download_system_bundle testtag "$DEST"
    assert_eq "$?" "2" "advertised but unobtainable must be fatal (2), never a fallback"
}

test_happy_path_stages_the_bundle() {
    local work; work="$(mktemp -d)"
    echo "24.04" > "${work}/ubuntu-version"
    echo "fake deb" > "${work}/pkg.deb"
    local bundle_tar="${work}/testtag-system-bundle.tar"
    tar -cf "$bundle_tar" -C "$work" ubuntu-version pkg.deb

    curl() {
        local out=""
        local i
        for ((i=1; i<=$#; i++)); do
            [[ "${!i}" == "-o" ]] && { local j=$((i+1)); out="${!j}"; }
        done
        for a in "$@"; do
            case "$a" in
                *api.github.com*)
                    _valid_release_json "$(_asset_entry testtag-system-bundle.tar)"
                    return 0 ;;
                */releases/download/*system-bundle.tar)
                    cp "$bundle_tar" "$out"
                    return 0 ;;
            esac
        done
        return 1
    }
    download_system_bundle testtag "$DEST"
    assert_eq "$?" "0" "a genuinely available bundle must stage successfully"
    assert_true test -d "${DEST}/system-bundle"
    assert_true test -f "${DEST}/system-bundle/ubuntu-version"
    rm -rf "$work"
}

# ---------------------------------------------------------------------------
# Per-module fetch selection. Exercises the REAL code by slicing the index
# branch out of lib/release.sh and running it -- a reimplementation here would
# pass while the shipped logic drifted.
# ---------------------------------------------------------------------------
_selection() {   # <INTACT_RELEASE_ONLY_MODULES> -> the asset names it would fetch
    INTACT_RELEASE_ONLY_MODULES="$1" python3 - "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/lib/release.sh" <<'PYEOF'
import json, os, sys
src = open(sys.argv[1]).read().split("\n")
start = next(i for i, l in enumerate(src) if l.strip() == "want = []")
end   = next(i for i, l in enumerate(src) if l.strip() == "if not want:")
block = "\n".join(src[start:end])
index = {"assets": {
    "intact":    {"asset": "t-intact.tar.gz",    "sha256": "a", "parts": []},
    "elk":       {"asset": "t-elk.tar.gz",       "sha256": "b", "parts": []},
    "iris":      {"asset": "t-iris.tar.gz",      "sha256": "c", "parts": []},
    "portainer": {"asset": "t-portainer.tar.gz", "sha256": "d", "parts": []},
}}
names = [v["asset"] for v in index["assets"].values()] + ["t.manifest.json"]
tag = "t"
os.environ["INDEX_JSON"] = json.dumps(index)
ns = {"json": json, "os": os, "sys": sys, "names": names, "tag": tag}
exec(block, ns)
print(" ".join(sorted(w[0] for w in ns["want"])))
PYEOF
}

test_unset_filter_fetches_every_asset() {
    # install.sh never sets the variable, and "an INSTALL takes the COMPLETE
    # module set" -- so unset must remain byte-identical to the old behaviour.
    local out; out="$(_selection "")"
    assert_contains "$out" "t-elk.tar.gz"       "unset must fetch everything"
    assert_contains "$out" "t-iris.tar.gz"      "unset must fetch everything"
    assert_contains "$out" "t-portainer.tar.gz" "unset must fetch everything"
}

test_a_filter_fetches_only_what_was_named() {
    local out; out="$(_selection "elk intact")"
    assert_contains     "$out" "t-elk.tar.gz"       "the named module must be fetched"
    assert_not_contains "$out" "t-iris.tar.gz"      "an unnamed module must be skipped"
    assert_not_contains "$out" "t-portainer.tar.gz" "an unnamed module must be skipped"
}

test_the_merged_manifest_is_always_fetched() {
    # plan_build reads its version table from this, so a filtered fetch that
    # dropped it would plan nothing at all.
    assert_contains "$(_selection "elk intact")" "t.manifest.json" \
        "the merged manifest is not a module asset and must always come along"
}

test_intact_is_fetched_whenever_the_caller_asks_for_it() {
    # scripts/upgrade.sh appends `intact` unconditionally; without its asset the
    # stage-0 hop has nothing to exec into and the box applies the release with
    # its own older engine.
    assert_contains "$(_selection "elk intact")" "t-intact.tar.gz" \
        "intact carries source/intact/scripts/upgrade.sh"
}

test_upgrade_sh_always_appends_intact_to_the_filter() {
    # Assert the BEHAVIOUR, not the line. The first version of this test pinned
    # the literal assignment and broke the moment the list was de-duplicated --
    # a test that fails on a refactor it should not care about teaches people to
    # ignore it.
    #
    # What must hold: whatever --only names, `intact` ends up in the fetch set,
    # because its asset carries source/intact/scripts/upgrade.sh and without it
    # the stage-0 hop has nothing to exec into.
    local f; f="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/scripts/upgrade.sh"
    assert_true grep -q 'INTACT_RELEASE_ONLY_MODULES=' "$f"
    # the construction must mention intact on the same logical line
    assert_true grep -q 'UPGRADE_ONLY//,/ } intact' "$f"
    # and the resulting list must not repeat it
    local r
    r="$(printf '%s\n' intact elk intact | awk '!seen[$0]++' | tr '\n' ' ')"
    assert_eq "${r% }" "intact elk" "the de-dup must collapse a repeated intact"
}

test_install_never_sets_the_filter() {
    local root; root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    local n; n="$(grep -rl 'INTACT_RELEASE_ONLY_MODULES' "${root}/install.sh" "${root}/lib/args.sh" 2>/dev/null | wc -l)"
    assert_eq "$n" "0" "the install path must take the complete module set"
}

run_all_tests
