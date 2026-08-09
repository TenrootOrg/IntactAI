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

run_all_tests
