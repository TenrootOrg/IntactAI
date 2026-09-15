#!/bin/bash
# scripts/velo_tools.sh -- adding third-party Velociraptor tools to an
# appliance, air-gapped or not.
#
# WHY THESE TESTS RUN THE REAL SCRIPT. The whole point of the command is the
# NAME a tool is registered under: an artifact asks for `Hayabusa-2.14.0`, and
# a registration under `hayabusa-2.14.0-win-x64.zip` succeeds, reports success,
# and is never found by anything. That failure is invisible until a collection
# runs at a customer site with no internet, so the assertions below check the
# VQL actually sent, not that the script exits 0.
#
# docker and curl are stubbed: no daemon, no network.

source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="${REPO}/scripts/velo_tools.sh"

# A fake appliance root: a tools dir the script writes into, and a docker shim
# that records the VQL it was asked to run.
_fake() {
    local root; root="$(mktemp -d)"
    mkdir -p "${root}/tools" "${root}/carry" "${root}/bin"
    cat > "${root}/bin/docker" <<EOF
#!/bin/bash
echo "\$@" >> "${root}/docker.calls"
case "\$1" in
    inspect)
        [[ "\$2" == "-f" ]] && { echo true; exit 0; }
        exit 0 ;;
esac
# the expected-hash lookup: answer with whatever the test planted
if [[ "\$*" == *expected_hash* ]]; then
    [[ -s "${root}/expect_sha" ]] && echo "{\"h\":\"\$(cat "${root}/expect_sha")\"}"
    exit 0
fi
# every other VQL call "succeeds" the way the real one reports success
echo '{"r":{"name":"x","serve_locally":true}}'
EOF
    chmod +x "${root}/bin/docker"
    echo "$root"
}

_run() {  # _run <root> <args...>
    local root="$1"; shift
    PATH="${root}/bin:$PATH" INTACT_TOOLS_DIR="${root}/tools" bash "$SCRIPT" "$@" 2>"${root}/err"
}

test_add_registers_under_the_tool_name_not_the_file_name() {
    local root; root="$(_fake)"
    echo "binary" > "${root}/carry/hayabusa-2.14.0-win-x64.zip"

    _run "$root" add Hayabusa-2.14.0 "${root}/carry/hayabusa-2.14.0-win-x64.zip" >/dev/null
    assert_eq "$?" "0" "add succeeds"

    local vql; vql="$(cat "${root}/docker.calls")"
    assert_contains "$vql" "tool='Hayabusa-2.14.0'" "registers under the artifact's tool name"
    assert_contains "$vql" "file='/tools/hayabusa-2.14.0-win-x64.zip'" "points at the file in the container"
    assert_not_contains "$vql" "tool='hayabusa-2.14.0-win-x64.zip'" "never registers under the file name"
    assert_true test -f "${root}/tools/hayabusa-2.14.0-win-x64.zip"
}

test_add_records_the_mapping_for_a_later_refresh() {
    local root; root="$(_fake)"
    echo x > "${root}/carry/sigcheck64.exe"
    _run "$root" add sigcheck_amd64 "${root}/carry/sigcheck64.exe" >/dev/null
    assert_eq "$(cat "${root}/tools/velo_tools.map")" "$(printf 'sigcheck_amd64\tsigcheck64.exe')" \
        "map holds TOOL<TAB>FILE"
}

test_re_adding_a_tool_replaces_its_line_instead_of_duplicating() {
    local root; root="$(_fake)"
    echo x > "${root}/carry/sigcheck64.exe"; echo y > "${root}/carry/sigcheck_new.exe"
    _run "$root" add sigcheck_amd64 "${root}/carry/sigcheck64.exe" >/dev/null
    _run "$root" add sigcheck_amd64 "${root}/carry/sigcheck_new.exe" >/dev/null
    assert_eq "$(wc -l < "${root}/tools/velo_tools.map")" "1" "one line per tool"
    assert_contains "$(cat "${root}/tools/velo_tools.map")" "sigcheck_new.exe" "keeps the newest file"
}

test_add_refuses_a_name_that_would_change_the_query() {
    local root; root="$(_fake)"
    echo x > "${root}/carry/evil.exe"
    _run "$root" add "x') OR 1=1 --" "${root}/carry/evil.exe" >/dev/null
    assert_ne "$?" "0" "rejected"
    assert_contains "$(cat "${root}/err")" "not allowed" "says why"
    assert_not_contains "$(cat "${root}/docker.calls" 2>/dev/null)" "inventory_add" "nothing registered"
}

test_add_fails_on_a_missing_file_without_registering() {
    local root; root="$(_fake)"
    _run "$root" add SomeTool "${root}/carry/absent.zip" >/dev/null
    assert_ne "$?" "0" "fails"
    assert_contains "$(cat "${root}/err")" "no such file" "says why"
    assert_not_contains "$(cat "${root}/docker.calls" 2>/dev/null)" "inventory_add" "nothing registered"
}

test_import_replays_every_line_of_a_carried_map() {
    local root; root="$(_fake)"
    echo a > "${root}/carry/hayabusa.zip"; echo b > "${root}/carry/profiles.json"
    printf 'Hayabusa-2.14.0\thayabusa.zip\nSigmaProfiles\tprofiles.json\n' > "${root}/carry/velo_tools.map"

    _run "$root" import "${root}/carry" >/dev/null
    assert_eq "$?" "0" "import succeeds"
    local vql; vql="$(cat "${root}/docker.calls")"
    assert_contains "$vql" "tool='Hayabusa-2.14.0'" "first tool registered"
    assert_contains "$vql" "tool='SigmaProfiles'" "second tool registered"
}

test_import_reports_a_file_named_in_the_map_but_not_carried() {
    local root; root="$(_fake)"
    printf 'Missing\tnot_here.zip\n' > "${root}/carry/velo_tools.map"
    _run "$root" import "${root}/carry" >/dev/null
    assert_ne "$?" "0" "fails rather than claiming success"
    assert_contains "$(cat "${root}/err")" "missing file for Missing" "names the tool"
}

test_import_without_a_map_points_at_the_add_command() {
    local root; root="$(_fake)"
    _run "$root" import "${root}/carry" >/dev/null
    assert_ne "$?" "0" "fails"
    assert_contains "$(cat "${root}/err")" "velo_tools.sh add" "tells the operator what to do"
}

test_list_turns_the_servers_answer_into_a_carryable_tsv() {
    local root; root="$(_fake)"
    cat > "${root}/bin/docker" <<EOF
#!/bin/bash
case "\$1" in inspect) [[ "\$2" == "-f" ]] && echo true; exit 0 ;; esac
echo '{"Tool":"Hayabusa-2.14.0","Url":"https://example.test/hayabusa.zip","Expected":"abc123","Artifact":"Windows.Hayabusa.Rules"}'
echo '{"Tool":"Hayabusa-2.14.0","Url":"https://example.test/hayabusa.zip","Expected":"abc123","Artifact":"Windows.Hayabusa.Monitoring"}'
echo '{"Tool":"VendorOnly","Url":"","Expected":"","Artifact":"Windows.Vendor.Install"}'
EOF
    chmod +x "${root}/bin/docker"
    local out; out="$(_run "$root" list)"
    assert_contains "$out" $'Hayabusa-2.14.0\thttps://example.test/hayabusa.zip\tabc123' "tool, URL and the pinned hash"
    assert_contains "$out" "Windows.Hayabusa.Monitoring" "keeps every artifact that wants it"
    assert_eq "$(grep -c '^Hayabusa-2.14.0' <<<"$out")" "1" "one row per tool, not per artifact"
    assert_contains "$out" $'VendorOnly\t\t\t' "a tool with no public URL still appears"
}

test_fetch_downloads_the_listed_urls_and_writes_the_map() {
    local root; root="$(_fake)"
    printf '# TOOL\tURL\tSHA\tARTIFACTS\nHayabusa-2.14.0\thttps://example.test/hayabusa.zip\t%s\tW.H.Rules\nVendorOnly\t\t\tW.V.Install\n' \
        "239f59ed55e737c77147cf55ad0c1b030b6d7ee748a7426952f9b852d5a935e5" > "${root}/list.tsv"
    # curl stub: writes the -o target, so fetch sees a real file appear.
    cat > "${root}/bin/curl" <<'EOF'
#!/bin/bash
out=""; while [[ $# -gt 0 ]]; do [[ "$1" == "-o" ]] && { out="$2"; shift; }; shift; done
printf 'payload' > "$out"
EOF
    chmod +x "${root}/bin/curl"

    local out; out="$(_run "$root" fetch "${root}/list.tsv" --out "${root}/carry")"
    assert_eq "$?" "0" "fetch succeeds"
    assert_true test -f "${root}/carry/hayabusa.zip"
    assert_eq "$(cat "${root}/carry/velo_tools.map")" "$(printf 'Hayabusa-2.14.0\thayabusa.zip')" \
        "map carries the real tool name next to the file"
    assert_contains "$out" "no public URL" "says which tool needs the vendor"
    assert_contains "$out" "hash matches" "verified the pinned hash"
}

test_fetch_refuses_a_download_that_does_not_match_the_pinned_hash() {
    local root; root="$(_fake)"
    printf '# TOOL\tURL\tSHA\tARTIFACTS\nHayabusa-2.14.0\thttps://example.test/hayabusa.zip\tdeadbeef\tW.H.Rules\n' \
        > "${root}/list.tsv"
    cat > "${root}/bin/curl" <<'EOF'
#!/bin/bash
out=""; while [[ $# -gt 0 ]]; do [[ "$1" == "-o" ]] && { out="$2"; shift; }; shift; done
printf 'payload' > "$out"
EOF
    chmod +x "${root}/bin/curl"
    _run "$root" fetch "${root}/list.tsv" --out "${root}/carry" >/dev/null
    assert_ne "$?" "0" "fetch reports failure"
    assert_contains "$(cat "${root}/err")" "hash mismatch" "names the problem"
    assert_contains "$(cat "${root}/err")" "different version" "explains it"
}

# ---------------------------------------------------------------------------
# An artifact can pin its tool's sha256 (Hayabusa, SharpHound, Capa, Sigcheck
# all do). Registering a file that does not match succeeds at the server and
# then fails on the ENDPOINT, mid-collection, at a customer site.
# ---------------------------------------------------------------------------
test_add_refuses_a_file_the_artifact_would_reject() {
    local root; root="$(_fake)"
    printf 'payload' > "${root}/carry/hayabusa.zip"
    echo "not_the_hash_of_payload" > "${root}/expect_sha"

    _run "$root" add Hayabusa-2.14.0 "${root}/carry/hayabusa.zip" >/dev/null
    assert_ne "$?" "0" "refused"
    local e; e="$(cat "${root}/err")"
    assert_contains "$e" "hash mismatch" "says what is wrong"
    assert_contains "$e" "the artifact expects: not_the_hash_of_payload" "shows the expected hash"
    assert_contains "$e" "--force" "offers the override"
    assert_not_contains "$(cat "${root}/docker.calls")" "inventory_add" "nothing registered"
    assert_false test -f "${root}/tools/hayabusa.zip"   # and no stray file left behind
}

test_add_registers_when_the_hash_matches() {
    local root; root="$(_fake)"
    printf 'payload' > "${root}/carry/hayabusa.zip"
    sha256sum < "${root}/carry/hayabusa.zip" | cut -d' ' -f1 > "${root}/expect_sha"

    _run "$root" add Hayabusa-2.14.0 "${root}/carry/hayabusa.zip" >/dev/null
    assert_eq "$?" "0" "accepted"
    assert_contains "$(cat "${root}/docker.calls")" "inventory_add" "registered"
}

test_add_force_registers_a_mismatch_but_says_so() {
    local root; root="$(_fake)"
    printf 'payload' > "${root}/carry/hayabusa.zip"
    echo "not_the_hash_of_payload" > "${root}/expect_sha"

    local out; out="$(_run "$root" add --force Hayabusa-2.14.0 "${root}/carry/hayabusa.zip")"
    assert_eq "$?" "0" "registers"
    assert_contains "$out" "WARNING" "warns"
    assert_contains "$(cat "${root}/docker.calls")" "inventory_add" "registered"
}

# ---------------------------------------------------------------------------
# The upgrade's --velo-refresh used to register every file in data/tools under
# its FILE name. These two cover the fix: names come from the map and from the
# shipped pattern mapping, and anything unnamed is reported, not mis-registered.
# ---------------------------------------------------------------------------
_refresh_root() {
    local root; root="$(mktemp -d)"
    mkdir -p "${root}/data/tools"
    cat > "${root}/data/tools_inventory.yaml" <<'YAML'
velociraptor_inventory:
  - tool_name: "Autorun_amd64"
    file_pattern: "(?i)^autorunsc64.exe$"
    enabled: true
  - tool_name: "Hayabusa-2.14.0"
    file_pattern: "(?i)^hayabusa-.*-win-x64.zip$"
    enabled: false
YAML
    echo "$root"
}

_run_refresh() {  # _run_refresh <root>; prints the VQL it would send
    local root="$1"
    ( set +u
      SCRIPT_DIR="$root"
      log_info()  { echo "INFO $*"; }
      log_warn()  { echo "WARN $*"; }
      velo_vql()  { echo "VQL $1" >> "${root}/vql"; echo '{"r":{}}'; }
      source "${REPO}/lib/upgrade/velo_refresh.sh" >/dev/null 2>&1
      _velo_refresh_tools "" )
}

test_refresh_names_tools_from_the_map_and_the_shipped_patterns() {
    local root; root="$(_refresh_root)"
    echo a > "${root}/data/tools/autorunsc64.exe"                 # by pattern
    echo b > "${root}/data/tools/hayabusa-2.14.0-win-x64.zip"     # by pattern
    echo c > "${root}/data/tools/inhouse_collector.exe"           # by the operator's map
    printf 'InHouseCollector\tinhouse_collector.exe\n' > "${root}/data/tools/velo_tools.map"

    local out; out="$(_run_refresh "$root")"
    local vql; vql="$(cat "${root}/vql" 2>/dev/null)"
    assert_contains "$vql" "tool='Autorun_amd64'" "default tier by pattern"
    assert_contains "$vql" "tool='Hayabusa-2.14.0'" "optional tier by pattern"
    assert_contains "$vql" "tool='InHouseCollector'" "operator's own tool from the map"
    assert_not_contains "$vql" "tool='autorunsc64.exe'" "never registers a file name as a tool"
    assert_contains "$out" "3 registered by name" "counts what it did"
}

test_refresh_reports_a_file_it_cannot_name_instead_of_inventing_one() {
    local root; root="$(_refresh_root)"
    echo x > "${root}/data/tools/mystery_tool.exe"
    local out; out="$(_run_refresh "$root")"
    assert_contains "$out" "1 unnamed" "counts it"
    assert_contains "$out" "mystery_tool.exe" "names the file"
    assert_contains "$out" "velo_tools.sh add" "says how to fix it"
    assert_false test -s "${root}/vql"   # nothing registered under a guessed name
}

# ---------------------------------------------------------------------------
# `test` proves the last hop: an ENDPOINT downloading a tool from the server.
# Registering a tool and serving it are different things, and only the endpoint
# settles the second.
# ---------------------------------------------------------------------------
_fake_endpoint() {  # _fake_endpoint <root> <flow-state> [rows]
    local root="$1" state="$2" rows="${3:-yes}"
    cat > "${root}/bin/docker" <<EOF
#!/bin/bash
echo "\$@" >> "${root}/docker.calls"
case "\$1" in inspect) [[ "\$2" == "-f" ]] && echo true; exit 0 ;; esac
q="\$*"
case "\$q" in
    *"FROM inventory()"*)   echo '{"name":"etl2pcapng","filename":"etl2pcapng.zip"}' ;;
    *"FROM clients()"*)     echo '{"client_id":"C.1234567890abcdef"}' ;;
    *collect_client*)       echo '{"f":{"flow_id":"F.TESTFLOW01"}}' ;;
    *"FROM flows("*)        echo '{"state":"${state}","session_id":"F.TESTFLOW01"}' ;;
    *"FROM source("*)       [[ "${rows}" == "yes" ]] && echo '{"Binary":"C:/Windows/Temp/etl2pcapng.zip","Hash":"abc"}' ;;
esac
exit 0
EOF
    chmod +x "${root}/bin/docker"
}

test_test_reports_pass_when_the_endpoint_fetched_the_tool() {
    local root; root="$(_fake)"; _fake_endpoint "$root" FINISHED yes
    local out; out="$(_run "$root" test --tool etl2pcapng)"
    assert_eq "$?" "0" "exits 0"
    assert_contains "$out" "PASS" "says it passed"
    assert_contains "$out" "C.1234567890abcdef" "names the endpoint it used"
    local calls; calls="$(cat "${root}/docker.calls")"
    assert_contains "$calls" "Generic.Utils.FetchBinary" "collects the fetch helper"
    assert_contains "$calls" "ToolName='etl2pcapng'" "asks for the tool by name"
}

test_test_reports_fail_when_the_flow_errors() {
    local root; root="$(_fake)"; _fake_endpoint "$root" ERROR no
    _run "$root" test --tool etl2pcapng >/dev/null
    assert_ne "$?" "0" "exits non-zero"
    assert_contains "$(cat "${root}/err")" "FAIL" "says it failed"
    assert_contains "$(cat "${root}/err")" "flow_logs" "points at the flow log"
}

test_test_stops_when_no_endpoint_is_enrolled() {
    local root; root="$(_fake)"
    cat > "${root}/bin/docker" <<EOF
#!/bin/bash
case "\$1" in inspect) [[ "\$2" == "-f" ]] && echo true; exit 0 ;; esac
case "\$*" in *"FROM inventory()"*) echo '{"name":"etl2pcapng"}' ;; esac
exit 0
EOF
    chmod +x "${root}/bin/docker"
    _run "$root" test --tool etl2pcapng >/dev/null
    assert_ne "$?" "0" "exits non-zero"
    assert_contains "$(cat "${root}/err")" "no endpoint is enrolled" "says why"
}

test_test_stops_when_the_tool_is_not_stored() {
    local root; root="$(_fake)"
    cat > "${root}/bin/docker" <<'EOF'
#!/bin/bash
case "$1" in inspect) [[ "$2" == "-f" ]] && echo true; exit 0 ;; esac
exit 0
EOF
    chmod +x "${root}/bin/docker"
    _run "$root" test --tool NoSuchTool >/dev/null
    assert_ne "$?" "0" "exits non-zero"
    assert_contains "$(cat "${root}/err")" "not stored on this server" "says why"
    assert_contains "$(cat "${root}/err")" "velo_tools.sh add" "says how to fix it"
}

python3 -c 'import yaml' 2>/dev/null || {
    echo "$(basename "$0"): SKIP -- PyYAML not installed"; exit 0; }

run_all_tests
