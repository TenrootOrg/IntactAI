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
# what the list query sees: the rows the test planted
if [[ "\$*" == *"AS Artifact"* ]]; then
    [[ -s "${root}/list_rows" ]] && cat "${root}/list_rows"
    exit 0
fi
# the URL an artifact declares for a tool: per-tool file first, then the default
if [[ "\$*" == *"url AS u FROM"* ]]; then
    t="\$(sed -n "s/.*name = '\\([^']*\\)'.*/\\1/p" <<< "\$*" | head -1)"
    if [[ -n "\$t" && -s "${root}/url.\$t" ]]; then
        echo "{\"u\":\"\$(cat "${root}/url.\$t")\"}"
    elif [[ -s "${root}/tool_url" ]]; then
        echo "{\"u\":\"\$(cat "${root}/tool_url")\"}"
    fi
    exit 0
fi
# the endpoints and when they were last seen
if [[ "\$*" == *"FROM clients()"* ]]; then
    if [[ -s "${root}/client_seen" ]]; then
        echo "{\"client_id\":\"C.testclient01\",\"last_seen_at\":\$(cat "${root}/client_seen")}"
    fi
    exit 0
fi
# what the server already stores, for the re-run checks
if [[ "\$*" == *"FROM inventory()"*"serve_locally AND hash"* ]]; then
    [[ -s "${root}/stored_sha" ]] && echo "{\"hash\":\"\$(cat "${root}/stored_sha")\"}"
    exit 0
fi
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

# A curl stub that writes the -o target and records that it ran, so a test can
# prove a re-run downloaded nothing.
_curl_logging() {
    local root="$1"
    cat > "${root}/bin/curl" <<'CURL'
#!/bin/bash
[[ -n "${VELO_TEST_CURL_LOG:-}" ]] && echo DOWNLOADED >> "$VELO_TEST_CURL_LOG"
out=""; while [[ $# -gt 0 ]]; do [[ "$1" == "-o" ]] && { out="$2"; shift; }; shift; done
[[ -n "$out" ]] && printf 'payload' > "$out"
exit 0
CURL
    chmod +x "${root}/bin/curl"
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

test_import_says_which_carried_files_the_map_leaves_out() {
    # A folder reused between carries keeps its old map: new files dropped into
    # it were left out in silence while import reported success.
    local root; root="$(_fake)"
    echo a > "${root}/carry/hayabusa.zip"; echo b > "${root}/carry/brand_new.zip"
    printf 'Hayabusa-2.14.0\thayabusa.zip\n' > "${root}/carry/velo_tools.map"
    local out; out="$(_run "$root" import "${root}/carry")"
    assert_eq "$?" "0" "the mapped tool still registers"
    assert_contains "$out" "brand_new.zip" "names the file it did not register"
    assert_contains "$out" "NOT registered" "says plainly that it was left out"
    assert_not_contains "$(cat "${root}/docker.calls")" "brand_new" "and really did not register it"
}

test_import_refuses_a_map_written_with_spaces_instead_of_tabs() {
    local root; root="$(_fake)"
    echo a > "${root}/carry/hayabusa.zip"
    printf 'Hayabusa-2.14.0 hayabusa.zip\n' > "${root}/carry/velo_tools.map"
    _run "$root" import "${root}/carry" >/dev/null
    assert_ne "$?" "0" "fails rather than registering nothing and reporting success"
    assert_contains "$(cat "${root}/err")" "no TAB" "says what is wrong with the line"
}

test_import_names_an_installer_tool_from_the_shipped_inventory() {
    # `import data/tools` is the documented way back after the Docker volumes are
    # deleted. The installer's own tools are in no velo_tools.map, so it used to
    # leave Autoruns, LastActivityView, lolrmm and the Velociraptor binaries
    # unregistered — 10 files on this appliance.
    local root; root="$(_fake)"
    echo x > "${root}/carry/autorunsc64.exe"
    echo y > "${root}/carry/nothing_knows_this.bin"
    printf '# empty map\n' > "${root}/carry/velo_tools.map"
    local out; out="$(_run "$root" import "${root}/carry")"
    assert_contains "$(cat "${root}/docker.calls")" "tool='Autorun_amd64'" \
        "the shipped inventory names autorunsc64.exe"
    assert_contains "$out" "registered Autorun_amd64 -> autorunsc64.exe" "and says so"
    assert_contains "$out" "1 file(s) here are named by neither" "the genuinely unnamed file is reported"
    assert_contains "$out" "nothing_knows_this.bin" "by name"
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

test_install_does_not_download_a_tool_the_server_already_holds() {
    # Re-running install at a site used to re-fetch every tool over the
    # customer's link and register the same bytes again.
    local root; root="$(_fake)"
    echo "abc123" > "${root}/stored_sha"
    echo "https://example.test/hayabusa.zip" > "${root}/tool_url"
    _curl_logging "$root"
    local out; out="$(VELO_TEST_CURL_LOG="${root}/curl.log" _run "$root" install Hayabusa-2.14.0)"
    assert_eq "$?" "0" "install succeeds"
    assert_contains "$out" "already stored" "says it is already there"
    assert_contains "$out" "0 added, 1 already stored" "and the summary does not claim it added one"
    assert_false test -s "${root}/curl.log"
}

test_install_downloads_again_when_the_stored_copy_is_the_wrong_version() {
    local root; root="$(_fake)"
    echo "abc123" > "${root}/stored_sha"          # what the server holds
    echo "deadbeef" > "${root}/expect_sha"        # what the artifact pins
    echo "https://example.test/hayabusa.zip" > "${root}/tool_url"
    _curl_logging "$root"
    local out; out="$(VELO_TEST_CURL_LOG="${root}/curl.log" _run "$root" install Hayabusa-2.14.0)"
    assert_contains "$out" "does not match the hash" "says why it downloads anyway"
    assert_true test -s "${root}/curl.log"
}

test_fetching_twice_into_the_same_folder_keeps_one_map_line() {
    local root; root="$(_fake)"
    printf 'Hayabusa-2.14.0\thttps://example.test/hayabusa.zip\t\tW.H.Rules\n' > "${root}/list.tsv"
    _curl_logging "$root"
    _run "$root" fetch "${root}/list.tsv" --out "${root}/carry" >/dev/null
    _run "$root" fetch "${root}/list.tsv" --out "${root}/carry" >/dev/null
    assert_eq "$(grep -c . "${root}/carry/velo_tools.map")" "1" "one line per tool, not one per run"
}

test_a_tool_test_against_an_offline_endpoint_is_a_skip_not_a_failure() {
    # Live: every enrolled client came from an imported dataset and was last seen
    # eight days ago. The collection queues, the flow stays RUNNING, and the test
    # waited two minutes and then reported FAIL — of the tool, which was fine.
    local root; root="$(_fake)"
    echo "abc123" > "${root}/stored_sha"      # the tool IS on the server
    python3 -c "import time; print(int((time.time()-8*86400)*1000000))" > "${root}/client_seen"
    local out; out="$(_run "$root" test --tool etl2pcapng)"
    assert_eq "$?" "2" "exits 2: could not prove, did not fail"
    assert_contains "$out" "SKIP" "says SKIP"
    assert_contains "$out" "days ago" "says how stale the endpoint is"
    assert_not_contains "$(cat "${root}/docker.calls")" "collect_client" "no collection was queued"
}

test_a_tool_test_against_a_live_endpoint_runs() {
    local root; root="$(_fake)"
    echo "abc123" > "${root}/stored_sha"      # the tool IS on the server
    python3 -c "import time; print(int((time.time()-30)*1000000))" > "${root}/client_seen"
    local out; out="$(_run "$root" test --tool etl2pcapng)"
    assert_ne "$?" "2" "a live endpoint is not skipped"
    assert_not_contains "$out" "offline" "and is not called offline"
}

test_fetch_accepts_a_process_substitution() {
    # `fetch <(grep ... missing.tsv)` failed with "no such file: /dev/fd/63".
    local root; root="$(_fake)"
    _curl_logging "$root"
    local out; out="$(_run "$root" fetch <(printf 'Gimphash\thttps://example.test/g.exe\t\tA\n') --out "${root}/carry")"
    assert_eq "$?" "0" "reads it"
    assert_contains "$out" "1 downloaded" "and fetches what it lists"
}

test_fetch_does_not_carry_a_download_that_failed_its_hash() {
    # Live: ESET's "latest" URL serves a newer build than the artifact pins. The
    # rejected file AND its map line stayed in the carry folder, so the operator
    # took to the site a file the endpoint would refuse.
    local root; root="$(_fake)"
    printf 'Good\thttps://example.test/good.zip\t\tA\nPinned\thttps://example.test/pinned.zip\tdeadbeef\tB\n' > "${root}/list.tsv"
    _curl_logging "$root"
    _run "$root" fetch "${root}/list.tsv" --out "${root}/carry" >/dev/null
    assert_ne "$?" "0" "reports the failure"
    assert_false test -f "${root}/carry/pinned.zip"
    assert_not_contains "$(cat "${root}/carry/velo_tools.map")" "Pinned" "and no map line for it"
    assert_contains "$(cat "${root}/carry/velo_tools.map")" "Good" "the good one is still carried"
}

test_the_carried_map_is_readable_by_the_far_end() {
    local root; root="$(_fake)"
    printf 'Good\thttps://example.test/good.zip\t\tA\n' > "${root}/list.tsv"
    _curl_logging "$root"
    _run "$root" fetch "${root}/list.tsv" --out "${root}/carry" >/dev/null
    assert_eq "$(stat -c '%a' "${root}/carry/velo_tools.map")" "644" "not mktemp's 600"
}

test_selftest_moves_past_a_tool_it_cannot_install() {
    # Live: the first missing tool alphabetically was ESETLogCollector, whose
    # vendor serves a newer build than the artifact pins, and the next was an FTK
    # download behind a 403. selftest reported four failures about an appliance
    # that was working perfectly.
    local root; root="$(_fake)"
    printf '{"Tool":"Aunfetchable","Url":"https://example.test/u.zip","Expected":"","Artifact":"A"}\n{"Tool":"Fine","Url":"https://example.test/fine.zip","Expected":"","Artifact":"B"}\n' \
        > "${root}/list_rows"
    echo "https://example.test/fine.zip" > "${root}/url.Fine"   # only this one resolves
    _curl_logging "$root"
    local out; out="$(_run "$root" selftest)"
    assert_contains "$out" "installed Fine" "moves on and installs the one that works"
    assert_not_contains "$out" "FAIL  could not install" "and does not call the appliance broken"
}

test_install_says_the_server_is_starting_rather_than_blaming_the_tool() {
    # Live: the docs' remove section restarts Velociraptor, and the very next
    # install said "no download URL known for Takajo-2.5.0" — for a tool whose
    # artifact declares one. The engine was simply not answering yet.
    local root; root="$(_fake)"
    cat > "${root}/bin/docker" <<EOF
#!/bin/bash
case "\$1" in
    inspect)
        [[ "\$2" == "-f" && "\$3" == *StartedAt* ]] && { date -u +%Y-%m-%dT%H:%M:%S.000000000Z; exit 0; }
        [[ "\$2" == "-f" ]] && { echo true; exit 0; }
        exit 0 ;;
esac
exit 0
EOF
    chmod +x "${root}/bin/docker"
    _run "$root" install Takajo-2.5.0 >/dev/null
    local e; e="$(cat "${root}/err")"
    assert_contains "$e" "not answering yet" "says the server is not ready"
    assert_not_contains "$e" "no download URL known" "instead of blaming the tool"
}

test_a_quiet_server_that_did_not_just_restart_still_reports_the_real_problem() {
    local root; root="$(_fake)"
    cat > "${root}/bin/docker" <<EOF
#!/bin/bash
case "\$1" in
    inspect)
        [[ "\$2" == "-f" && "\$3" == *StartedAt* ]] && { echo "2020-01-01T00:00:00.000000000Z"; exit 0; }
        [[ "\$2" == "-f" ]] && { echo true; exit 0; }
        exit 0 ;;
esac
exit 0
EOF
    chmod +x "${root}/bin/docker"
    _run "$root" install VendorOnly >/dev/null
    assert_contains "$(cat "${root}/err")" "no download URL known" "the ordinary message"
}

test_fetch_refuses_a_list_that_matched_nothing() {
    # Live: the page's own example filter matched nothing on a box that already
    # held both tools, and fetch still said "carry <dir> to the appliance".
    local root; root="$(_fake)"
    printf '# 52 tool(s) missing\n# TOOL\tURL\tSHA\tARTIFACTS\n' > "${root}/list.tsv"
    _curl_logging "$root"
    _run "$root" fetch "${root}/list.tsv" --out "${root}/carry" >/dev/null
    assert_ne "$?" "0" "fails instead of sending an empty folder to the site"
    assert_contains "$(cat "${root}/err")" "nothing to fetch" "says what happened"
    assert_not_contains "$(cat "${root}/out" 2>/dev/null)" "carry " "and does not say to carry it"
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
      velo_vql()      { echo "VQL $1" >> "${root}/vql"; echo '{"r":{}}'; }
      velo_vql_api()  { echo "VQL $1" >> "${root}/vql"; echo '{"r":{}}'; }
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

test_refresh_registers_against_the_running_server_not_a_second_copy() {
    # `query --config server.config.yaml` starts a NEW local Velociraptor whose
    # writes the running server discards. Live: the refresh said "37 tools
    # registered by name" and registered none — a custom tool added by the
    # operator was gone after the refresh that is meant to replay it.
    local root; root="$(_refresh_root)"
    echo c > "${root}/data/tools/inhouse_collector.exe"
    printf 'InHouseCollector\tinhouse_collector.exe\n' > "${root}/data/tools/velo_tools.map"
    ( set +u
      SCRIPT_DIR="$root"
      log_info() { :; }; log_warn() { :; }
      velo_vql()     { echo "CONFIG $1" >> "${root}/calls"; echo '{"r":{}}'; }
      velo_vql_api() { echo "API $1"    >> "${root}/calls"; echo '{"r":{}}'; }
      source "${REPO}/lib/upgrade/velo_refresh.sh" >/dev/null 2>&1
      _velo_refresh_tools "" ) >/dev/null
    assert_contains "$(grep inventory_add "${root}/calls")" "API " "registers through the running server"
    assert_not_contains "$(grep inventory_add "${root}/calls")" "CONFIG " "never through a second local copy"
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

# ---------------------------------------------------------------------------
# `install` exists because copying a URL by hand is where this goes wrong: a
# guessed file name 404s, and a wrong version fails the artifact's hash check.
# The URL comes from the artifact that wants the tool.
# ---------------------------------------------------------------------------
test_install_downloads_the_url_the_server_reports() {
    local root; root="$(_fake)"
    cat > "${root}/bin/docker" <<EOF
#!/bin/bash
echo "\$@" >> "${root}/docker.calls"
case "\$1" in inspect) [[ "\$2" == "-f" ]] && echo true; exit 0 ;; esac
case "\$*" in
    *"url AS u"*)       echo '{"u":"https://example.test/takajo-2.5.0-win.zip"}' ;;
    *expected_hash*)    ;;
    *)                  echo '{"r":{"name":"x"}}' ;;
esac
exit 0
EOF
    chmod +x "${root}/bin/docker"
    cat > "${root}/bin/curl" <<'EOF'
#!/bin/bash
echo "curl $*" >> "CALLS"
out=""; while [[ $# -gt 0 ]]; do [[ "$1" == "-o" ]] && { out="$2"; shift; }; shift; done
printf 'payload' > "$out"
EOF
    sed -i "s#CALLS#${root}/curl.calls#" "${root}/bin/curl"; chmod +x "${root}/bin/curl"

    local out; out="$(_run "$root" install Takajo-2.5.0)"
    assert_eq "$?" "0" "install succeeds"
    assert_contains "$(cat "${root}/curl.calls")" "https://example.test/takajo-2.5.0-win.zip" "downloads what the server named"
    assert_contains "$(cat "${root}/docker.calls")" "tool='Takajo-2.5.0'" "registers under that name"
    assert_contains "$out" "1 added, 0 already stored, 0 failed" "reports what it did"
    assert_true test -f "${root}/tools/takajo-2.5.0-win.zip"
}

test_install_says_what_to_do_when_there_is_no_public_url() {
    local root; root="$(_fake)"
    cat > "${root}/bin/docker" <<EOF
#!/bin/bash
case "\$1" in inspect) [[ "\$2" == "-f" ]] && echo true; exit 0 ;; esac
exit 0
EOF
    chmod +x "${root}/bin/docker"
    _run "$root" install CrowdStrikeFalconInstaller >/dev/null
    assert_ne "$?" "0" "fails"
    local e; e="$(cat "${root}/err")"
    assert_contains "$e" "no download URL known" "says why"
    assert_contains "$e" "velo_tools.sh add CrowdStrikeFalconInstaller" "points at the manual route"
}

# ---------------------------------------------------------------------------
# `selftest` is the one-command check. What matters is that it never calls a
# step it could not prove a pass -- an unproven step is SKIP, and a served file
# whose bytes do not match the stored hash is a FAIL, not a pass.
# ---------------------------------------------------------------------------
_selftest_stub() {  # _selftest_stub <root> <served-body>
    local root="$1" body="$2"
    printf '%s' "$body" > "${root}/served"
    cat > "${root}/bin/docker" <<EOF
#!/bin/bash
case "\$1" in inspect) [[ "\$2" == "-f" ]] && echo true; exit 0 ;; esac
case "\$*" in
    *"NOT name IN stored.name"*) echo '{"Tool":"Aftermath","Url":"https://example.test/aftermath","Expected":"","Artifact":"MacOS.Collection.Aftermath"}' ;;
    *"url AS u"*)                echo '{"u":"https://example.test/aftermath"}' ;;
    *"FROM clients()"*)          ;;
    *"serve_url FROM inventory"*) echo '{"filename":"aftermath","hash":"HASHVAL","serve_url":"https://srv:8000/public/abc"}' ;;
    *"FROM inventory()"*)        echo '{"name":"Aftermath","filename":"aftermath","hash":"HASHVAL"}' ;;
    *)                           echo '{"r":{"name":"Aftermath"}}' ;;
esac
exit 0
EOF
    sed -i "s/HASHVAL/$(printf '%s' "$body" | sha256sum | cut -d' ' -f1)/g" "${root}/bin/docker"
    chmod +x "${root}/bin/docker"
    cat > "${root}/bin/curl" <<EOF
#!/bin/bash
out=""; while [[ \$# -gt 0 ]]; do [[ "\$1" == "-o" ]] && { out="\$2"; shift; }; shift; done
if [[ -n "\$out" ]]; then printf '%s' "\$(cat ${root}/served)" > "\$out"; else cat "${root}/served"; fi
EOF
    chmod +x "${root}/bin/curl"
}

test_selftest_passes_when_the_served_bytes_match() {
    local root; root="$(_fake)"; _selftest_stub "$root" "the-real-payload"
    local out; out="$(_run "$root" selftest)"
    assert_eq "$?" "0" "exits 0"
    assert_contains "$out" "0 fail" "nothing failed"
    assert_contains "$out" "the hash matches" "checked the served bytes"
    assert_contains "$out" "SKIP  no endpoint is enrolled" "endpoint step is skipped, not claimed"
}

test_selftest_fails_when_the_server_serves_different_bytes() {
    local root; root="$(_fake)"; _selftest_stub "$root" "the-real-payload"
    # the server hands back something else than the hash it recorded
    printf 'tampered' > "${root}/served.alt"
    cat > "${root}/bin/curl" <<EOF
#!/bin/bash
out=""; while [[ \$# -gt 0 ]]; do [[ "\$1" == "-o" ]] && { out="\$2"; shift; }; shift; done
if [[ -n "\$out" ]]; then printf '%s' "\$(cat ${root}/served)" > "\$out"; else cat "${root}/served.alt"; fi
EOF
    chmod +x "${root}/bin/curl"
    _run "$root" selftest >/dev/null
    assert_ne "$?" "0" "exits non-zero"
    assert_contains "$(cat "${root}/err")" "do not match the stored hash" "says what is wrong"
}

test_help_always_shows_the_command_list() {
    local root; root="$(_fake)"
    # The help used to print a fixed line range of the header, so adding a line
    # to the header silently cut the Usage line off the bottom.
    local out; out="$(_run "$root")"
    assert_contains "$out" "Usage: scripts/velo_tools.sh" "prints the usage line"
    for c in list install fetch add import status test selftest; do
        assert_contains "$out" "$c" "help mentions $c"
    done
}

python3 -c 'import yaml' 2>/dev/null || {
    echo "$(basename "$0"): SKIP -- PyYAML not installed"; exit 0; }

run_all_tests
