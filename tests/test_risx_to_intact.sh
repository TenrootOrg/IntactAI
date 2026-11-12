#!/bin/bash
# scripts/migrate/risx_to_intact.sh -- risx-mssp -> Intact on the same machine.
#
# The real script runs end to end against a fake risx box and a fake Intact
# checkout. sudo, docker, install.sh and the adopt script are stubs that record
# what they were asked to do; every answer is fed on stdin exactly as an
# operator would type it. A normal run asks exactly twice: "r" at the pause,
# and "y" on the config. install.sh and the identity swap have their own suites.

source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

python3 -c 'import yaml' 2>/dev/null || {
    echo "$(basename "$0"): SKIP -- PyYAML not installed"; exit 0; }

# Build: $W/risx (a risx box), $W/intact (an Intact checkout), $W/bin (stubs).
_world() {
    W="$(mktemp -d)"
    local velo="$W/risx/setup_platform/workdir/velociraptor/velociraptor"
    mkdir -p "$velo/clients/C.1234/collections" "$velo/clients/linux" \
             "$W/risx/setup_platform/scripts" "$W/intact/scripts/migrate" \
             "$W/intact/data/velociraptor" "$W/bin" "$W/log" "$W/home"
    cat > "$velo/server.config.yaml" <<'YAML'
Client:
  server_urls: ["https://10.9.8.7:8000/"]
  ca_certificate: "-----BEGIN CERTIFICATE-----\nFAKECA\n-----END CERTIFICATE-----"
  nonce: "FAKENONCE="
# Not a PEM block on purpose: the release build's gitleaks scan rejects any
# PEM private-key header, fake or not, and the script never parses the key.
CA: {private_key: "FAKEKEY-not-a-real-key"}
Datastore: {location: ".", filestore_directory: "."}
YAML
    echo record > "$velo/clients/C.1234/collections/flow.json"
    echo binary > "$velo/clients/linux/velociraptor_client"
    # risx's own teardown: empties workdir, as the real one does
    cat > "$W/risx/setup_platform/scripts/cleanup.sh" <<EOF
#!/bin/bash
echo "cleanup \$*" >> "$W/log/calls"
rm -rf "$W/risx/setup_platform/workdir/"*
EOF
    # the Intact checkout: the real scripts under test, the real config.yaml
    cp "$REPO/scripts/migrate/risx_to_intact.sh" "$REPO/scripts/migrate/risx_lib.sh" "$W/intact/scripts/migrate/"
    cp "$REPO/config.yaml" "$W/intact/config.yaml"
    cat > "$W/intact/install.sh" <<EOF
echo "install \$*" >> "$W/log/calls"
EOF
    cat > "$W/intact/scripts/adopt_velociraptor_identity.sh" <<EOF
echo "adopt \$*" >> "$W/log/calls"
# record what the datastore dir held, then "adopt": install the backed-up config
[[ "\$*" == *--datastore* ]] && find "\${@: -1}" -type f | sed 's|.*/velociraptor/|ds: |' >> "$W/log/calls"
[[ -n "\${ADOPT_NOOP:-}" ]] && exit 0
# write into the checkout this stub lives in (a cloned one in the clone test)
d="\$(dirname "\$0")/../data/velociraptor"; mkdir -p "\$d"
cp "\$2/server.config.yaml" "\$d/server.config.yaml"
EOF
    printf '#!/bin/bash\n[[ "$1" == reboot ]] && { echo "reboot" >> %q; exit 0; }\nexec "$@"\n' "$W/log/calls" > "$W/bin/sudo"
    cat > "$W/bin/docker" <<EOF
#!/bin/bash
echo "docker \$*" >> "$W/log/calls"
[[ "\$1" == exec ]] && echo '[{"client_id": "C.1234", "host": "endpoint-1"}, {"client_id": "C.5678", "host": "endpoint-2"}]'
[[ "\$*" == *--filter* ]] && echo "Up 2 minutes"
exit 0
EOF
    chmod +x "$W/bin/"* "$W/risx/setup_platform/scripts/cleanup.sh"
}

_state() { echo "$W/backup/.risx_to_intact.$(cat /etc/machine-id 2>/dev/null || hostname).state"; }

# _run "answers" [extra args...] -> output in $OUT, exit code in $RC
_run() {
    local answers="$1"; shift
    RC=0
    OUT="$(printf '%b' "$answers" | PATH="$W/bin:$PATH" HOME="$W/home" EDITOR=true \
           RISX_ROOT="$W/risx/setup_platform" \
           bash "$W/intact/scripts/migrate/risx_to_intact.sh" --backup-dir "$W/backup" "$@" 2>&1)" || RC=$?
}

# The only two answers a normal run needs: r at the pause, y on the config.
NORMAL='r\ny\n'

test_a_normal_run_asks_twice_and_does_every_step_in_order() {
    _world
    _run "$NORMAL"
    assert_eq "$RC" "0" "the whole run must succeed: $(tail -5 <<<"$OUT")"
    local calls; calls="$(cat "$W/log/calls")"
    assert_contains "$calls" "cleanup " "risx removed with its own cleanup.sh"
    assert_contains "$calls" "install " "install.sh ran"
    assert_contains "$calls" "adopt --from $W/backup -y --datastore" "adopted, always with the history"
    assert_not_contains "$calls" "reboot" "no reboot"
    local c i a
    c=$(grep -n '^cleanup' "$W/log/calls" | cut -d: -f1); i=$(grep -n '^install' "$W/log/calls" | cut -d: -f1)
    a=$(grep -n '^adopt' "$W/log/calls" | cut -d: -f1)
    assert_true test "$c" -lt "$i"; assert_true test "$i" -lt "$a"
    assert_eq "$(sed -n 's/^domain: //p' "$W/intact/config.yaml")" "10.9.8.7" "domain pre-set to what clients dial"
    assert_contains "$OUT" "CA in use matches the backup"
    for s in find backup copied removed config installed adopted verified; do
        assert_true grep -qx "$s" "$(_state)"
    done
    # exactly two answers were read
    assert_eq "$(grep -c 'answer:' "$W"/backup/risx_to_intact-*.log)" "2" "a normal run asks twice"
}

test_the_archive_keeps_history_and_drops_the_installers() {
    _world
    _run "$NORMAL"
    local tarball; tarball="$(ls "$W"/backup/velociraptor-full-*.tar.gz)"
    local list; list="$(tar -tzf "$tarball")"
    assert_contains "$list" "velociraptor/server.config.yaml"
    assert_contains "$list" "velociraptor/clients/C.1234/collections/flow.json" "client records kept"
    assert_not_contains "$list" "clients/linux" "repacked installers left out"
    assert_contains "$(cat "$W/log/calls")" "ds: clients/C.1234/collections/flow.json" "history handed to the adopt step"
    assert_eq "$(stat -c %a "$tarball")" "600" "the archive holds the CA key"
}

test_the_pause_shows_scp_lines_and_waits_for_r() {
    _world
    _run 'c\nx\n'                            # anything but r keeps waiting; then end of input
    assert_ne "$RC" "0"
    assert_contains "$OUT" "PowerShell:"
    assert_contains "$OUT" "bash (Linux/macOS):"
    assert_contains "$OUT" "scp -r \"$(id -un)@"
    assert_contains "$OUT" "NEXT: risx-mssp is REMOVED"
    assert_eq "$(stat -c %a "$W/backup/server.config.yaml")" "600" "the config copy is a credential"
    assert_false grep -q '^cleanup' "$W/log/calls"
    assert_true test -f "$W/risx/setup_platform/workdir/velociraptor/velociraptor/server.config.yaml"
}

test_the_client_count_is_reported() {
    _world
    _run "$NORMAL"
    assert_contains "$OUT" "clients known to the new server: 2 (e.g. endpoint-1, endpoint-2)"
}

test_a_rerun_after_risx_is_gone_continues() {
    _world
    _run 'r\n'                               # removed, then end of input at the config
    assert_true grep -qx removed "$(_state)"
    assert_false grep -qx config "$(_state)"
    _run 'y\n'
    assert_eq "$RC" "0" "the re-run must finish: $(tail -5 <<<"$OUT")"
    assert_eq "$(grep -c '^cleanup' "$W/log/calls")" "1" "risx is not removed twice"
    assert_contains "$(cat "$W/log/calls")" "install "
}

test_a_removal_cut_off_midway_continues_from_the_backup() {
    _world
    _run ''                                  # backed up, stopped at the pause
    rm -rf "$W/risx/setup_platform/workdir/"*  # cleanup ran but was never recorded
    _run 'y\n'
    assert_eq "$RC" "0" "$(tail -5 <<<"$OUT")"
    assert_contains "$OUT" "no longer on this box"
    assert_contains "$(cat "$W/log/calls")" "install "
}

test_a_wrong_domain_is_caught_before_install() {
    _world
    printf '#!/bin/bash\nsed -i "s/^domain:.*/domain: elsewhere.example/" "$1"\n' > "$W/bin/ed-wrong"
    chmod +x "$W/bin/ed-wrong"
    RC=0
    OUT="$(printf 'r\ny\nn\n' | PATH="$W/bin:$PATH" HOME="$W/home" EDITOR=ed-wrong \
           RISX_ROOT="$W/risx/setup_platform" \
           bash "$W/intact/scripts/migrate/risx_to_intact.sh" --backup-dir "$W/backup" 2>&1)" || RC=$?
    assert_contains "$OUT" "NOT what the clients dial (10.9.8.7)"
    assert_false grep -q '^install' "$W/log/calls"
}

test_an_adopt_that_did_not_take_is_not_recorded() {
    _world
    ADOPT_NOOP=1 _run "$NORMAL"
    assert_ne "$RC" "0"
    assert_contains "$OUT" "does not run"
    assert_false grep -qx adopted "$(_state)"
}

test_a_finished_migration_rerun_is_a_noop() {
    _world
    _run "$NORMAL"
    _run ''
    assert_eq "$RC" "0"
    assert_contains "$OUT" "already complete"
}

test_a_relative_backup_dir_still_works() {
    _world
    RC=0
    OUT="$(cd "$W" && printf '%b' "$NORMAL" | PATH="$W/bin:$PATH" HOME="$W/home" EDITOR=true \
           RISX_ROOT="$W/risx/setup_platform" \
           bash "$W/intact/scripts/migrate/risx_to_intact.sh" --backup-dir rel-backup 2>&1)" || RC=$?
    assert_eq "$RC" "0" "$(tail -3 <<<"$OUT")"
    assert_contains "$(cat "$W/log/calls")" "adopt --from $W/rel-backup"
}

# --- run from anywhere --------------------------------------------------------

test_a_copy_of_the_script_runs_from_any_folder_using_the_intact_checkout() {
    _world
    mkdir -p "$W/elsewhere" && cp "$REPO/scripts/migrate/risx_to_intact.sh" "$W/elsewhere/"
    RC=0
    OUT="$(cd /tmp && printf '%b' "$NORMAL" | PATH="$W/bin:$PATH" HOME="$W/home" EDITOR=true \
           RISX_ROOT="$W/risx/setup_platform" INTACT_DIR="$W/intact" \
           bash "$W/elsewhere/risx_to_intact.sh" --backup-dir "$W/backup" 2>&1)" || RC=$?
    assert_eq "$RC" "0" "$(tail -3 <<<"$OUT")"
    assert_contains "$OUT" "at $W/intact"
    assert_contains "$(cat "$W/log/calls")" "install "
}

test_without_a_checkout_it_clones_the_release_first() {
    _world
    # a "release" repo holding the fake checkout, tagged
    local src="$W/src"; cp -r "$W/intact" "$src"
    git -C "$src" init -q && git -C "$src" add -A && \
        git -C "$src" -c user.email=t@t -c user.name=t commit -qm r && git -C "$src" tag intact-29990101
    mkdir -p "$W/elsewhere" && cp "$REPO/scripts/migrate/risx_to_intact.sh" "$W/elsewhere/"
    RC=0
    OUT="$(cd /tmp && printf '%b' "$NORMAL" | PATH="$W/bin:$PATH" HOME="$W/home" EDITOR=true \
           RISX_ROOT="$W/risx/setup_platform" INTACT_DIR="$W/home/intact" \
           INTACT_RELEASE_TAG=intact-29990101 INTACT_GIT_URL="$src" \
           bash "$W/elsewhere/risx_to_intact.sh" --backup-dir "$W/backup" 2>&1)" || RC=$?
    assert_eq "$RC" "0" "$(tail -3 <<<"$OUT")"
    assert_contains "$OUT" "Fetching Intact intact-29990101 into $W/home/intact"
    assert_true test -f "$W/home/intact/scripts/migrate/risx_to_intact.sh"
}

# --- logging ------------------------------------------------------------------

test_the_log_has_output_answers_and_steps_but_no_secrets() {
    _world
    _run "$NORMAL"
    local log; log="$(ls "$W"/backup/risx_to_intact-*.log)"
    assert_eq "$(stat -c %a "$log")" "600" "the log is owner-only"
    local body; body="$(cat "$log")"
    assert_contains "$body" "answer: r" "typed answers are logged"
    assert_contains "$body" "=== 4. Remove risx-mssp" "steps are logged"
    assert_contains "$body" "CA in use matches the backup" "output is logged"
    assert_not_contains "$body" "FAKENONCE" "the nonce never reaches the log"
    assert_not_contains "$body" "FAKEKEY" "the CA key never reaches the log"
}

test_an_error_lists_the_logs_to_collect() {
    _world
    _run ''
    assert_ne "$RC" "0"
    assert_contains "$OUT" "Logs to collect"
    assert_contains "$OUT" "$W/backup/risx_to_intact-"
}

test_help() {
    local out; out="$(bash "$REPO/scripts/migrate/risx_to_intact.sh" --help)"
    assert_contains "$out" "server_urls"
    assert_contains "$out" "SAME machine"
    assert_true grep -q 'not root' "$REPO/scripts/migrate/risx_to_intact.sh"
}

run_all_tests
