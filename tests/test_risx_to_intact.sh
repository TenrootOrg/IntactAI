#!/bin/bash
# scripts/migrate/risx_to_intact.sh -- the guided risx-mssp -> Intact migration.
#
# The real script runs end to end against a fake risx box and a fake Intact
# checkout. sudo, docker, install.sh and the adopt script are stubs that record
# what they were asked to do; every answer is fed on stdin exactly as an
# operator would type it. What cannot run here is install.sh and the identity
# swap themselves -- both have their own suites (test_adopt_velo_identity.sh).

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
             "$W/intact/data/velociraptor" "$W/bin" "$W/log"
    cat > "$velo/server.config.yaml" <<'YAML'
Client:
  server_urls: ["https://10.9.8.7:8000/"]
  ca_certificate: "-----BEGIN CERTIFICATE-----\nFAKECA\n-----END CERTIFICATE-----"
  nonce: "FAKENONCE="
CA: {private_key: "-----BEGIN RSA PRIVATE KEY-----\nFAKEKEY\n-----END RSA PRIVATE KEY-----"}
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
cp "\$2/server.config.yaml" "$W/intact/data/velociraptor/server.config.yaml"
EOF
    printf '#!/bin/bash\n[[ "$1" == reboot ]] && { echo "reboot" >> %q; exit 0; }\nexec "$@"\n' "$W/log/calls" > "$W/bin/sudo"
    cat > "$W/bin/docker" <<EOF
#!/bin/bash
echo "docker \$*" >> "$W/log/calls"
[[ "\$1" == exec ]] && echo "C.1234  endpoint-1"
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

# mode 1, find y, copied y, REMOVE, reboot n, install y, history Y, shred y
SAME_MACHINE='1\ny\ny\nREMOVE\nn\ny\n\ny\ny\n'

test_same_machine_runs_every_step_in_order() {
    _world; mkdir -p "$W/home"
    _run "$SAME_MACHINE"
    assert_eq "$RC" "0" "the whole run must succeed: $(tail -5 <<<"$OUT")"
    local calls; calls="$(cat "$W/log/calls")"
    assert_contains "$calls" "cleanup " "risx removed with its own cleanup.sh"
    assert_contains "$calls" "install " "install.sh ran"
    assert_contains "$calls" "adopt --from $W/backup -y --datastore" "adopted from the backup, with history"
    # order: remove before install before adopt
    local c i a
    c=$(grep -n '^cleanup' "$W/log/calls" | cut -d: -f1); i=$(grep -n '^install' "$W/log/calls" | cut -d: -f1)
    a=$(grep -n '^adopt' "$W/log/calls" | cut -d: -f1)
    assert_true test "$c" -lt "$i"; assert_true test "$i" -lt "$a"
    assert_eq "$(sed -n 's/^domain: //p' "$W/intact/config.yaml")" "10.9.8.7" "domain pre-set to what clients dial"
    assert_contains "$OUT" "CA in use matches the backup" "verified against the backup"
    for s in find backup copied removed config installed adopted verified; do
        assert_true grep -qx "$s" "$(_state)"
    done
}

test_the_archive_keeps_history_and_drops_the_installers() {
    _world; mkdir -p "$W/home"
    _run "$SAME_MACHINE"
    local tarball; tarball="$(ls "$W"/backup/velociraptor-full-*.tar.gz)"
    local list; list="$(tar -tzf "$tarball")"
    assert_contains "$list" "velociraptor/server.config.yaml"
    assert_contains "$list" "velociraptor/clients/C.1234/collections/flow.json" "client records kept"
    assert_not_contains "$list" "clients/linux" "repacked installers left out"
    assert_contains "$(cat "$W/log/calls")" "ds: clients/C.1234/collections/flow.json" "history handed to the adopt step"
    assert_eq "$(stat -c %a "$tarball")" "600" "the archive holds the CA key"
}

test_the_scp_pause_prints_powershell_and_bash_lines() {
    _world; mkdir -p "$W/home"
    _run '1\ny\nn\n'                       # stop at the copy prompt
    assert_eq "$RC" "0" "stopping at the pause is not an error"
    assert_contains "$OUT" "PowerShell:"
    assert_contains "$OUT" "bash (Linux/macOS):"
    assert_contains "$OUT" "scp -r \"$(id -un)@"
    assert_eq "$(stat -c %a "$W/backup/server.config.yaml")" "600" "the config copy is a credential"
    assert_false grep -q '^cleanup' "$W/log/calls"
}

test_anything_but_REMOVE_removes_nothing() {
    _world; mkdir -p "$W/home"
    _run '1\ny\ny\nremove\n'
    assert_ne "$RC" "0"
    assert_false grep -q '^cleanup' "$W/log/calls"
    assert_true test -f "$W/risx/setup_platform/workdir/velociraptor/velociraptor/server.config.yaml"
}

test_a_rerun_continues_after_risx_is_gone() {
    _world; mkdir -p "$W/home"
    _run '1\ny\ny\nREMOVE\nn\nn\n'           # stop at the config review
    assert_true grep -qx removed "$(_state)"
    assert_false grep -qx config "$(_state)"
    _run 'y\n\ny\ny\n'                       # re-run: install y, history Y, adopt y, shred y
    assert_eq "$RC" "0" "the re-run must finish: $(tail -5 <<<"$OUT")"
    assert_contains "$OUT" "resuming the 'same' migration"
    assert_eq "$(grep -c '^cleanup' "$W/log/calls")" "1" "risx is not removed twice"
    assert_contains "$(cat "$W/log/calls")" "install "
}

test_a_wrong_domain_is_caught_before_install() {
    _world; mkdir -p "$W/home"
    printf '#!/bin/bash\nsed -i "s/^domain:.*/domain: elsewhere.example/" "$1"\n' > "$W/bin/ed-wrong"
    chmod +x "$W/bin/ed-wrong"
    RC=0
    OUT="$(printf '1\ny\ny\nREMOVE\nn\ny\nn\nn\n' | PATH="$W/bin:$PATH" HOME="$W/home" EDITOR=ed-wrong \
           RISX_ROOT="$W/risx/setup_platform" \
           bash "$W/intact/scripts/migrate/risx_to_intact.sh" --backup-dir "$W/backup" 2>&1)" || RC=$?
    assert_contains "$OUT" "NOT what the clients dial (10.9.8.7)"
    assert_false grep -q '^install' "$W/log/calls"
}

test_new_box_waits_for_the_backup_then_installs_and_adopts() {
    _world; mkdir -p "$W/home"
    cp "$W/risx/setup_platform/workdir/velociraptor/velociraptor/server.config.yaml" "$W/old.yaml"
    rm -rf "$W/risx"                         # there is no risx on the new box
    _run '3\nn\n'                            # no backup yet: stop
    assert_contains "$OUT" "No backup at $W/backup yet"
    assert_false grep -q '^install' "$W/log/calls"
    # the backup arrives, as scp would bring it from the old box (config only)
    cp "$W/old.yaml" "$W/backup/server.config.yaml"
    _run 'y\ny\ny\ny\n'                      # identity y, install y, adopt y, shred y
    assert_eq "$RC" "0" "$(tail -5 <<<"$OUT")"
    assert_contains "$OUT" "resuming the 'new' migration"
    assert_contains "$(cat "$W/log/calls")" "adopt --from $W/backup"
    assert_not_contains "$(cat "$W/log/calls")" "--datastore" "no archive: identity only"
    assert_contains "$OUT" "powered off, NOT wiped"
    assert_false test -e "$W/backup/server.config.yaml" "working copy shredded"
}

test_old_box_backs_up_and_stops_without_removing() {
    _world; mkdir -p "$W/home"
    _run '2\ny\nn\ny\n'                      # mode 2, find y, don't stop velo, copied y
    assert_eq "$RC" "0" "$(tail -5 <<<"$OUT")"
    assert_contains "$OUT" "on the NEW box"
    assert_false grep -q '^cleanup' "$W/log/calls"
    assert_false grep -q '^install' "$W/log/calls"
    assert_true test -s "$W/backup/server.config.yaml"
}

test_help_and_root_guard() {
    local out; out="$(bash "$REPO/scripts/migrate/risx_to_intact.sh" --help)"
    assert_contains "$out" "server_urls"
    assert_contains "$out" "--package"
    assert_true grep -q 'not root' "$REPO/scripts/migrate/risx_to_intact.sh"
}

# --- what the review found ---------------------------------------------------

test_the_backup_carried_to_the_new_box_does_not_resume_as_the_old_box() {
    _world; mkdir -p "$W/home"
    RISX_MIG_MACHINE=oldbox _run '2\ny\nn\ny\n'           # old box: back up, copied
    assert_eq "$RC" "0" "$(tail -3 <<<"$OUT")"
    rm -rf "$W/risx"                                        # now on the new box
    RISX_MIG_MACHINE=newbox _run '3\ny\ny\n\ny\ny\n'    # new box: 3, identity, install, history, adopt, shred
    assert_eq "$RC" "0" "$(tail -5 <<<"$OUT")"
    assert_not_contains "$OUT" "resuming the 'old'"
    assert_contains "$(cat "$W/log/calls")" "adopt --from $W/backup -y --datastore"
}

test_saying_no_at_adopt_changes_nothing_and_is_not_recorded() {
    _world; mkdir -p "$W/home"
    _run '1\ny\ny\nREMOVE\nn\ny\n\nn\n'               # ... history Y, adopt N
    assert_ne "$RC" "0"
    assert_false grep -q '^adopt' "$W/log/calls"
    assert_false grep -qx adopted "$(_state)"
}

test_an_adopt_that_did_not_take_is_not_recorded() {
    _world; mkdir -p "$W/home"
    ADOPT_NOOP=1 _run "$SAME_MACHINE"
    assert_ne "$RC" "0"
    assert_contains "$OUT" "does not run"
    assert_false grep -qx adopted "$(_state)"
}

test_a_removal_cut_off_midway_continues_from_the_backup() {
    _world; mkdir -p "$W/home"
    _run '1\ny\nn\n'                       # backed up, stopped at the copy pause
    rm -rf "$W/risx/setup_platform/workdir/"*  # cleanup.sh ran but the script never recorded it
    _run 'y\n\ny\ny\n'                     # install y, history Y, adopt y, shred y
    assert_eq "$RC" "0" "$(tail -5 <<<"$OUT")"
    assert_contains "$OUT" "no longer on this box"
    assert_contains "$(cat "$W/log/calls")" "install "
}

test_a_finished_migration_rerun_is_a_noop() {
    _world; mkdir -p "$W/home"
    _run "$SAME_MACHINE"
    _run ''
    assert_eq "$RC" "0"
    assert_contains "$OUT" "already complete"
}

test_a_relative_backup_dir_still_works_after_changing_directory() {
    _world; mkdir -p "$W/home"
    RC=0
    OUT="$(cd "$W" && printf '%b' "$SAME_MACHINE" | PATH="$W/bin:$PATH" HOME="$W/home" EDITOR=true \
           RISX_ROOT="$W/risx/setup_platform" \
           bash "$W/intact/scripts/migrate/risx_to_intact.sh" --backup-dir rel-backup 2>&1)" || RC=$?
    assert_eq "$RC" "0" "$(tail -3 <<<"$OUT")"
    assert_contains "$(cat "$W/log/calls")" "adopt --from $W/rel-backup"
}

run_all_tests
