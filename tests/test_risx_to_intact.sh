#!/bin/bash
# scripts/migrate/risx_to_intact.sh -- risx-mssp -> Intact on the same machine.
#
# The real script runs end to end against a fake risx box and a fake Intact
# checkout. sudo, docker, install.sh and the adopt script are stubs that record
# what they were asked to do; every answer is fed on stdin exactly as an
# operator would type it. A normal run asks three times, all before risx is
# removed: Enter on the backup choice (configuration only), "y" on the config,
# and "r" at the pause. install.sh and the identity swap have their own suites.

source "$(dirname "${BASH_SOURCE[0]}")/helpers.sh"

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

python3 -c 'import yaml' 2>/dev/null || {
    echo "$(basename "$0"): SKIP -- PyYAML not installed"; exit 0; }

# Build: $W/risx (a risx box), $W/intact (an Intact checkout), $W/bin (stubs).
_world() {
    W="$(mktemp -d)"
    local velo="$W/risx/setup_platform/workdir/velociraptor/velociraptor"
    mkdir -p "$velo/clients/C.1234/collections" "$velo/clients/C.5678" "$velo/clients/linux" \
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
# --force: takes the leftovers, and says what the real one says about Docker's own networks
[[ "\$1" == --force ]] && { rm -f "$W/log/left"; echo "Error response from daemon: bridge is a pre-defined network and cannot be removed"; }
exit 0
EOF
    # the Intact checkout: the real scripts under test, the real config.yaml
    cp "$REPO/scripts/migrate/risx_to_intact.sh" "$REPO/scripts/migrate/risx_lib.sh" \
       "$REPO/scripts/migrate/transform_config.py" "$W/intact/scripts/migrate/"
    cp "$REPO/config.yaml" "$W/intact/config.yaml"
    # what the install leaves: lib/secrets.sh and the Velociraptor store
    mkdir -p "$W/intact/lib" "$W/intact/modules/velociraptor/secrets"
    cp "$REPO/lib/secrets.sh" "$W/intact/lib/"
    printf 'VELOX_USER=tenroot\nVELOX_ROLE=administrator\nVELOX_USER_2=api\n' > "$W/intact/modules/velociraptor/.env"
    printf 'VELOX_PASSWORD=GuiStored1Abc\nVELOX_PASSWORD_2=ApiStored2Xyz\n' > "$W/intact/modules/velociraptor/secrets/creds.env"
    cat > "$W/intact/install.sh" <<EOF
echo "install \$*" >> "$W/log/calls"
[[ -z "\${INSTALL_FAIL:-}" ]]
EOF
    cat > "$W/intact/scripts/adopt_velociraptor_identity.sh" <<EOF
echo "adopt \$*" >> "$W/log/calls"
# record what the datastore dir held, then "adopt": install the backed-up config
[[ "\$*" == *--datastore* ]] && { d="\${@: -1}"; find "\$d" -type f | sed "s|^\$d/|ds: |"; } >> "$W/log/calls"
[[ -n "\${ADOPT_NOOP:-}" ]] && exit 0
# write into the checkout this stub lives in (a cloned one in the clone test)
d="\$(dirname "\$0")/../data/velociraptor"; mkdir -p "\$d"
cp "\$2/server.config.yaml" "\$d/server.config.yaml"
EOF
    # sudo: runs the command as you; -v / -n answer like a cached sudo unless
    # $W/log/sudo_refuse exists (a mistyped password, an expired ticket).
    cat > "$W/bin/sudo" <<EOF
#!/bin/bash
[[ "\$1" == reboot ]] && { echo "reboot" >> "$W/log/calls"; exit 0; }
if [[ "\$1" == -v || "\$1" == -n ]]; then
    [[ -e "$W/log/sudo_refuse" ]] && { echo "sudo: refused" >&2; exit 1; }
    [[ "\$1" == -n ]] && shift
    [[ "\$1" == -v || "\$1" == true ]] && exit 0
fi
exec "\$@"
EOF
    cat > "$W/bin/docker" <<EOF
#!/bin/bash
echo "docker \$*" >> "$W/log/calls"
# user add: the value arrives in the exec's environment (\$_P), never its argv
[[ "\$*" == *"user add"* ]] && echo "\${@: -2:1} \$_P" >> "$W/log/velo_pw"
[[ "\$1" == exec ]] && echo '[{"client_id": "C.1234", "host": "endpoint-1"}, {"client_id": "C.5678", "host": "endpoint-2"}]'
[[ "\$*" == *--filter* ]] && echo "Up 2 minutes"
# containers cleanup.sh left behind (the test creates \$W/log/left)
[[ "\$*" == "ps -a --format"* && -e "$W/log/left" ]] && cat "$W/log/left"
exit 0
EOF
    # The GUI login check after the recreate (never the real 127.0.0.1:8889):
    # 200 unless $W/log/velo_refuse exists. Records the URL, never the password.
    cat > "$W/bin/curl" <<EOF
#!/bin/bash
cat >/dev/null
echo "curl \${*: -1}" >> "$W/log/calls"
[[ -e "$W/log/velo_refuse" ]] && echo 401 || echo 200
EOF
    # free space where Docker keeps its volumes: $FAKE_FREE_GB (default plenty)
    printf '#!/bin/bash\n[[ "$*" == *-B1G* ]] && { echo Avail; echo "${FAKE_FREE_GB:-500}"; exit 0; }\nexec %q "$@"\n' \
        "$(command -v df)" > "$W/bin/df"
    chmod +x "$W/bin/"* "$W/risx/setup_platform/scripts/cleanup.sh"
}

_state() { echo "$W/backup/.risx_to_intact.$(cat /etc/machine-id 2>/dev/null || hostname).state"; }

# _run "answers" [extra args...] -> output in $OUT, exit code in $RC
_run() {
    local answers="$1"; shift
    RC=0
    OUT="$(printf '%b' "$answers" | PATH="$W/bin:$PATH" HOME="$W/home" EDITOR=true VELO_LOGIN_WAIT=1 \
           RISX_ROOT="$W/risx/setup_platform" \
           bash "$W/intact/scripts/migrate/risx_to_intact.sh" --backup-dir "$W/backup" "$@" 2>&1)" || RC=$?
}

# The answers a normal run needs, all before the removal: Enter (= configuration
# only) on the backup choice, y on the config, r at the pause.
NORMAL='\ny\nr\n'

test_a_normal_run_asks_three_times_and_does_every_step_in_order() {
    _world
    _run "$NORMAL"
    assert_eq "$RC" "0" "the whole run must succeed: $(tail -5 <<<"$OUT")"
    local calls; calls="$(cat "$W/log/calls")"
    assert_contains "$calls" "cleanup " "risx removed with its own cleanup.sh"
    assert_contains "$calls" "install " "install.sh ran"
    assert_contains "$calls" "adopt --from $W/backup -y --datastore $W/backup/datastore" "adopted with the moved history"
    assert_true grep -qx backup_mode=config "$(_state)"
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
    # exactly three answers were read
    assert_eq "$(grep -c 'answer:' "$W"/backup/risx_to_intact-*.log)" "3" "a normal run asks three times"
}

test_the_adopted_users_get_the_stored_passwords() {
    _world
    _run "$NORMAL"
    assert_eq "$RC" "0" "$(tail -5 <<<"$OUT")"
    local calls; calls="$(cat "$W/log/calls")"
    assert_contains "$(cat "$W/log/velo_pw")" "tenroot GuiStored1Abc" "the GUI user gets the stored password"
    assert_contains "$(cat "$W/log/velo_pw")" "api ApiStored2Xyz" "api gets its stored password"
    assert_contains "$calls" 'docker exec -e _P intact_velociraptor sh -c'
    assert_contains "$calls" '--role "$2" _ tenroot administrator'
    assert_contains "$calls" '--role "$2" _ api api,administrator' "api keeps its identity and roles"
    assert_not_contains "$calls" "GuiStored1Abc" "not in the docker argv (docker events log it)"
    assert_not_contains "$calls" "ApiStored2Xyz"
    assert_not_contains "$calls" "user delete" "api is never removed"
    assert_not_contains "$calls" "user_delete" "api is never removed"
    assert_not_contains "$(cat "$W"/backup/risx_to_intact-*.log)" "GuiStored1Abc" "the password stays out of the log"
}

test_the_users_take_their_new_passwords_only_after_a_recreate() {
    # 0.77.3: a running server does not see `user add` until it restarts, and
    # a plain restart would keep the old env_file. So: user add, recreate, log in.
    _world
    _run "$NORMAL"
    assert_eq "$RC" "0" "$(tail -5 <<<"$OUT")"
    local add rec login
    add="$(grep -n '_ api api,administrator' "$W/log/calls" | cut -d: -f1)"
    rec="$(grep -n 'docker compose up -d --force-recreate --no-build --pull never velociraptor' "$W/log/calls" | cut -d: -f1)"
    login="$(grep -n '^curl http://127.0.0.1:8889/velociraptor/app/index.html' "$W/log/calls" | tail -1 | cut -d: -f1)"
    assert_true test -n "$rec"
    assert_true test "$add" -lt "$rec"
    assert_true test "$rec" -lt "$login"
    assert_eq "$(grep -c '^curl ' "$W/log/calls")" "2" "both the GUI user and api are checked"
    assert_not_contains "$(cat "$W/log/calls")" "docker restart"
}

test_a_login_refused_after_the_recreate_stops_before_verified() {
    _world
    : > "$W/log/velo_refuse"
    _run "$NORMAL"
    assert_ne "$RC" "0"
    assert_contains "$OUT" "does not accept the stored password"
    assert_false grep -qx verified "$(_state)"
}

test_a_missing_store_stops_before_verified() {
    _world
    rm -f "$W/intact/modules/velociraptor/secrets/creds.env"
    _run "$NORMAL"
    assert_ne "$RC" "0"
    assert_contains "$OUT" "passwords Intact stored"
    assert_false grep -qx verified "$(_state)"
}

test_every_known_default_is_flagged_not_only_123123() {
    _world
    printf '#!/bin/bash\nsed -i "0,/password:.*/s//password: changeme/" "$1"\n' > "$W/bin/ed-weak"
    chmod +x "$W/bin/ed-weak"
    RC=0
    OUT="$(printf '\ny\n' | PATH="$W/bin:$PATH" HOME="$W/home" EDITOR=ed-weak \
           RISX_ROOT="$W/risx/setup_platform" \
           bash "$W/intact/scripts/migrate/risx_to_intact.sh" --backup-dir "$W/backup" 2>&1)" || RC=$?
    assert_contains "$OUT" "publicly known password"
}

test_data_mode_moves_the_datastore_instead_of_archiving_it() {
    _world
    _run '2\ny\nr\n'
    assert_eq "$RC" "0" "$(tail -5 <<<"$OUT")"
    assert_true test -f "$W/backup/datastore/clients/C.1234/collections/flow.json"
    assert_false compgen -G "$W/backup/velociraptor-full-*.tar.gz" "no archive any more"
    assert_contains "$OUT" "same disk, instant"
    assert_contains "$(cat "$W/log/calls")" "ds: clients/C.1234/collections/flow.json" "history handed to the adopt step"
    assert_eq "$(stat -c %a "$W/backup/datastore")" "700" "the datastore holds the CA key"
    assert_eq "$(stat -c %U "$W/backup/datastore/clients/C.1234/collections/flow.json")" "$(id -un)" "yours, so scp can read it"
    assert_true grep -qx backup_mode=data "$(_state)"
    assert_contains "$OUT" "scp -r \"$(id -un)@" "the whole backup, datastore included"
}

test_configuration_only_still_brings_the_history_and_copies_only_the_configs() {
    # The choice is only what the off-box copy holds: Intact gets the data either way.
    _world
    _run '1\ny\nr\n'
    assert_eq "$RC" "0" "$(tail -5 <<<"$OUT")"
    assert_contains "$(cat "$W/log/calls")" "adopt --from $W/backup -y --datastore $W/backup/datastore"
    assert_contains "$(cat "$W/log/calls")" "ds: clients/C.1234/collections/flow.json"
    assert_contains "$OUT" "scp \"$(id -un)@" "the config files only"
    assert_contains "$OUT" "$W/backup/*.config.yaml\" ."
    assert_not_contains "$OUT" "scp -r"
}

test_the_backup_option_skips_the_question() {
    _world
    _run 'y\nr\n' --backup config
    assert_eq "$RC" "0" "$(tail -5 <<<"$OUT")"
    assert_eq "$(grep -c 'answer:' "$W"/backup/risx_to_intact-*.log)" "2" "no backup question"
    assert_contains "$(cat "$W/log/calls")" "--datastore"
    _world
    _run 'x\n' --backup everything
    assert_ne "$RC" "0"
    assert_contains "$OUT" "--backup must be config or data"
}

test_the_pause_shows_one_scp_line_and_waits_for_r() {
    _world
    _run '\ny\nc\nx\n'                       # anything but r keeps waiting; then end of input
    assert_ne "$RC" "0"
    assert_not_contains "$OUT" "PowerShell:"
    assert_eq "$(grep -c '^    scp .*config.yaml' <<<"$OUT")" "1" "one command for every shell"
    assert_contains "$OUT" "scp \"$(id -un)@"
    assert_contains "$OUT" "sudo mv $W/backup/datastore $W/risx/setup_platform/workdir/velociraptor/velociraptor" "how to put risx back"
    assert_contains "$OUT" "NEXT: risx-mssp is REMOVED"
    assert_eq "$(stat -c %a "$W/backup/server.config.yaml")" "600" "the config copy is a credential"
    assert_false grep -q '^cleanup' "$W/log/calls"
}

test_a_rerun_after_stopping_at_the_pause_still_removes_risx() {
    # data mode moved risx's server.config.yaml away with the datastore: a
    # re-run must still find risx, and must still run its cleanup.sh
    _world
    _run '\ny\n'                             # backed up (moved), stopped at the pause
    assert_false test -e "$W/risx/setup_platform/workdir/velociraptor/velociraptor"
    _run 'r\n'
    assert_eq "$RC" "0" "$(tail -5 <<<"$OUT")"
    assert_not_contains "$OUT" "no longer on this box"
    assert_eq "$(grep -c '^cleanup' "$W/log/calls")" "1" "risx removed by its own cleanup.sh"
    assert_contains "$(cat "$W/log/calls")" "--datastore $W/backup/datastore"
}

test_an_archive_from_the_old_script_is_unpacked_once_and_reused() {
    _world
    # a backup the previous version made, stopped before the install
    mkdir -p "$W/backup"
    local velo="$W/risx/setup_platform/workdir/velociraptor"
    cp "$velo/velociraptor/server.config.yaml" "$W/backup/"
    tar -czf "$W/backup/velociraptor-full-20261112-120000.tar.gz" -C "$velo" velociraptor
    rm -rf "$W/risx/setup_platform/workdir/"*
    printf 'find\nbackup\ndskb=10\ncopied\nremoved\n' > "$(_state)"
    ADOPT_NOOP=1 _run 'y\n'                  # the adopt "fails": a retry follows
    assert_ne "$RC" "0"
    assert_contains "$OUT" "unpacking $W/backup/velociraptor-full-20261112-120000.tar.gz into $W/backup/datastore"
    assert_contains "$(cat "$W/log/calls")" "ds: clients/C.1234/collections/flow.json"
    _run ''
    assert_eq "$RC" "0" "$(tail -5 <<<"$OUT")"
    assert_not_contains "$OUT" "unpacking" "the retry reuses the unpacked datastore"
    assert_contains "$(cat "$W/log/calls")" "--datastore $W/backup/datastore"
}

test_every_question_comes_before_risx_is_removed() {
    _world
    _run "$NORMAL"
    assert_eq "$RC" "0" "$(tail -5 <<<"$OUT")"
    local log last cleanup
    log="$(ls "$W"/backup/risx_to_intact-*.log)"
    last="$(grep -n 'answer:' "$log" | tail -1 | cut -d: -f1)"
    cleanup="$(grep -n '=== 7. Remove risx-mssp' "$log" | cut -d: -f1)"
    assert_true test "$last" -lt "$cleanup"
}

test_a_missing_piece_of_the_checkout_stops_before_anything_changes() {
    _world
    rm "$W/intact/scripts/adopt_velociraptor_identity.sh"
    _run "$NORMAL"
    assert_ne "$RC" "0"
    assert_contains "$OUT" "has no scripts/adopt_velociraptor_identity.sh"
    assert_false grep -q '^cleanup' "$W/log/calls"
    assert_false grep -q 'docker update' "$W/log/calls" "risx's Velociraptor is not even stopped"
    assert_true test -f "$W/risx/setup_platform/workdir/velociraptor/velociraptor/server.config.yaml"
}

test_disk_space_is_checked_before_anything_changes() {
    _world
    FAKE_FREE_GB=0 _run "$NORMAL"
    assert_ne "$RC" "0"
    assert_contains "$OUT" "not enough space under"
    assert_false grep -q '^cleanup' "$W/log/calls"
    _world
    FAKE_FREE_GB=50 _run '\ny\nn\n'          # below the README's 100 GB: asked, and refused
    assert_ne "$RC" "0"
    assert_contains "$OUT" "Intact wants 100 GB free"
    assert_contains "$OUT" "stopped before anything changed"
    assert_true test -f "$W/risx/setup_platform/workdir/velociraptor/velociraptor/server.config.yaml"
}

test_a_configuration_only_backup_from_the_previous_version_still_moves_the_history() {
    # 391e84af's "configuration only" left the datastore in risx. A re-run of
    # such a migration must move it before cleanup.sh deletes it.
    _world
    mkdir -p "$W/backup"
    cp "$W/risx/setup_platform/workdir/velociraptor/velociraptor/server.config.yaml" "$W/backup/"
    printf 'find\nbackup_mode=config\nbackup\nconfig\n' > "$(_state)"
    _run 'r\n'
    assert_eq "$RC" "0" "$(tail -5 <<<"$OUT")"
    assert_contains "$(cat "$W/log/calls")" "ds: clients/C.1234/collections/flow.json"
}

test_leftover_containers_are_described_and_force_stays_quiet() {
    _world
    echo "misp-db-1  (mysql:8, Exited (0) 2 hours ago)" > "$W/log/left"
    _run '\ny\nr\ny\n'                       # the normal three, then y to --force
    assert_eq "$RC" "0" "$(tail -5 <<<"$OUT")"
    assert_contains "$OUT" "still present after cleanup.sh"
    assert_contains "$OUT" "misp-db-1  (mysql:8, Exited (0) 2 hours ago)" "what it is, not just a name"
    assert_contains "$OUT" "removed the rest"
    assert_contains "$(cat "$W/log/calls")" "cleanup --force"
    assert_not_contains "$OUT" "pre-defined network" "cleanup.sh's own noise stays in the log"
    assert_contains "$(cat "$W"/backup/risx_to_intact-*.log)" "pre-defined network"
}

test_sudo_is_asked_once_at_the_start_and_a_refusal_stops_there() {
    _world
    : > "$W/log/sudo_refuse"
    _run "$NORMAL"
    assert_ne "$RC" "0"
    assert_contains "$OUT" "this script needs sudo (it is asked once, here)"
    assert_false grep -qx find "$(_state)" "nothing started"
}

test_a_sudo_refused_mid_run_stops_the_step_and_a_rerun_continues() {
    # QA, 2026-11-18: sudo expired during the install, three wrong passwords in
    # step 9, and the step went on with an empty CA.
    _world
    printf 'touch %q\n' "$W/log/sudo_refuse" >> "$W/intact/install.sh"   # the install outlasts sudo
    _run "$NORMAL"
    assert_ne "$RC" "0"
    assert_contains "$OUT" "sudo was refused — run the script again; it continues from this step"
    assert_true grep -qx installed "$(_state)"
    assert_false grep -qx adopted "$(_state)" "the adopt never ran half-way"
    assert_not_contains "$(cat "$W/log/calls")" "adopt --from"
    rm -f "$W/log/sudo_refuse"; sed -i '$d' "$W/intact/install.sh"
    _run ''
    assert_eq "$RC" "0" "$(tail -5 <<<"$OUT")"
    assert_contains "$(cat "$W/log/calls")" "adopt --from"
}

test_the_client_count_is_reported() {
    _world
    _run "$NORMAL"
    assert_contains "$OUT" "clients known to the new server: 2 of the 2 risx had (e.g. endpoint-1, endpoint-2)"
    # asked of the running server: a separate --config query process reads none
    assert_contains "$(cat "$W/log/calls")" "--api_config /velociraptor/api.config.yaml query"
    assert_not_contains "$OUT" "appear as they reconnect"
}

test_clients_still_missing_are_named_not_warned_about() {
    _world
    mkdir -p "$W/risx/setup_platform/workdir/velociraptor/velociraptor/clients/C.9abc"
    VELO_COUNT_WAIT=0 _run "$NORMAL"
    assert_eq "$RC" "0" "$(tail -5 <<<"$OUT")"
    assert_contains "$OUT" "clients known to the new server: 2 of the 3 risx had"
    assert_contains "$OUT" "the other 1 appear as they reconnect"
    assert_not_contains "$OUT" "WARN"
}

test_a_rerun_after_risx_is_gone_continues() {
    _world
    INSTALL_FAIL=1 _run "$NORMAL"            # removed, then the install fails
    assert_ne "$RC" "0"
    assert_true grep -qx removed "$(_state)"
    assert_false grep -qx installed "$(_state)"
    _run ''                                   # nothing left to ask
    assert_eq "$RC" "0" "the re-run must finish: $(tail -5 <<<"$OUT")"
    assert_eq "$(grep -c '^cleanup' "$W/log/calls")" "1" "risx is not removed twice"
    assert_contains "$(cat "$W/log/calls")" "install "
}

test_a_removal_cut_off_midway_continues_from_the_backup() {
    _world
    _run '\ny\n'                             # backed up, stopped at the pause
    rm -rf "$W/risx/setup_platform/workdir/"*  # cleanup ran but was never recorded
    _run ''
    assert_eq "$RC" "0" "$(tail -5 <<<"$OUT")"
    assert_contains "$OUT" "no longer on this box"
    assert_contains "$(cat "$W/log/calls")" "install "
}

test_a_wrong_domain_is_caught_before_install() {
    _world
    printf '#!/bin/bash\nsed -i "s/^domain:.*/domain: elsewhere.example/" "$1"\n' > "$W/bin/ed-wrong"
    chmod +x "$W/bin/ed-wrong"
    RC=0
    OUT="$(printf '\ny\nn\n' | PATH="$W/bin:$PATH" HOME="$W/home" EDITOR=ed-wrong \
           RISX_ROOT="$W/risx/setup_platform" \
           bash "$W/intact/scripts/migrate/risx_to_intact.sh" --backup-dir "$W/backup" 2>&1)" || RC=$?
    assert_contains "$OUT" "NOT what the clients dial (10.9.8.7)"
    assert_false grep -q '^install' "$W/log/calls"
    assert_false grep -q '^cleanup' "$W/log/calls" "caught while risx still runs"
    assert_true test -f "$W/risx/setup_platform/workdir/velociraptor/velociraptor/server.config.yaml"
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
    assert_contains "$body" "=== 7. Remove risx-mssp" "steps are logged"
    assert_contains "$body" "CA in use matches the backup" "output is logged"
    assert_not_contains "$body" "FAKENONCE" "the nonce never reaches the log"
    assert_not_contains "$body" "FAKEKEY" "the CA key never reaches the log"
}

test_an_error_leaves_one_file_to_send_back() {
    _world
    _run ''
    assert_ne "$RC" "0"
    assert_contains "$OUT" "Everything to send back is in one file"
    local tgz; tgz="$(ls "$W"/backup/risx_to_intact-*-logs.tar.gz)"
    assert_true test -f "$tgz"
    assert_eq "$(stat -c %a "$tgz")" "600" "it may name hosts and accounts"
    assert_contains "$OUT" "scp \"$(id -un)@" "how to copy it off"
    assert_contains "$OUT" "$tgz\" ."
}

test_the_bundle_has_the_logs_and_the_box_but_no_secret() {
    _world
    printf 'install log line\nVELOX_PASSWORD=GuiStored1Abc\n' > "$W/intact/install_20261117.log"
    _run "$NORMAL"
    assert_eq "$RC" "0" "$(tail -5 <<<"$OUT")"
    local tgz x; tgz="$(ls "$W"/backup/risx_to_intact-*-logs.tar.gz)"
    x="$(mktemp -d)"; tar -xzf "$tgz" -C "$x"
    assert_true test -f "$x/box.txt"
    assert_true test -f "$x/config.yaml"
    assert_true test -f "$x/install_20261117.log"
    assert_true compgen -G "$x/risx_to_intact-*.log"
    assert_contains "$(cat "$x/box.txt")" "== containers"
    assert_contains "$(cat "$x/box.txt")" "== migration state"
    assert_contains "$(cat "$x"/risx_to_intact-*.log)" "CA in use matches the backup" "the whole run is in it"
    assert_contains "$(cat "$x/install_20261117.log")" "VELOX_PASSWORD=[REDACTED]"
    local all; all="$(cat "$x"/* )"
    assert_not_contains "$all" "GuiStored1Abc"
    assert_not_contains "$all" "FAKEKEY"
    assert_not_contains "$all" "FAKENONCE"
    assert_false test -e "$x/server.config.yaml" "never the fleet's CA config"
    rm -rf "$x"
}

test_help() {
    local out; out="$(bash "$REPO/scripts/migrate/risx_to_intact.sh" --help)"
    assert_contains "$out" "server_urls"
    assert_contains "$out" "SAME machine"
    assert_true grep -q 'not root' "$REPO/scripts/migrate/risx_to_intact.sh"
}

run_all_tests
