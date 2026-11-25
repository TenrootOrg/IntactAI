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
    # risx's own teardown is never run any more: if anything calls it, it shows
    cat > "$W/risx/setup_platform/scripts/cleanup.sh" <<EOF
#!/bin/bash
echo "cleanup \$*" >> "$W/log/calls"
exit 0
EOF
    # risx's stacks: compose files (timesketch one folder deeper, as on risx),
    # its installer clone and loose files next to setup_platform
    local wd="$W/risx/setup_platform/workdir"
    mkdir -p "$wd/elk" "$wd/misp" "$wd/timesketch/timesketch" "$W/risx/Risx-MSSP/setup_platform/workdir"
    for d in elk misp timesketch/timesketch; do echo "services: {}" > "$wd/$d/docker-compose.yml"; done
    echo "TIMESKETCH_VERSION=1" > "$wd/timesketch/timesketch/.env"
    # risx's unconfigured templates of the same stacks (no .env)
    mkdir -p "$W/risx/setup_platform/resources/elk" "$W/risx/setup_platform/resources/timesketch"
    for d in elk timesketch; do echo "services: {}" > "$W/risx/setup_platform/resources/$d/docker-compose.yml"; done
    echo zip > "$W/risx/upgrade-scripts.zip"; echo "api: x" > "$W/risx/hohit_api.config.yaml"
    # Docker on a risx box: two stacks (one running), a one-off `docker run`, and
    # a running container and an image that are not risx's
    cat > "$W/log/docker.json" <<JSON
{"build_cache": "1.9GB", "containers": [
  {"id": "c-elk", "name": "elasticsearch", "project": "elk", "wd": "$wd/elk", "status": "Exited (0) 1 hour ago",
   "image": "sha256:img-elk", "vols": ["elk_elasticsearch"], "nets": ["elk_default", "main_network"]},
  {"id": "c-misp", "name": "misp-db-1", "project": "misp", "wd": "$wd/misp", "status": "Up 2 hours",
   "image": "sha256:img-misp", "vols": ["misp_mysql_data", "$(printf 'a%.0s' {1..64})"], "nets": ["misp_default"]},
  {"id": "c-oneoff", "name": "kind_lovelace", "project": "", "wd": "", "status": "Exited (0) 5 months ago",
   "image": "sha256:img-plaso", "vols": [], "nets": ["bridge"]},
  {"id": "c-other", "name": "someone-else", "project": "", "wd": "", "status": "Up 3 days",
   "image": "sha256:img-other", "vols": [], "nets": ["bridge"]}],
 "volumes": [{"name": "elk_elasticsearch", "project": "elk"}, {"name": "misp_mysql_data", "project": "misp"},
   {"name": "$(printf 'a%.0s' {1..64})", "project": ""}, {"name": "$(printf 'b%.0s' {1..64})", "project": "", "dangling": true},
   {"name": "other_data", "project": "", "dangling": true}],
 "networks": [{"name": "main_network", "project": ""}, {"name": "elk_default", "project": "elk"},
   {"name": "misp_default", "project": "misp"}],
 "images": [{"id": "sha256:img-elk", "ref": "elk-elasticsearch:latest", "size": 1073741824},
   {"id": "sha256:img-misp", "ref": "mariadb:10.11", "size": 536870912},
   {"id": "sha256:img-misp-old", "ref": "mariadb:10.6", "size": 268435456},
   {"id": "sha256:img-plaso", "ref": "log2timeline/plaso:latest", "size": 536870912},
   {"id": "sha256:img-dangling", "ref": "<none>:<none>", "size": 268435456, "dangling": true},
   {"id": "sha256:img-other", "ref": "alpine:latest", "size": 8000000}]}
JSON
    cp "$REPO/tests/fake_docker_risx.py" "$W/bin/fake_docker.py"
    # crontab: the user's and root's (sudo exports FAKE_ROOT), MISP's job in root's
    cat > "$W/bin/crontab" <<EOF
#!/bin/bash
f="$W/log/crontab_user"; [[ -n "\${FAKE_ROOT:-}" ]] && f="$W/log/crontab_root"
[[ "\$1" == -l ]] && { [[ -e "\$f" ]] && cat "\$f" || { echo "no crontab" >&2; exit 1; }; exit 0; }
cp "\$1" "\$f"
EOF
    printf '# empty crontab\n*/5 * * * * docker exec misp-misp-core-1 /var/www/MISP/app/Console/cake Server fetchFeed 1 all\n0 3 * * * /usr/bin/backup.sh\n' > "$W/log/crontab_root"
    # the Intact checkout: the real scripts under test, the real config.yaml
    cp "$REPO/scripts/migrate/risx_to_intact.sh" "$REPO/scripts/migrate/risx_lib.sh" \
       "$REPO/scripts/migrate/transform_config.py" "$W/intact/scripts/migrate/"
    cp "$REPO/config.yaml" "$W/intact/config.yaml"
    # what the install leaves: lib/secrets.sh and the Velociraptor store
    mkdir -p "$W/intact/lib" "$W/intact/modules/velociraptor/secrets"
    # the installer's own password step runs at step 3: its real libraries
    cp "$REPO/lib/secrets.sh" "$REPO/lib/common.sh" "$REPO/lib/config.sh" "$REPO/lib/state_registry.sh" "$W/intact/lib/"
    printf 'VELOX_USER=tenroot\nVELOX_ROLE=administrator\nVELOX_USER_2=api\n' > "$W/intact/modules/velociraptor/.env"
    printf 'VELOX_PASSWORD=GuiStored1Abc\nVELOX_PASSWORD_2=ApiStored2Xyz\n' > "$W/intact/modules/velociraptor/secrets/creds.env"
    # what show-credentials.sh prints, and the token the install left
    cat > "$W/intact/scripts/show-credentials.sh" <<'EOF'
printf 'module | user | password\nvelociraptor | tenroot | PwVelo1\nDashboard setup token | - | TOK-abc123\n'
EOF
    mkdir -p "$W/intact/data/state/backend" && echo TOK-abc123 > "$W/intact/data/state/backend/setup_token"
    cat > "$W/intact/install.sh" <<EOF
echo "install \$* reinit=\${INTACT_REINIT:-} logins_later=\${INTACT_LOGINS_LATER:-}" >> "$W/log/calls"
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
[[ "\$*" == "-n -v" ]] && echo "sudo keep-alive" >> "$W/log/calls"
if [[ "\$1" == -v || "\$1" == -n ]]; then
    [[ -e "$W/log/sudo_refuse" ]] && { echo "sudo: refused" >&2; exit 1; }
    # NOPASSWD rule + sudo group: -n works, -v still wants a password
    [[ "\$1" == -v && -e "$W/log/sudo_v_needs_password" ]] && { echo "sudo: a password is required" >&2; exit 1; }
    [[ "\$1" == -n ]] && shift
    [[ "\$1" == -v || "\$1" == true ]] && exit 0
fi
export FAKE_ROOT=1
exec "\$@"
EOF
    cat > "$W/bin/docker" <<EOF
#!/bin/bash
echo "docker \$*" >> "$W/log/calls"
# user add: the value arrives in the exec's environment (\$_P), never its argv
[[ "\$*" == *"user add"* ]] && echo "\${@: -2:1} \$_P" >> "$W/log/velo_pw"
[[ "\$*" == "exec velociraptor ./velociraptor version" ]] && { cat "$W/log/live_velo_version" 2>/dev/null; exit 0; }
[[ "\$1" == exec ]] && echo '[{"client_id": "C.1234", "host": "endpoint-1"}, {"client_id": "C.5678", "host": "endpoint-2"}]'
[[ "\$1" == ps && "\$*" == *--filter* ]] && echo "Up 2 minutes"
# the inventory and the removal (step 7): the fake risx box in docker.json
case "\$*" in
  "ps -a --format {{.ID}}|"*|inspect*|rm\ *|volume\ *|network\ *|images*|image\ *|compose\ *|system\ df*|builder\ *)
    FAKE_DOCKER_STATE="$W/log/docker.json" FAKE_DOCKER_LOG="$W/log/calls" exec python3 "$W/bin/fake_docker.py" "\$@" ;;
esac
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
    assert_contains "$calls" "compose down $W/risx/setup_platform/workdir/elk" "risx removed, stack by stack"
    assert_not_contains "$calls" "cleanup" "never risx's own cleanup.sh"
    assert_false test -e "$W/risx/setup_platform"
    assert_contains "$calls" "install " "install.sh ran"
    assert_contains "$calls" "adopt --from $W/backup -y --datastore $W/backup/datastore" "adopted with the moved history"
    assert_true grep -qx backup_mode=config "$(_state)"
    assert_not_contains "$calls" "reboot" "no reboot"
    local c i a
    c=$(grep -n 'compose down' "$W/log/calls" | head -1 | cut -d: -f1); i=$(grep -n '^install' "$W/log/calls" | cut -d: -f1)
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
    # stored at step 3; lost afterwards (here: during the install)
    printf 'rm -f %q\n' "$W/intact/modules/velociraptor/secrets/creds.env" >> "$W/intact/install.sh"
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

test_a_lab_box_is_not_warned_about_passwords_the_install_accepts() {
    # QA, 2026-11-18: allow_weak_passwords: true, known passwords in config.yaml,
    # step 3 said "the install refuses" -- and the install then accepted them.
    _world
    printf '#!/bin/bash\nsed -i "0,/password:.*/s//password: changeme/" "$1"\ngrep -q "^allow_weak_passwords:" "$1" && sed -i "s/^allow_weak_passwords:.*/allow_weak_passwords: true/" "$1" || echo "allow_weak_passwords: true" >> "$1"\n' > "$W/bin/ed-lab"
    chmod +x "$W/bin/ed-lab"
    RC=0
    OUT="$(printf '%b' "$NORMAL" | PATH="$W/bin:$PATH" HOME="$W/home" EDITOR=ed-lab VELO_LOGIN_WAIT=1 \
           RISX_ROOT="$W/risx/setup_platform" \
           bash "$W/intact/scripts/migrate/risx_to_intact.sh" --backup-dir "$W/backup" 2>&1)" || RC=$?
    assert_eq "$RC" "0" "$(tail -5 <<<"$OUT")"
    assert_not_contains "$OUT" "publicly known password"
    assert_contains "$OUT" "(allowed: lab mode, allow_weak_passwords: true)"
    # and the bundle shows the switch, while the password itself stays masked
    local x; x="$(mktemp -d)"; tar -xzf "$(ls "$W"/backup/risx_to_intact-*-logs.tar.gz)" -C "$x"
    assert_contains "$(cat "$x/config.yaml")" "allow_weak_passwords: true"
    assert_not_contains "$(cat "$x/config.yaml")" "changeme"
    rm -rf "$x"
}

test_data_mode_moves_the_datastore_instead_of_archiving_it() {
    _world
    _run '2\ny\nr\n'
    assert_eq "$RC" "0" "$(tail -5 <<<"$OUT")"
    assert_true test -f "$W/backup/datastore/clients/C.1234/collections/flow.json"
    assert_false compgen -G "$W/backup/velociraptor-full-*.tar.gz"   # no archive any more
    assert_contains "$OUT" "same disk: instant"
    assert_contains "$(cat "$W/log/calls")" "ds: clients/C.1234/collections/flow.json" "history handed to the adopt step"
    assert_eq "$(stat -c %a "$W/backup/datastore")" "700" "the datastore holds the CA key"
    assert_eq "$(stat -c %U "$W/backup/datastore/clients/C.1234/collections/flow.json")" "$(id -un)" "yours, so scp can read it"
    assert_true grep -qx backup_mode=data "$(_state)"
    # one .tar over ssh, not scp -r (that unpacked every datastore file loose)
    assert_contains "$OUT" "ssh $(id -un)@"
    assert_contains "$OUT" " tar -cf - -C $(dirname "$W/backup") backup > velociraptor_backup.tar"
    assert_contains "$OUT" "cmd /c 'ssh $(id -un)@"
    assert_not_contains "$OUT" "scp -r"
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
    assert_eq "$(grep -c '^ *scp .*config.yaml' <<<"$OUT")" "1" "one command for every shell"
    assert_contains "$OUT" "scp \"$(id -un)@"
    assert_contains "$(cat "$W"/backup/risx_to_intact-*.log)" "sudo mv $W/backup/datastore $W/risx/setup_platform/workdir/velociraptor/velociraptor" "how to put risx back: in the log"
    assert_contains "$OUT" "COPY THE BACKUP TO YOUR LAPTOP NOW"
    assert_contains "$OUT" "Next, risx is removed:"
    assert_eq "$(stat -c %a "$W/backup/server.config.yaml")" "600" "the config copy is a credential"
    assert_false grep -q 'compose down' "$W/log/calls"
}

test_a_rerun_after_stopping_at_the_pause_still_removes_risx() {
    # data mode moved risx's server.config.yaml away with the datastore: a
    # re-run must still find risx, and must still remove it
    _world
    _run '\ny\n'                             # backed up (moved), stopped at the pause
    assert_false test -e "$W/risx/setup_platform/workdir/velociraptor/velociraptor"
    _run 'r\n'
    assert_eq "$RC" "0" "$(tail -5 <<<"$OUT")"
    assert_not_contains "$OUT" "no longer on this box"
    assert_eq "$(grep -cx "compose down $W/risx/setup_platform/workdir/elk" "$W/log/calls")" "1" "risx removed once"
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
    assert_false grep -q 'compose down' "$W/log/calls"
    assert_false grep -q 'docker update' "$W/log/calls"   # risx's Velociraptor is not even stopped
    assert_true test -f "$W/risx/setup_platform/workdir/velociraptor/velociraptor/server.config.yaml"
}

test_disk_space_is_checked_before_anything_changes() {
    _world
    FAKE_FREE_GB=0 _run "$NORMAL"
    assert_ne "$RC" "0"
    assert_contains "$OUT" "not enough space under"
    assert_false grep -q 'compose down' "$W/log/calls"
    _world
    FAKE_FREE_GB=20 _run "$NORMAL"           # under the history + 30 GB: stops
    assert_ne "$RC" "0"
    assert_contains "$OUT" "need at least 30 GB more"
    assert_true test -f "$W/risx/setup_platform/workdir/velociraptor/velociraptor/server.config.yaml"
    _world
    FAKE_FREE_GB=50 _run "$NORMAL"           # under the README's 100 GB: a warning, no question
    assert_eq "$RC" "0" "$(tail -5 <<<"$OUT")"
    assert_contains "$OUT" "Intact wants 100 GB free"
    assert_eq "$(grep -c 'answer:' "$W"/backup/risx_to_intact-*.log)" "3"
}

test_a_configuration_only_backup_from_the_previous_version_still_moves_the_history() {
    # 391e84af's "configuration only" left the datastore in risx. A re-run of
    # such a migration must move it before step 7 deletes it.
    _world
    mkdir -p "$W/backup"
    cp "$W/risx/setup_platform/workdir/velociraptor/velociraptor/server.config.yaml" "$W/backup/"
    printf 'find\nbackup_mode=config\nbackup\nconfig\n' > "$(_state)"
    _run 'r\n'
    assert_eq "$RC" "0" "$(tail -5 <<<"$OUT")"
    assert_contains "$(cat "$W/log/calls")" "ds: clients/C.1234/collections/flow.json"
}

test_everything_risx_owns_is_removed_and_nothing_else() {
    # Read from Docker, not from risx's cleanup.sh (never run any more).
    _world
    _run "$NORMAL"
    assert_eq "$RC" "0" "$(tail -5 <<<"$OUT")"
    # named at the pause, before the r -- nothing asks about it later
    local named press; named="$(grep -n 'Next, risx is removed: 3 stacks, 3 containers, 4 volumes, 3 networks' <<<"$OUT" | head -1 | cut -d: -f1)"
    press="$(grep -n '=== 7. Remove' <<<"$OUT" | cut -d: -f1)"
    assert_true test -n "$named"; assert_true test "$named" -lt "$press"
    assert_contains "$OUT" "5 images (2.5 GB), build cache 1.9GB"
    assert_contains "$OUT" "Kept: 2 loose risx files (moved into the backup), 2 thing(s) not risx's."
    local log; log="$(cat "$W"/backup/risx_to_intact-*.log)"   # the full list
    assert_contains "$log" "3 compose stack(s): elk, misp, timesketch"
    assert_contains "$(cat "$W/log/calls")" "builder prune"
    assert_contains "$log" "container someone-else (Up 3 days)"   # a running container nobody can tie to risx
    assert_contains "$log" "image alpine:latest"
    local st; st="$(cat "$W/log/docker.json")"
    for gone in c-elk c-misp c-oneoff elk_elasticsearch misp_mysql_data main_network elk_default misp_default \
                sha256:img-elk sha256:img-misp sha256:img-misp-old sha256:img-plaso sha256:img-dangling \
                "$(printf 'b%.0s' {1..64})"; do
        assert_not_contains "$st" "\"$gone\""
    done
    assert_contains "$st" '"c-other"'; assert_contains "$st" '"other_data"'; assert_contains "$st" '"sha256:img-other"'
    # each stack by its own compose file, timesketch's one folder deeper too
    assert_contains "$(cat "$W/log/calls")" "compose down $W/risx/setup_platform/workdir/timesketch/timesketch"
    assert_not_contains "$(cat "$W/log/calls")" "cleanup"
    # MISP's cron job gone, the rest of root's crontab kept
    assert_not_contains "$(cat "$W/log/crontab_root")" "docker exec misp"
    assert_not_contains "$(cat "$W/log/crontab_root")" "# empty crontab"
    assert_contains "$(cat "$W/log/crontab_root")" "/usr/bin/backup.sh"
    # folders deleted; loose files moved into the backup, not deleted
    assert_false test -e "$W/risx/setup_platform"
    assert_false test -e "$W/risx/Risx-MSSP"
    assert_true test -f "$W/backup/risx-leftovers/upgrade-scripts.zip"
    assert_true test -f "$W/backup/risx-leftovers/hohit_api.config.yaml"
    assert_contains "$OUT" "risx removed: 3 stack(s), 3 container(s), 4 volume(s), 3 network(s), 5 image(s) (2.5 GB freed)"
    # and the history still reached Intact
    assert_contains "$(cat "$W/log/calls")" "ds: clients/C.1234/collections/flow.json"
}

test_the_removal_shows_its_progress_on_screen() {
    # mssp-demo, 2026-11-18: "details in the log", then ~5 silent minutes
    _world
    _run "$NORMAL"
    assert_eq "$RC" "0" "$(tail -5 <<<"$OUT")"
    assert_not_contains "$OUT" "details in the log"
    assert_contains "$OUT" "removing risx:"
    assert_contains "$OUT" "  stack 1/3 elk: removed"
    assert_contains "$OUT" "  stack 3/3 timesketch: removed"
    # the resources/ templates are the same projects: never downed (mssp-demo:
    # 24 "stacks" for 12, and the Timesketch template's down failed)
    assert_not_contains "$(cat "$W/log/calls")" "compose down $W/risx/setup_platform/resources"
    assert_contains "$OUT" "  containers: 3 removed   volumes: 4   networks: 3"
    assert_contains "$OUT" "  images: 5 removed (2.5 GB)   build cache: cleared"
    assert_contains "$OUT" "  cron lines: 2 removed   folders deleted: setup_platform, Risx-MSSP"
    assert_contains "$OUT" "  2 loose risx files moved into $W/backup/risx-leftovers"
    # Docker's own output stays in the log
    assert_not_contains "$OUT" "== docker compose down"
    assert_contains "$(cat "$W"/backup/risx_to_intact-*.log)" "== docker compose down in $W/risx/setup_platform/workdir/elk"
}

test_what_compose_down_already_removed_is_not_removed_again() {
    # mssp-demo, 2026-11-18: 48 "No such container/network" lines in the log
    _world
    _run "$NORMAL"
    assert_eq "$RC" "0" "$(tail -5 <<<"$OUT")"
    assert_false grep -aqE 'No such|not found' "$W"/backup/risx_to_intact-*.log
    assert_not_contains "$(cat "$W/log/calls")" "docker rm -f -v c-elk"   # its stack's compose down took it
    assert_contains "$(cat "$W/log/calls")" "docker rm -f -v c-oneoff"    # in no stack: removed here
}

test_the_password_step_logs_each_line_once() {
    # mssp-demo, 2026-11-18: its log_* lines reached the log through stdout AND LOG_FILE
    _world
    _run "$NORMAL"
    assert_eq "$RC" "0" "$(tail -5 <<<"$OUT")"
    assert_eq "$(grep -c 'Module passwords stored' "$W"/backup/risx_to_intact-*.log)" "1" "once, not twice"
}

test_a_hebrew_layout_answer_is_read_as_its_latin_key() {
    # mssp-demo, 2026-11-18: the pause read 0xD7 + "r" (Backspace erased half a ר)
    _world
    _run '\nט\n\xd7r\n'
    assert_eq "$RC" "0" "$(tail -5 <<<"$OUT")"
    local log; log="$(ls "$W"/backup/risx_to_intact-*.log)"
    assert_eq "$(grep -ac 'answer:' "$log")" "3" "each accepted the first time"
    assert_true grep -q '^\[[0-9: -]*\] answer: r$' "$log"
    assert_true grep -q '^\[[0-9: -]*\] answer: y$' "$log"     # ט is y
    assert_eq "$(grep -a 'answer:' "$log" | LC_ALL=C tr -d '\40-\176\n' | wc -c)" "0" "answers logged as clean ASCII"
    _world
    _run '\ny\nר\n'
    assert_eq "$RC" "0" "$(tail -5 <<<"$OUT")"
    assert_eq "$(grep -ac 'answer:' "$W"/backup/risx_to_intact-*.log)" "3" "ר is r, accepted the first time"
}

test_sudo_is_asked_once_at_the_start_and_a_refusal_stops_there() {
    _world
    : > "$W/log/sudo_refuse"
    _run "$NORMAL"
    assert_ne "$RC" "0"
    assert_contains "$OUT" "this script needs sudo (it is asked once, here)"
    assert_false grep -qx find "$(_state)"   # nothing started
}

test_passwordless_sudo_is_not_asked_even_if_validating_would_ask() {
    # mssp-demo, 2026-11-18: NOPASSWD for the user, who is also in the sudo
    # group -- `sudo -n true` works, `sudo -v` asks, and the run died at once.
    _world
    : > "$W/log/sudo_v_needs_password"
    _run "$NORMAL"
    assert_eq "$RC" "0" "$(tail -5 <<<"$OUT")"
    assert_not_contains "$OUT" "this script needs sudo"
}

test_sudo_is_kept_fresh_even_when_nothing_was_asked() {
    # mssp-demo, 2026-11-18: `sudo -n true` passed on a password cached from a
    # `sudo rm` just before the run, so no keep-alive started; it ran out during
    # the install and step 9 sat at a prompt for 20 minutes.
    _world
    _run "$NORMAL"
    assert_eq "$RC" "0" "$(tail -5 <<<"$OUT")"
    assert_not_contains "$OUT" "this script needs sudo"
    assert_contains "$(cat "$W/log/calls")" "sudo keep-alive"
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
    assert_false grep -qx adopted "$(_state)"   # the adopt never ran half-way
    assert_not_contains "$(cat "$W/log/calls")" "adopt --from"
    rm -f "$W/log/sudo_refuse"; sed -i '$d' "$W/intact/install.sh"
    _run ''
    assert_eq "$RC" "0" "$(tail -5 <<<"$OUT")"
    assert_contains "$(cat "$W/log/calls")" "adopt --from"
}

test_on_a_terminal_the_run_ends_with_the_logins_and_the_token() {
    command -v script >/dev/null || return 0
    _world
    printf '%b' "$NORMAL" > "$W/answers"
    local out
    out="$(PATH="$W/bin:$PATH" HOME="$W/home" EDITOR=true VELO_LOGIN_WAIT=1 RISX_ROOT="$W/risx/setup_platform" \
           script -q -c "bash $W/intact/scripts/migrate/risx_to_intact.sh --backup-dir $W/backup < $W/answers" /dev/null </dev/null 2>&1 | tr -d '\r')"
    local last2; last2="$(grep -v '^\s*$' <<<"$out" | tail -2)"
    assert_eq "$(head -1 <<<"$last2")" "  Dashboard setup: https://10.9.8.7/setup.html" "$(tail -8 <<<"$out")"
    assert_eq "$(tail -1 <<<"$last2")" "  Setup token:     TOK-abc123"
    assert_contains "$out" "velociraptor | tenroot | PwVelo1"
    assert_eq "$(grep -c 'TOK-abc123' <<<"$out")" "1" "once, in the last line (not the token row of show-credentials)"
    # the password step talks to the terminal directly (a staircase through the
    # log pipe under sudo's raw mode, mssp-demo 2026-11-18), and logs once
    assert_eq "$(grep -c 'Module passwords stored' "$W"/backup/risx_to_intact-*.log)" "1"
    assert_not_contains "$(cat "$W"/backup/risx_to_intact-*.log)" "TOK-abc123" "never in the log"
    assert_not_contains "$(cat "$W"/backup/risx_to_intact-*.log)" "PwVelo1"
    local x; x="$(mktemp -d)"; tar -xzf "$(ls "$W"/backup/risx_to_intact-*-logs.tar.gz)" -C "$x"
    assert_not_contains "$(cat "$x"/*)" "TOK-abc123" "never in the bundle"
    rm -rf "$x"
}

test_without_a_terminal_it_only_says_where_the_logins_are() {
    _world
    _run "$NORMAL"
    assert_eq "$RC" "0" "$(tail -5 <<<"$OUT")"
    assert_contains "$OUT" "Logins and the dashboard setup token: sudo bash $W/intact/scripts/show-credentials.sh"
    assert_not_contains "$OUT" "TOK-abc123"
}

test_the_install_leaves_the_logins_to_the_end_even_when_it_fails() {
    # install.sh used to print them too: twice on screen (mssp-demo, 2026-11-18).
    # Left to this script, they must still show when the install fails.
    _world
    INSTALL_FAIL=1 _run "$NORMAL"
    assert_ne "$RC" "0"
    assert_contains "$(cat "$W/log/calls")" "logins_later=1"
    assert_contains "$OUT" "Logins and the dashboard setup token: sudo bash"
}

test_every_question_is_asked_before_risx_is_touched() {
    _world
    _run "$NORMAL"
    assert_eq "$RC" "0" "$(tail -5 <<<"$OUT")"
    local log; log="$(ls "$W"/backup/risx_to_intact-*.log)"
    # the passwords are stored at step 3, before the backup and the removal
    local pw bk; pw="$(grep -n "the tools' passwords" "$log" | cut -d: -f1)"; bk="$(grep -n '=== 5\. Back up' "$log" | cut -d: -f1)"
    assert_true test -n "$pw"; assert_true test "$pw" -lt "$bk"
    assert_true test -s "$W/intact/modules/elk/secrets/creds.env"   # stored for install.sh to find
    assert_false grep -qE "^\s+password: *[^' ]" "$W/intact/config.yaml"   # config.yaml blanked again
    assert_not_contains "$(cat "$W/log/calls")" "cleanup" "never risx's cleanup.sh, nor --force"
    assert_contains "$(cat "$W/log/calls")" "reinit=1" "install.sh's Re-initialize? is answered for it"
}

test_an_old_velociraptor_is_a_warning_not_a_stop() {
    _world
    sed -i '1i version: {name: velociraptor, version: 0.6.4}' "$W/risx/setup_platform/workdir/velociraptor/velociraptor/server.config.yaml"
    _run "$NORMAL"
    assert_eq "$RC" "0" "$(tail -5 <<<"$OUT")"
    assert_contains "$OUT" "older than the tested 0.6.9"
    assert_eq "$(grep -c 'answer:' "$W"/backup/risx_to_intact-*.log)" "3" "no extra question"
}

test_stop_before_install_leaves_the_box_to_look_at_then_continues() {
    _world
    _run "$NORMAL" --stop-before-install
    assert_eq "$RC" "0" "$(tail -5 <<<"$OUT")"
    assert_contains "$OUT" "stopped before the install (--stop-before-install)"
    assert_true grep -qx removed "$(_state)"
    assert_false grep -q '^install' "$W/log/calls"
    assert_false test -e "$W/risx/setup_platform"
    _run ''                                   # again, without it: the install and the rest
    assert_eq "$RC" "0" "$(tail -5 <<<"$OUT")"
    assert_contains "$(cat "$W/log/calls")" "install "
    assert_true grep -qx verified "$(_state)"
    assert_eq "$(grep -cx "compose down $W/risx/setup_platform/workdir/elk" "$W/log/calls")" "1"
}

test_a_risx_velociraptor_newer_than_intacts_stops_before_anything_changes() {
    _world
    local cfg="$W/risx/setup_platform/workdir/velociraptor/velociraptor/server.config.yaml"
    sed -i '1i version: {name: velociraptor, version: 0.99.1}' "$cfg"
    _run "$NORMAL"
    assert_ne "$RC" "0"
    assert_contains "$OUT" "newer than Intact's"
    assert_true test -f "$cfg"                     # still in place: nothing moved
    _world                                          # 0.77.2 -> 0.77.3, the customer's case: goes on
    sed -i '1i version: {name: velociraptor, version: 0.77.2}' "$W/risx/setup_platform/workdir/velociraptor/velociraptor/server.config.yaml"
    _run "$NORMAL"
    assert_eq "$RC" "0" "$(tail -5 <<<"$OUT")"
    assert_not_contains "$OUT" "newer than Intact's"
}

test_a_recent_client_list_counts_when_the_server_saves_none_at_its_stop() {
    # mssp-demo, 2026-11-18: 0.77.2 stopped cleanly without saving its list;
    # the one it saved 17 s earlier was there, yet the warning said EMPTY.
    local d out; d="$(mktemp -d)"; mkdir -p "$d/bin" "$d/velo/client_info"
    touch -d '-40 seconds' "$d/velo/client_info/snapshot.json"
    printf '#!/bin/bash\ncase "$1" in ps) [[ -e %q ]] || echo velociraptor ;; exec) echo 42; touch %q ;; esac\nexit 0\n' \
        "$d/gone" "$d/gone" > "$d/bin/docker"
    printf '#!/bin/bash\nexec "$@"\n' > "$d/bin/sudo"
    chmod +x "$d/bin/docker" "$d/bin/sudo"
    out="$(PATH="$d/bin:$PATH" bash -c 'source "$1/scripts/migrate/risx_lib.sh"; VELO_DATA="$2/velo"; graceful_stop_legacy_velo' _ "$REPO" "$d" 2>&1)"
    assert_contains "$out" "client list kept (saved by the server"
    assert_not_contains "$out" "EMPTY"
    rm -rf "$d"
}

test_the_version_is_the_running_servers_not_the_configs() {
    # mssp-demo, 2026-11-18: risx upgraded to 0.77.2, its config still said
    # 0.75.5 (written when it was generated), and step 1 showed 0.75.5.
    _world
    sed -i '1i version: {name: velociraptor, version: 0.75.5}' "$W/risx/setup_platform/workdir/velociraptor/velociraptor/server.config.yaml"
    printf 'name: velociraptor\nversion: 0.99.1\ncommit: abc\n' > "$W/log/live_velo_version"
    _run "$NORMAL"
    assert_contains "$OUT" "Velociraptor   : 0.99.1"
    assert_ne "$RC" "0"
    assert_contains "$OUT" "newer than Intact's"
}

test_a_stray_byte_in_the_output_does_not_lose_the_log_from_the_bundle() {
    # redact() read strict UTF-8: one non-UTF-8 byte in the log (a keystroke,
    # odd Docker or install output) crashed it and the bundle lost that log.
    _world
    printf 'printf "install: odd byte \\xff here\\n"\n' >> "$W/intact/install.sh"
    _run "$NORMAL"
    assert_eq "$RC" "0" "$(tail -5 <<<"$OUT")"
    local x; x="$(mktemp -d)"; tar -xzf "$(ls "$W"/backup/risx_to_intact-*-logs.tar.gz)" -C "$x"
    assert_true compgen -G "$x/risx_to_intact-*.log"
    assert_contains "$(cat "$x"/risx_to_intact-*.log)" "odd byte"
    rm -rf "$x"
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

test_clients_are_counted_against_risx_client_list_not_its_folders() {
    # mssp-demo: 12 folders, 4 listed clients; "4 of the 12" read as a loss
    _world
    local velo="$W/risx/setup_platform/workdir/velociraptor/velociraptor"
    mkdir -p "$velo/client_info" "$velo/clients/C.9abc"
    printf '{"client_id":"C.1234"}{"client_id": "C.5678"}{"client_id":"C.1234"}' > "$velo/client_info/snapshot.json"
    VELO_COUNT_WAIT=0 _run "$NORMAL"
    assert_eq "$RC" "0" "$(tail -5 <<<"$OUT")"
    assert_contains "$OUT" "clients known to the new server: 2 of the 2 risx had"
    assert_contains "$OUT" "1 more client folder(s) hold only history"
    assert_not_contains "$OUT" "appear as they reconnect"
}

test_a_rerun_after_risx_is_gone_continues() {
    _world
    INSTALL_FAIL=1 _run "$NORMAL"            # removed, then the install fails
    assert_ne "$RC" "0"
    assert_true grep -qx removed "$(_state)"
    assert_false grep -qx installed "$(_state)"
    _run ''                                   # nothing left to ask
    assert_eq "$RC" "0" "the re-run must finish: $(tail -5 <<<"$OUT")"
    assert_eq "$(grep -cx "compose down $W/risx/setup_platform/workdir/elk" "$W/log/calls")" "1" "risx is not removed twice"
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
    assert_false grep -q 'compose down' "$W/log/calls"   # caught while risx still runs
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
    assert_false test -e "$x/server.config.yaml"   # never the fleet's CA config
    rm -rf "$x"
}

test_help() {
    local out; out="$(bash "$REPO/scripts/migrate/risx_to_intact.sh" --help)"
    assert_contains "$out" "server_urls"
    assert_contains "$out" "SAME machine"
    assert_true grep -q 'not root' "$REPO/scripts/migrate/risx_to_intact.sh"
}

run_all_tests
