#!/bin/bash
# risx_to_intact.sh — guided risx-mssp -> Intact.AI migration, end to end.
#
# The operator runbook (docs/RISX_TO_INTACT_RUNBOOK.md) as one script. It keeps
# the deployed Velociraptor fleet: every client keeps its client_id and nothing
# is touched on an endpoint. Everything else from risx starts fresh in Intact.
#
# Run it from an Intact checkout, as your normal login user (sudo is used where
# needed). Run it — do not pipe it into bash: the prompts read your answers.
#
#   bash scripts/migrate/risx_to_intact.sh [--backup-dir DIR] [--package TAR]
#
# It asks which of three cases you are in:
#   1  same machine       risx is replaced on this box (no rollback once removed)
#   2  new machine, OLD   back up on the risx box, then go to the new box
#   3  new machine, NEW   install Intact here and adopt the backed-up identity
#
# Steps (the ones that ask you are marked ?):
#   find risx ?   back up   copy it off ? (scp lines for PowerShell and bash)
#   remove risx ? (type REMOVE)   config.yaml in nano ?   install.sh
#   adopt the identity ? (scripts/adopt_velociraptor_identity.sh)   verify
#
# Each finished step is recorded in <backup-dir>/.risx_to_intact.<machine>.state
# (one file per machine, so the backup can be copied to the new box with it),
# and a re-run after a failure, a stop or a reboot carries on where it stopped.
#
# Everything it prints, and every answer typed, is logged to
# <backup-dir>/risx_to_intact-<host>-<time>.log (mode 600). On an error it lists
# every log to collect: this one, install.sh's and the adopt script's.
#
# Options:
#   --backup-dir DIR   where the backup lives (default ~/velociraptor_backup)
#   --package TAR      air-gapped: passed to install.sh --package
# Environment: RISX_ROOT (the risx setup_platform dir, if discovery fails),
#              EDITOR (default nano).
#
# THE ONE THING NO SCRIPT CAN FIX: clients dial Client.server_urls verbatim
# (normally https://<old-host>:8000/). The Intact box must answer at that
# address on that port — take over the old box's IP/DNS, or repoint DNS.

set -u
set -o pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
# shellcheck source=risx_lib.sh
source "$HERE/risx_lib.sh"      # say warn die confirm discover_risx graceful_stop_legacy_velo

BACKUP_DIR="${BACKUP_DIR:-$HOME/velociraptor_backup}"
PACKAGE=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --backup-dir) BACKUP_DIR="${2:?--backup-dir needs a directory}"; shift ;;
        --package)    PACKAGE="${2:?--package needs a file}"; shift ;;
        -h|--help)    sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) die "unknown option: $1 (see --help)" ;;
    esac
    shift
done
# Absolute: later steps run from the Intact root.
BACKUP_DIR="$(realpath -m "$BACKUP_DIR")"
[[ -n "$PACKAGE" ]] && PACKAGE="$(realpath -m "$PACKAGE")"
STATE="$BACKUP_DIR/.risx_to_intact.${RISX_MIG_MACHINE:-$(cat /etc/machine-id 2>/dev/null || hostname)}.state"
CFG="$ROOT/config.yaml"

[[ "$(id -u)" -eq 0 ]] && die "run as your normal login user, not root (the script calls sudo itself)"
command -v python3 >/dev/null || die "python3 is required"
[[ -n "$PACKAGE" && ! -e "$PACKAGE" ]] && die "--package $PACKAGE: not found"

# --- log: everything printed goes to the terminal AND the log ----------------
mkdir -p "$BACKUP_DIR" && chmod 700 "$BACKUP_DIR"
LOG="$BACKUP_DIR/risx_to_intact-$(hostname -s 2>/dev/null || hostname)-$(date +%Y%m%d-%H%M%S).log"
( umask 077; : > "$LOG" ) || die "cannot write the log $LOG"
exec > >(tee -a "$LOG") 2>&1
list_logs() {
    echo "  Logs to collect (they may name hosts and accounts; check before sending):"
    echo "    $LOG"
    local f
    for f in "$(ls -t "$ROOT"/install_*.log 2>/dev/null | head -1)" \
             "$(ls -t "$ROOT"/adopt_velo_identity_*.log 2>/dev/null | head -1)"; do
        if [[ -n "$f" ]]; then echo "    $f"; fi
    done
}
on_exit() {
    local rc=$?
    if (( rc != 0 )); then echo; warn "stopped with exit $rc at $(date '+%F %T')"; list_logs; fi
}
trap on_exit EXIT
echo "risx_to_intact.sh: $(date '+%F %T') on $(hostname) as $(id -un); Intact $(git -C "$ROOT" describe --tags --always 2>/dev/null || echo '?') at $ROOT"

# --- small helpers -----------------------------------------------------------

done_step() { grep -qx "$1" "$STATE" 2>/dev/null; }
mark()      { echo "$1" >> "$STATE"; }
# Each step runs once; on a re-run a finished step is skipped with a note.
step() {
    if done_step "$1"; then say "step '$1' already done — skipping"; return 1; fi
    echo; say "=== $2 === ($(date '+%F %T'))"; return 0
}
log_answer() { printf '[%s] answer: %s\n' "$(date +%T)" "$1" >> "$LOG"; }
ask() {  # ask VAR "prompt" — dies on end of input instead of looping forever
    local _a; read -r -p "$2" _a || die "no answer (end of input) — stopped"
    log_answer "$_a"; printf -v "$1" '%s' "$_a"
}
confirm() {  # risx_lib's confirm, plus the answer in the log
    local _a; read -r -p "$1 [y/N] " _a || _a=""
    log_answer "${_a:-<none>}"
    [[ "$_a" == y || "$_a" == Y || "$_a" == yes ]]
}
velo_restart_hint() {
    say "risx's Velociraptor is stopped. To start it again:"
    say "  docker update --restart=unless-stopped velociraptor && docker start velociraptor"
}
risx_present() {
    if [[ -n "${RISX_ROOT:-}" ]]; then
        [[ -f "$RISX_ROOT/workdir/velociraptor/velociraptor/server.config.yaml" ]]
    else
        compgen -G "/home/*/setup_platform/workdir/velociraptor/velociraptor/server.config.yaml" >/dev/null
    fi
}
free_kb() { df -Pk "$1" 2>/dev/null | awk 'NR==2{print $4}'; }

ensure_yaml() {
    python3 -c 'import yaml' 2>/dev/null && return 0
    warn "python3-yaml is missing; it is needed to read the Velociraptor config"
    confirm "Install it now (sudo apt-get install -y python3-yaml)?" || die "python3-yaml is required"
    sudo apt-get install -y python3-yaml >/dev/null || die "could not install python3-yaml"
}

# identity FILE [sudo] -> sets ID_FP ID_URL ID_HOST ID_PORT ID_NONCE (yes/no)
identity() {
    local out
    out=$(${2:+sudo} python3 - "$1" <<'PYEOF'
import hashlib, sys, yaml
from urllib.parse import urlparse
d = yaml.safe_load(open(sys.argv[1])) or {}
key = (d.get('CA') or {}).get('private_key') or ''
urls = (d.get('Client') or {}).get('server_urls') or ['']
u = urlparse(urls[0])
print(hashlib.sha256(key.encode()).hexdigest()[:16] if key else '')
print(urls[0]); print(u.hostname or '')
print(u.port or (443 if u.scheme == 'https' else 80))
print('yes' if (d.get('Client') or {}).get('nonce') else 'no')
PYEOF
) || die "could not read $1"
    { read -r ID_FP; read -r ID_URL; read -r ID_HOST; read -r ID_PORT; read -r ID_NONCE; } <<<"$out"
}

show_identity() {
    echo "    CA fingerprint : ${ID_FP:-<MISSING>}"
    echo "    clients dial   : ${ID_URL:-<MISSING>}"
    echo "    nonce present  : $ID_NONCE"
    [[ -n "$ID_FP" && -n "$ID_HOST" && "$ID_NONCE" == yes ]] \
        || die "this is not a usable Velociraptor server config (fingerprint, address and nonce must all be present)"
}

live_fp() {
    sudo python3 - "$ROOT/data/velociraptor/server.config.yaml" 2>/dev/null <<'PYEOF'
import hashlib, sys, yaml
d = yaml.safe_load(open(sys.argv[1])) or {}
print(hashlib.sha256(((d.get('CA') or {}).get('private_key') or '').encode()).hexdigest()[:16])
PYEOF
}

# Is HOST one of this box's addresses (or a name resolving to one)?
is_here() {
    local ip ips; ips=" $(hostname -I 2>/dev/null) "
    [[ "$ips" == *" $1 "* ]] && return 0
    for ip in $(getent ahostsv4 "$1" 2>/dev/null | awk '{print $1}' | sort -u); do
        [[ "$ips" == *" $ip "* || "$ip" == 127.* ]] && return 0
    done
    return 1
}

# --- steps -------------------------------------------------------------------

choose_mode() {
    MODE="$(sed -n 's/^mode=//p' "$STATE" 2>/dev/null | head -1)"
    if [[ -n "$MODE" ]]; then say "resuming the '$MODE' migration recorded in $STATE"; return; fi
    echo
    echo "  Where are you?"
    echo "    1) same machine      — replace risx on THIS box (no rollback once risx is removed)"
    echo "    2) new machine, OLD  — this is the risx box: back it up, then go to the new box"
    echo "    3) new machine, NEW  — this is the new box: install Intact and adopt the backup"
    local ans; ask ans "  Choose 1, 2 or 3: "
    case "$ans" in 1) MODE=same ;; 2) MODE=old ;; 3) MODE=new ;; *) die "no choice made" ;; esac
    echo "mode=$MODE" >> "$STATE"
}

find_risx() {
    if done_step find; then          # re-run: re-read what later steps need
        discover_risx; identity "$VELO_DATA/server.config.yaml" sudo; return 0
    fi
    step find "1. Find risx-mssp and its Velociraptor identity"
    discover_risx
    echo; sudo ls -la "$VELO_DATA" | head -15
    echo; say "this is the identity your whole fleet is pinned to:"
    identity "$VELO_DATA/server.config.yaml" sudo
    show_identity
    confirm "Is that the Velociraptor directory and identity you want to move?" || die "stopped — nothing was changed"
    mark find
}

backup() {
    step backup "2. Back up the Velociraptor files to $BACKUP_DIR" || return 0
    # A graceful stop flushes the fleet list (client_info/snapshot.json); without
    # it Intact shows an EMPTY client list until each endpoint re-enrols.
    local live_opts=()
    if [[ "$MODE" == same ]]; then
        graceful_stop_legacy_velo
    else
        echo "  Stopping risx's Velociraptor now keeps the fleet list and history"
        echo "  complete, but the clients have no server until the new box takes over."
        if confirm "Stop the risx Velociraptor gracefully before the backup?"; then
            graceful_stop_legacy_velo; velo_restart_hint
        else
            # a live server writes while tar reads; GNU tar then exits 1
            live_opts=(--warning=no-file-changed --ignore-failed-read)
            warn "backing up a running server: history up to now is kept, but the fleet list may be stale"
        fi
    fi
    mkdir -p "$BACKUP_DIR" && chmod 700 "$BACKUP_DIR"
    local need have
    need=$(sudo du -sk --exclude=clients/linux --exclude=clients/mac --exclude=clients/windows "$VELO_DATA" | cut -f1)
    have=$(free_kb "$BACKUP_DIR")
    (( have > need )) || die "not enough free space in $BACKUP_DIR: the datastore is $((need/1024)) MB, $((have/1024)) MB free"
    sudo install -m 600 -o "$(id -un)" -g "$(id -gn)" "$VELO_DATA/server.config.yaml" "$BACKUP_DIR/server.config.yaml" \
        || die "could not copy server.config.yaml"
    sudo install -m 600 -o "$(id -un)" -g "$(id -gn)" "$VELO_DATA/client.config.yaml" "$BACKUP_DIR/client.config.yaml" 2>/dev/null || true
    local fp_src="$ID_FP"
    identity "$BACKUP_DIR/server.config.yaml"
    [[ "$ID_FP" == "$fp_src" ]] || die "the copied server.config.yaml does not match the original"

    # Datastore + filestore (history and the fleet list). The repacked client
    # installers are left out: Intact builds its own, and they are most of the size.
    local tarball rc=0; tarball="$BACKUP_DIR/velociraptor-full-$(date +%Y%m%d-%H%M%S).tar.gz"
    say "archiving the datastore ($((need/1024)) MB; this can take a few minutes)…"
    sudo tar -czf "$tarball" "${live_opts[@]}" -C "$(dirname "$VELO_DATA")" \
        --exclude='velociraptor/clients/linux' --exclude='velociraptor/clients/mac' \
        --exclude='velociraptor/clients/windows' "$(basename "$VELO_DATA")" || rc=$?
    if (( rc == 1 && ${#live_opts[@]} )); then
        warn "some files changed while archiving (the server is running) — kept"
    elif (( rc != 0 )); then
        sudo rm -f "$tarball"; die "the archive failed (tar exit $rc) — nothing else was done"
    fi
    sudo chown "$(id -un):$(id -gn)" "$tarball" && chmod 600 "$tarball"
    tar -tzf "$tarball" "velociraptor/server.config.yaml" >/dev/null 2>&1 \
        || die "the archive is not readable — nothing else was done"
    echo "dskb=$need" >> "$STATE"
    echo; ls -lh "$BACKUP_DIR"
    mark backup
}

copy_out() {
    step copied "3. Copy the backup OFF this machine (just in case)" || return 0
    local ip="$ID_HOST" dst; dst="$(basename "$BACKUP_DIR")"
    is_here "$ip" || ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
    cat <<EOF

  The backup holds the Velociraptor CA private key: treat it as a credential.
  From your laptop:

    PowerShell:
      scp -r "$(id -un)@${ip:-<this-box-ip>}:${BACKUP_DIR}" .
      dir ".\\${dst}"

    bash (Linux/macOS):
      scp -r "$(id -un)@${ip:-<this-box-ip>}:${BACKUP_DIR}" .
      ls -l "./${dst}"

EOF
    local ans
    while true; do
        ask ans "  Copied? [y]es / [s]kip copying / [n]o, stop here: "
        case "$ans" in
            y|Y) say "good — keep that copy until the migration is verified"; break ;;
            s|S) warn "no off-box copy: if this box dies, the fleet's identity dies with it"
                 confirm "Continue WITHOUT an off-box copy?" && break ;;
            n|N) say "stopped. Re-run the script to continue from here."
                 [[ "$MODE" == same ]] && velo_restart_hint
                 exit 0 ;;
        esac
    done
    mark copied
}

remove_risx_box() {
    step removed "4. Remove risx-mssp from this machine" || return 0
    local cleanup="$RISX_ROOT/scripts/cleanup.sh"
    [[ -f "$cleanup" ]] || die "no $cleanup — remove risx by hand, then re-run"
    echo "  About to PERMANENTLY remove risx-mssp with its own cleanup.sh:"
    docker ps -a --format '    container: {{.Names}} ({{.Image}})' | grep -v ' intact_' || true
    echo "    directory: $RISX_ROOT/workdir ($(sudo du -sh "$RISX_ROOT/workdir" 2>/dev/null | cut -f1))"
    echo "  Kept: $BACKUP_DIR"
    [[ -s "$BACKUP_DIR/server.config.yaml" ]] && compgen -G "$BACKUP_DIR/velociraptor-full-*.tar.gz" >/dev/null \
        || die "the backup is incomplete — refusing to remove risx"
    local ans; ask ans "  Type REMOVE to continue: "
    [[ "$ans" == REMOVE ]] || die "stopped (you typed '$ans') — nothing was removed"
    (cd "$RISX_ROOT/scripts" && bash cleanup.sh) || warn "cleanup.sh reported a problem"
    mark removed      # from here risx is gone even if the rest is interrupted
    local left; left="$(docker ps -a --format '{{.Names}}' | grep -v '^intact_' || true)"
    if [[ -n "$left" ]]; then
        warn "still present after cleanup.sh:"; echo "$left" | sed 's/^/    /'
        echo "  cleanup.sh --force removes EVERY container, network and volume on this host,"
        echo "  not only risx's. Right on a dedicated box, a disaster on a shared one."
        if confirm "Run cleanup.sh --force?"; then
            (cd "$RISX_ROOT/scripts" && bash cleanup.sh --force) || warn "cleanup.sh --force reported a problem"
        fi
    fi
    echo "  A reboot now clears the Docker network state risx leaves behind (the runbook's advice)."
    if confirm "Reboot now? Re-run this script after it comes back to continue."; then
        sudo reboot; exit 0
    fi
}

edit_config() {
    step config "5. Configure Intact (config.yaml)" || return 0
    [[ -f "$CFG" ]] || die "$CFG not found — run this from an Intact checkout"
    # Pre-set the values that MUST match what clients dial. Written in place:
    # the backend mounts config.yaml by inode, so never write-and-rename it.
    python3 - "$CFG" "$ID_HOST" "$ID_PORT" <<'PYEOF' || die "could not write $CFG (is it yours to edit?)"
import re, sys
path, host, port = sys.argv[1:]
with open(path, 'r+') as f:
    s = f.read()
    s = re.sub(r'(?m)^domain:.*$', f'domain: {host}', s, count=1)
    s = re.sub(r'(?m)^(\s*agent_port:).*$', rf'\g<1> {port}', s, count=1)
    f.seek(0); f.write(s); f.truncate()
PYEOF
    say "pre-set domain: $ID_HOST (the host every deployed client dials)"
    grep -qE '^\s*agent_port:' "$CFG" && say "pre-set modules.velociraptor.agent_port: $ID_PORT"
    while true; do
        say "opening config.yaml — check the IP/domain, choose modules, set passwords; save and exit"
        # the editor needs the real terminal, not the logging pipe
        if { : >/dev/tty; } 2>/dev/null; then ${EDITOR:-nano} "$CFG" </dev/tty >/dev/tty 2>&1
        else ${EDITOR:-nano} "$CFG"; fi
        local summary
        summary="$(python3 - "$CFG" <<'PYEOF'
import sys, yaml
c = yaml.safe_load(open(sys.argv[1])) or {}
m = c.get('modules') or {}
on = sorted(k for k, v in m.items() if isinstance(v, dict) and v.get('enabled', True))
weak = sorted(k for k, v in m.items() if isinstance(v, dict) and str(v.get('password', '')) == '123123'
              and v.get('enabled', True))
velo = m.get('velociraptor') or {}
print(c.get('domain', '')); print(velo.get('agent_port', 8000))
print('yes' if velo.get('enabled', True) else 'no'); print(', '.join(on)); print(', '.join(weak))
PYEOF
)" || { warn "config.yaml does not parse as YAML — fix it"; continue; }
        local domain port velo_on mods weak
        { read -r domain; read -r port; read -r velo_on; read -r mods; read -r weak; } <<<"$summary"
        echo
        echo "  ------- config summary -------"
        echo "  domain             : $domain"
        echo "  Velociraptor port  : $port"
        echo "  enabled modules    : ${mods:-none}"
        echo "  default passwords  : ${weak:-none}"
        echo "  ------------------------------"
        local bad=0
        [[ "$velo_on" == yes ]] || { warn "Velociraptor is DISABLED — the migration needs it"; bad=1; }
        [[ "$domain" == "$ID_HOST" ]] || warn "domain $domain is NOT what the clients dial ($ID_HOST): every deployed client would be stranded"
        [[ "$port" == "$ID_PORT" ]] || warn "Velociraptor port $port is NOT the port the clients dial ($ID_PORT)"
        [[ -n "$weak" ]] && warn "these modules still use the default password 123123: $weak"
        local ans; ask ans "  Install with this config? [y]es / [e]dit again / [n]o, stop: "
        case "$ans" in
            y|Y) (( bad )) && { warn "fix the problem above first"; continue; }
                 if [[ "$domain" != "$ID_HOST" || "$port" != "$ID_PORT" ]]; then
                     confirm "Are you SURE? Clients will only arrive if you repoint DNS/IP to $domain:$port yourself." || continue
                 fi
                 break ;;
            n|N) say "stopped. Re-run the script to continue from here."; exit 0 ;;
            *)   ;;
        esac
    done
    mark config
}

install_intact() {
    step installed "6. Install Intact.AI" || return 0
    if docker ps --format '{{.Names}}' 2>/dev/null | grep -qx intact_velociraptor \
            && ! confirm "Intact is already running on this box. Re-run install.sh anyway?"; then
        say "keeping the running install"; mark installed; return 0
    fi
    say "running install.sh${PACKAGE:+ --package $PACKAGE} (this takes a while; it downloads ~6 GB online)"
    (cd "$ROOT" && sudo bash install.sh ${PACKAGE:+--package "$PACKAGE"}) \
        || die "install.sh failed — fix the cause and re-run this script; it continues from the install"
    mark installed
}

adopt() {
    step adopted "7. Adopt the Velociraptor identity" || return 0
    local cur; cur="$(live_fp)"
    echo "  incoming CA (the fleet's) : $ID_FP"
    echo "  CA on this box now        : ${cur:-<none>}"
    echo "  clients dial              : $ID_URL"
    if ! is_here "$ID_HOST"; then
        warn "THIS BOX DOES NOT ANSWER AT $ID_HOST YET (its addresses: $(hostname -I 2>/dev/null))."
        warn "  Clients only arrive once that address is moved here (IP or DNS)."
    fi
    local tarball extract="" ds=() ans
    tarball="$(ls -t "$BACKUP_DIR"/velociraptor-full-*.tar.gz 2>/dev/null | head -1)"
    if [[ -n "$tarball" ]]; then
        echo "  Bring the old history (hunts, flows, results and the fleet list) across?"
        echo "  Clients reconnect either way; without it Intact starts with an empty history."
        ask ans "  Bring the history? [Y/n] "
        if [[ ! "$ans" =~ ^[Nn] ]]; then
            # Unpacked here, then copied into the datastore volume: about 2x its size.
            local dskb; dskb="$(sed -n 's/^dskb=//p' "$STATE" | tail -1)"
            dskb="${dskb:-$(( $(stat -c %s "$tarball") * 3 / 1024 ))}"
            if (( $(free_kb "$BACKUP_DIR") < dskb * 2 )); then
                warn "about $((dskb*2/1024)) MB is needed to bring the history; $(( $(free_kb "$BACKUP_DIR")/1024 )) MB is free"
                confirm "Continue WITHOUT the history?" || die "stopped — free some space and re-run"
            else
                extract="$BACKUP_DIR/.datastore-extract"
                say "unpacking $tarball…"
                sudo rm -rf "$extract"; mkdir -p "$extract"
                sudo tar -xzf "$tarball" -C "$extract" || die "could not unpack $tarball"
                ds=(--datastore "$extract/velociraptor")
            fi
        fi
    else
        warn "no datastore archive in $BACKUP_DIR: only the identity moves, history starts empty"
    fi
    if ! confirm "Adopt the fleet's identity $ID_FP on this box now?"; then
        [[ -n "$extract" ]] && sudo rm -rf "$extract"
        die "stopped — nothing was changed"
    fi
    # -y: we asked above, and the address check is ours (the adopt script would
    # refuse whenever domain differs from what clients dial, even when the
    # operator is repointing DNS separately and confirmed that in step 5).
    local rc=0
    (cd "$ROOT" && sudo bash scripts/adopt_velociraptor_identity.sh --from "$BACKUP_DIR" -y "${ds[@]}") || rc=$?
    [[ -n "$extract" ]] && sudo rm -rf "$extract"
    (( rc == 0 )) || die "the adopt step failed (exit $rc) — see adopt_velo_identity_*.log in $ROOT; re-run to retry"
    [[ "$(live_fp)" == "$ID_FP" ]] \
        || die "the adopt step finished but this box does not run $ID_FP — re-run to retry"
    mark adopted
}

verify() {
    step verified "8. Verify" || return 0
    local live; live="$(live_fp)"
    [[ "$live" == "$ID_FP" ]] \
        || die "CA in use is '${live:-unreadable}', the backup's is $ID_FP — the adoption did not take"
    say "CA in use matches the backup: $live"
    if ! docker ps --filter 'name=^intact_velociraptor$' --format '{{.Status}}' 2>/dev/null | grep -q '^Up'; then
        die "intact_velociraptor is not running. Start it, then re-run:
    (cd $ROOT && sudo docker compose -f modules/velociraptor/docker-compose.yaml up -d --no-build --pull never)"
    fi
    say "intact_velociraptor is up"
    say "clients known to the new server (a large fleet trickles in over minutes to hours):"
    docker exec intact_velociraptor ./velociraptor --config /velociraptor/server.config.yaml \
        query "SELECT client_id, os_info.hostname AS host, last_seen_at FROM clients() LIMIT 20" 2>/dev/null \
        || warn "could not query the clients yet — try again in a minute"
    mark verified
    if confirm "Shred the working copy of server.config.yaml in $BACKUP_DIR? (the archive is kept)"; then
        shred -u "$BACKUP_DIR/server.config.yaml" "$BACKUP_DIR/client.config.yaml" 2>/dev/null || true
    fi
    cat <<EOF

  Done. Next:
    - open https://${ID_HOST}/ and finish the first-login setup
    - check that a collection reaches one returning client
    - keep $(ls -t "$BACKUP_DIR"/velociraptor-full-*.tar.gz 2>/dev/null | head -1) safe until the
      customer is satisfied (it still contains the CA)
EOF
    if [[ "$MODE" == new ]]; then echo "    - leave the old risx box powered off, NOT wiped, for a week"; fi
    echo; list_logs
}

new_box_backup() {
    if risx_present && ! done_step find; then
        warn "risx-mssp is installed on THIS box. Option 3 is for a NEW machine;"
        warn "  to replace risx here, delete $STATE and choose 1."
        confirm "Continue as the new box anyway?" || die "stopped"
    fi
    # On the new box the backup has to arrive from the old one first.
    while [[ ! -s "$BACKUP_DIR/server.config.yaml" ]]; do
        cat <<EOF

  No backup at $BACKUP_DIR yet. Copy the backup folder here from the old box, e.g. on THIS box:
      scp -r "<user>@<old-box-ip>:<backup folder on the old box>" "$BACKUP_DIR"
  or from your laptop (PowerShell or bash):
      scp -r "./$(basename "$BACKUP_DIR")" "$(id -un)@$(hostname -I 2>/dev/null | awk '{print $1}'):$(dirname "$BACKUP_DIR")/"
EOF
        confirm "Copied it? (check again)" || { say "stopped. Re-run the script once the backup is here."; exit 0; }
    done
    chmod 700 "$BACKUP_DIR"; chmod 600 "$BACKUP_DIR"/server.config.yaml
    identity "$BACKUP_DIR/server.config.yaml"
    say "backup found — the identity it carries:"; show_identity
    done_step find || { confirm "Is this the identity your fleet is pinned to?" || die "stopped"; mark find; }
}

# --- main --------------------------------------------------------------------

ensure_yaml
choose_mode
if done_step verified; then say "this migration is already complete (see $STATE)"; exit 0; fi
if [[ "$MODE" != new ]]; then
    docker ps >/dev/null 2>&1 || die "this user cannot run docker — add it to the docker group and log in again"
fi
case "$MODE" in
    same)
        # risx already removed (finished, or cut off mid-removal): work from the backup.
        if done_step backup && ! risx_present && ! done_step removed; then
            warn "risx-mssp is no longer on this box — continuing from the backup"; mark removed
        fi
        done_step removed || { find_risx; backup; copy_out; remove_risx_box; }
        identity "$BACKUP_DIR/server.config.yaml"
        edit_config; install_intact; adopt; verify ;;
    old)
        find_risx; backup; copy_out
        cat <<EOF

  The old box is backed up. Next, on the NEW box:
    1. clone Intact and copy $(basename "$BACKUP_DIR") into the home folder there
    2. run:  bash scripts/migrate/risx_to_intact.sh   and choose 3
  Leave this box running until the new one is up, then move its IP/DNS over.
EOF
        echo; list_logs
        ;;
    new)
        new_box_backup; edit_config; install_intact; adopt; verify ;;
esac
