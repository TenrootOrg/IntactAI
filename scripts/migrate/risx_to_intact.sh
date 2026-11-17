#!/bin/bash
# risx_to_intact.sh — replace risx-mssp with Intact.AI on the SAME machine.
#
# The deployed Velociraptor fleet is kept: every client keeps its client_id and
# nothing is touched on an endpoint. Everything else from risx starts fresh.
# (Moving to ANOTHER machine is a manual procedure: docs/RISX_TO_INTACT_RUNBOOK.md.)
#
# Run it as your normal login user (sudo is used where needed), from anywhere:
#
#   bash risx_to_intact.sh [--backup config|data] [--backup-dir DIR] [--package TAR]
#
# Outside an Intact checkout it clones the latest Intact release into ~/intact
# (or $INTACT_DIR) and carries on from there. Run it; do not pipe it into bash.
#
# Intact always gets BOTH the configuration (the fleet's identity) and the data
# (hunts, collections, client list). Every question and check comes first,
# while risx still runs; after the pause it runs to the end by itself:
#   1 find risx and show the fleet's identity
#   2 what goes into the backup you copy off the box: 1 config / 2 config + data
#   3 config.yaml in nano, then: y = use it / e = edit again          <- you
#   4 check everything the rest needs (the checkout, docker, disk space)
#   5 back up (graceful stop, server.config.yaml; the datastore is MOVED next
#     to it — instant on the same disk, no archive)
#   6 PAUSE: one scp line to copy the backup off; press r to continue  <- you
#   7 remove risx (its own cleanup.sh)
#   8 install.sh   9 adopt the identity, with the old history   10 verify
# Other questions appear only when something is wrong (the address clients dial
# does not match, containers are left after the cleanup, ...).
#
# Each finished step is recorded in <backup-dir>/.risx_to_intact.<machine>.state,
# so a re-run after a failure or Ctrl+C carries on where it stopped. Everything
# printed, and every answer, is logged to <backup-dir>/risx_to_intact-*.log
# (mode 600); on an error it lists every log to collect.
#
# Options:
#   --backup MODE      what the backup you copy off the box holds (Intact gets
#                      both either way): config = the configuration files only
#                      (KB, seconds to copy); data = also the datastore (large).
#                      Asked at step 2 when not given.
#   --backup-dir DIR   where the backup lives (default ~/velociraptor_backup)
#   --package TAR      air-gapped: passed to install.sh --package
# Environment: RISX_ROOT (the risx setup_platform dir, if discovery fails),
#              INTACT_DIR (where to clone Intact, default ~/intact), EDITOR.
#
# THE ONE THING NO SCRIPT CAN FIX: clients dial Client.server_urls verbatim
# (normally https://<this-host>:8000/). This box keeps answering there because
# it is the same machine — keep its IP/DNS name.

set -u
set -o pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." 2>/dev/null && pwd)"

# --- run from anywhere: find or fetch an Intact checkout, then run from it ---
if [[ ! -f "$ROOT/install.sh" || ! -f "$HERE/risx_lib.sh" ]]; then
    INTACT_DIR="${INTACT_DIR:-$HOME/intact}"
    if [[ ! -f "$INTACT_DIR/scripts/migrate/risx_to_intact.sh" ]]; then
        command -v git >/dev/null || { echo "git is required to fetch Intact" >&2; exit 1; }
        tag="${INTACT_RELEASE_TAG:-}"
        if [[ -z "$tag" ]]; then
            tag="$(curl -fsSL ${GITHUB_TOKEN:+-H "Authorization: token $GITHUB_TOKEN"} \
                   https://api.github.com/repos/TenrootOrg/IntactAI/releases/latest 2>/dev/null \
                   | python3 -c 'import json,sys; print(json.load(sys.stdin)["tag_name"])' 2>/dev/null)"
        fi
        [[ -n "$tag" ]] || { echo "Could not find the latest Intact release; set INTACT_RELEASE_TAG=<tag>" >&2; exit 1; }
        echo "Fetching Intact $tag into $INTACT_DIR ..."
        git clone --quiet --branch "$tag" "${INTACT_GIT_URL:-https://github.com/TenrootOrg/IntactAI.git}" "$INTACT_DIR" \
            || { echo "git clone failed" >&2; exit 1; }
        [[ -f "$INTACT_DIR/scripts/migrate/risx_to_intact.sh" ]] \
            || { echo "Intact $tag has no scripts/migrate/risx_to_intact.sh" >&2; exit 1; }
    fi
    exec bash "$INTACT_DIR/scripts/migrate/risx_to_intact.sh" "$@"
fi

# shellcheck source=risx_lib.sh
source "$HERE/risx_lib.sh"      # say warn die discover_risx graceful_stop_legacy_velo
# shellcheck source=../../lib/secrets.sh
source "$ROOT/lib/secrets.sh" || die "cannot load $ROOT/lib/secrets.sh"   # INTACT_KNOWN_DEFAULT_PASSWORDS

BACKUP_DIR="${BACKUP_DIR:-$HOME/velociraptor_backup}"
PACKAGE=""
BACKUP_MODE=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --backup-dir) BACKUP_DIR="${2:?--backup-dir needs a directory}"; shift ;;
        --package)    PACKAGE="${2:?--package needs a file}"; shift ;;
        --backup)     BACKUP_MODE="${2:?--backup needs config or data}"; shift
                      [[ "$BACKUP_MODE" == config || "$BACKUP_MODE" == data ]] \
                          || die "--backup must be config or data, not '$BACKUP_MODE'" ;;
        -h|--help)    sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) die "unknown option: $1 (see --help)" ;;
    esac
    shift
done
# Absolute: later steps run from the Intact root.
BACKUP_DIR="$(realpath -m "$BACKUP_DIR")"
[[ -n "$PACKAGE" ]] && PACKAGE="$(realpath -m "$PACKAGE")"
STATE="$BACKUP_DIR/.risx_to_intact.${RISX_MIG_MACHINE:-$(cat /etc/machine-id 2>/dev/null || hostname)}.state"
CFG="$ROOT/config.yaml"
# risx's datastore directory, moved here at step 5 (see move_datastore)
DS="$BACKUP_DIR/datastore"

[[ "$(id -u)" -eq 0 ]] && die "run as your normal login user, not root (the script calls sudo itself)"
command -v python3 >/dev/null || die "python3 is required"
[[ -n "$PACKAGE" && ! -e "$PACKAGE" ]] && die "--package $PACKAGE: not found"

# --- log: everything printed goes to the terminal AND the log ----------------
mkdir -p "$BACKUP_DIR" && chmod 700 "$BACKUP_DIR"
( umask 077; : >> "$STATE" ) || die "cannot write $STATE"
LOG="$BACKUP_DIR/risx_to_intact-$(hostname -s 2>/dev/null || hostname)-$(date +%Y%m%d-%H%M%S).log"
( umask 077; : > "$LOG" ) || die "cannot write the log $LOG"
exec > >(tee -a "$LOG") 2>&1

# Masks what looks like a credential: KEY=value / key: value pairs named like a
# password, token, secret or key, and whole PEM blocks. A safety net for the
# bundle -- the log itself is written to hold none.
redact() {
    python3 -c '
import re, sys
t = sys.stdin.read()
t = re.sub(r"-----BEGIN [A-Z ]+-----[\s\S]*?-----END [A-Z ]+-----", "[REDACTED PEM]", t)
t = re.sub(r"(?im)^(\s*[\w.-]*(?:password|passwd|token|secret|api_?key|private_key|nonce)[\w.-]*\s*[:=]\s*)\S.*$",
           lambda m: m.group(1) + "[REDACTED]", t)
sys.stdout.write(t)'
}

# What the box looked like: enough to diagnose a run from another machine.
box_report() {
    echo "== $(date '+%F %T') on $(hostname) as $(id -un)"
    uname -a; grep -h PRETTY_NAME /etc/os-release 2>/dev/null
    echo "Intact: $(git -C "$ROOT" describe --tags --always 2>/dev/null || cat "$ROOT/VERSION" 2>/dev/null || echo '?') at $ROOT"
    echo "risx_to_intact.sh sha256: $(sha256sum "$0" | cut -c1-16)"
    echo; echo "== docker"; docker version --format 'engine {{.Server.Version}}, client {{.Client.Version}}' 2>&1
    docker compose version 2>&1; echo "root: $(docker info -f '{{.DockerRootDir}}' 2>&1)"
    echo; echo "== disk and memory"; df -h / "$BACKUP_DIR" "$(docker info -f '{{.DockerRootDir}}' 2>/dev/null || echo /)" 2>&1 | uniq; free -m 2>&1
    echo; echo "== containers"; docker ps -a --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}' 2>&1
    echo; echo "== migration state ($STATE)"; cat "$STATE" 2>/dev/null
    echo; echo "== risx (${RISX_ROOT:-$(state_val risx_root)})"
    ls -la "${RISX_ROOT:-$(state_val risx_root)}/workdir" 2>&1 | head -30
    echo; echo "== backup folder"; ls -la "$BACKUP_DIR" 2>&1
    if sudo -n true 2>/dev/null; then
        local d; for d in "$DS" "${VELO_DATA:-}"; do
            [[ -n "$d" ]] && sudo test -d "$d" || continue
            echo "$d: $(sudo du -sh "$d" 2>/dev/null | cut -f1), clients: $(sudo find "$d/clients" -maxdepth 1 -name 'C.*' 2>/dev/null | wc -l)," \
                 "snapshot: $(sudo stat -c %y "$d/client_info/snapshot.json" 2>/dev/null || echo none)"
        done
    fi
    local c; for c in velociraptor intact_velociraptor; do
        docker ps -a --format '{{.Names}}' 2>/dev/null | grep -qx "$c" || continue
        echo; echo "== docker logs --tail 200 $c"; docker logs --tail 200 "$c" 2>&1
    done
}

# One file to send back, made at every exit: this run's log, the install and
# adopt logs, the progress state, box_report and config.yaml -- all through
# redact(). Never server.config.yaml or the datastore (the fleet's CA key).
bundle_logs() {
    local tmp out f
    tmp="$(mktemp -d)" || return 1
    out="${LOG%.log}-logs.tar.gz"
    sleep 0.5        # shortcut: lets tee flush the last lines; a lost line or two at worst
    for f in "$LOG" "$(ls -t "$ROOT"/install_*.log 2>/dev/null | head -1)" \
             "$(ls -t "$ROOT"/adopt_velo_identity_*.log 2>/dev/null | head -1)"; do
        [[ -n "$f" && -r "$f" ]] && redact < "$f" > "$tmp/$(basename "$f")"
    done
    box_report 2>&1 | redact > "$tmp/box.txt"
    redact < "$CFG" > "$tmp/config.yaml" 2>/dev/null
    ( umask 077; tar -czf "$out" -C "$tmp" . ) && rm -rf "$tmp" || { rm -rf "$tmp"; return 1; }
    local ip; ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
    echo "  Everything to send back is in one file (passwords and keys masked):"
    echo "    $out"
    echo "  To copy it to your laptop (PowerShell or a Linux/macOS shell):"
    echo "    scp \"$(id -un)@${ip:-<this-box-ip>}:$out\" ."
}
on_exit() {
    local rc=$?
    # plain, not a second WARN: the ERROR above already said what went wrong
    if (( rc != 0 )); then echo "  stopped at $(date '+%F %T') (exit $rc)"; fi
    echo; bundle_logs || echo "  (could not pack the logs; send $LOG)"
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
confirm() {  # y/N, with the answer in the log
    local _a; read -r -p "$1 [y/N] " _a || _a=""
    log_answer "${_a:-<none>}"
    [[ "$_a" == y || "$_a" == Y || "$_a" == yes ]]
}
risx_present() {
    local base="${RISX_ROOT:-/home/*/setup_platform}"
    compgen -G "$base/workdir/velociraptor/velociraptor/server.config.yaml" >/dev/null && return 0
    # step 5 moved the datastore out; the rest of risx stays
    # until its cleanup.sh empties workdir/
    [[ -d "$DS" ]] && compgen -G "$base/workdir/velociraptor" >/dev/null
}
state_val() { sed -n "s/^$1=//p" "$STATE" 2>/dev/null | tail -1; }
# config | data: what the off-box copy holds. A state written before the choice
# existed: data when the backup holds any history (a moved datastore or an old archive).
backup_mode() {
    local m; m="$(state_val backup_mode)"
    if [[ -z "$m" ]]; then
        if [[ -d "$DS" ]] || compgen -G "$BACKUP_DIR/velociraptor-full-*.tar.gz" >/dev/null; then m=data; else m=config; fi
    fi
    echo "$m"
}
free_kb() { df -Pk "$1" 2>/dev/null | awk 'NR==2{print $4}'; }
# The history's size: risx keeps its client installers under clients/<os>,
# which are not history and do not come across (a test box: 317 MB in all, 75 MB of history).
ds_kb() { sudo du -sk --exclude=clients/linux --exclude=clients/mac --exclude=clients/windows "$1" 2>/dev/null | cut -f1; }

ensure_yaml() {
    python3 -c 'import yaml' 2>/dev/null && return 0
    warn "python3-yaml is missing; it is needed to read the Velociraptor config"
    confirm "Install it now (sudo apt-get install -y python3-yaml)?" || die "python3-yaml is required"
    sudo apt-get install -y python3-yaml >/dev/null || die "could not install python3-yaml"
}

# identity FILE [sudo] -> sets ID_FP ID_URL ID_HOST ID_PORT ID_NONCE (yes/no) ID_VER
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
print((d.get('version') or {}).get('version') or '')
PYEOF
) || die "could not read $1"
    { read -r ID_FP; read -r ID_URL; read -r ID_HOST; read -r ID_PORT; read -r ID_NONCE; read -r ID_VER; } <<<"$out"
}

show_identity() {
    echo "    CA fingerprint : ${ID_FP:-<MISSING>}"
    echo "    clients dial   : ${ID_URL:-<MISSING>}"
    echo "    nonce present  : $ID_NONCE"
    echo "    Velociraptor   : ${ID_VER:-unknown}"
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

# --- steps -------------------------------------------------------------------

find_risx() {
    if done_step find; then          # re-run: re-read what later steps need
        # From the state, not discover_risx: in data mode the datastore (and
        # risx's server.config.yaml with it) has already moved to the backup.
        RISX_ROOT="${RISX_ROOT:-$(state_val risx_root)}"
        if [[ -n "$RISX_ROOT" ]]; then VELO_DIR="$RISX_ROOT/workdir/velociraptor"; VELO_DATA="$VELO_DIR/velociraptor"
        else discover_risx; fi
        if done_step backup; then identity "$BACKUP_DIR/server.config.yaml"
        else identity "$VELO_DATA/server.config.yaml" sudo; fi
        return 0
    fi
    step find "1. Find risx-mssp and its Velociraptor identity"
    discover_risx
    echo "risx_root=$RISX_ROOT" >> "$STATE"
    say "this is the identity your whole fleet is pinned to (write the fingerprint down):"
    identity "$VELO_DATA/server.config.yaml" sudo
    show_identity
    mark find
}

choose_mode() {
    MODE="${BACKUP_MODE:-$(state_val backup_mode)}"
    [[ -z "$MODE" ]] && { echo; say "=== 2. Choose what the backup holds === ($(date '+%F %T'))"; }
    while [[ -z "$MODE" ]]; do
        cat <<EOF

  Intact gets the configuration AND the data (hunts, collections, client
  list) either way. What should the backup you copy off this box hold?
    1  configuration only — the fleet's identity, a few KB: the copy takes seconds
    2  configuration + data — also the datastore: as big as risx's history
EOF
        local ans; ask ans "  1 or 2 [1]: "
        case "${ans:-1}" in 1) MODE=config ;; 2) MODE=data ;; *) warn "type 1 or 2" ;; esac
    done
    [[ "$(state_val backup_mode)" == "$MODE" ]] || echo "backup_mode=$MODE" >> "$STATE"
    say "backup to copy off the box: $([[ $MODE == data ]] && echo 'configuration + data' || echo 'configuration only')"
}

# risx's cleanup.sh empties workdir/, so the datastore has to leave it first
# (always: Intact gets the history whatever the backup choice).
# A rename, not tar.gz + unzip: risx is removed next anyway, and on the same
# disk it is instant and needs no space. Another disk makes mv a plain copy.
move_datastore() {
    if [[ -d "$DS" ]]; then say "the datastore is already in $DS"; return 0; fi
    local need; need=$(ds_kb "$VELO_DATA")
    if [[ "$(stat -c %d "$VELO_DATA")" == "$(stat -c %d "$BACKUP_DIR")" ]]; then
        say "moving the datastore ($((need/1024)) MB) to $DS — same disk, instant"
    else
        (( $(free_kb "$BACKUP_DIR") > need )) \
            || die "not enough free space in $BACKUP_DIR: the datastore is $((need/1024)) MB, $(( $(free_kb "$BACKUP_DIR")/1024 )) MB free"
        say "moving the datastore ($((need/1024)) MB) to $DS — another disk, so this is a copy"
    fi
    sudo mv "$VELO_DATA" "$DS" || die "could not move $VELO_DATA to $DS"
    sudo chmod 700 "$DS"
    # Only when it is copied off: yours, so the scp in step 6 can read it. One
    # chown per file, so skipped when nobody needs it (the adopt reads it as root).
    if [[ "$(backup_mode)" == data ]]; then sudo chown -R "$(id -un):$(id -gn)" "$DS"; fi
    echo "dskb=$need" >> "$STATE"
}

backup() {
    step backup "5. Back up to $BACKUP_DIR" || return 0
    # A graceful stop flushes the fleet list (client_info/snapshot.json); without
    # it Intact shows an EMPTY client list until each endpoint re-enrols.
    graceful_stop_legacy_velo
    mkdir -p "$BACKUP_DIR" && chmod 700 "$BACKUP_DIR"
    sudo install -m 600 -o "$(id -un)" -g "$(id -gn)" "$VELO_DATA/server.config.yaml" "$BACKUP_DIR/server.config.yaml" \
        || die "could not copy server.config.yaml"
    sudo install -m 600 -o "$(id -un)" -g "$(id -gn)" "$VELO_DATA/client.config.yaml" "$BACKUP_DIR/client.config.yaml" 2>/dev/null || true
    local fp_src="$ID_FP"
    identity "$BACKUP_DIR/server.config.yaml"
    [[ "$ID_FP" == "$fp_src" ]] || die "the copied server.config.yaml does not match the original"
    move_datastore
    echo; ls -lh "$BACKUP_DIR"
    mark backup
}

pause_for_copy() {
    step copied "6. Copy the backup off this machine (optional), then continue" || return 0
    local ip; ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
    local src; src="$(id -un)@${ip:-<this-box-ip>}:${BACKUP_DIR}"
    local what line
    if [[ "$(backup_mode)" == data ]]; then
        what="configuration + data"; line="scp -r \"${src}\" ."
    else
        # the two config files only: the datastore next to them is root's and large
        what="configuration only"; line="scp \"${src}/*.config.yaml\" ."
    fi
    cat <<EOF

  The backup (${what}) is ready in ${BACKUP_DIR}; it holds the fleet's CA key: a credential.
  To keep a copy off this box, run on your laptop (PowerShell or a Linux/macOS shell):

    ${line}

  NEXT: risx-mssp is REMOVED from this box.
  (Ctrl+C stops here; risx's Velociraptor is stopped — to start it again:
EOF
    echo "   sudo mv ${DS} ${VELO_DATA}"
    cat <<EOF
   docker update --restart=unless-stopped velociraptor && docker start velociraptor)

EOF
    local ans
    while true; do
        ask ans "  Press r to continue: "
        [[ "$ans" == r || "$ans" == R ]] && break
    done
    mark copied
}

remove_risx_box() {
    step removed "7. Remove risx-mssp from this machine" || return 0
    local cleanup="$RISX_ROOT/scripts/cleanup.sh"
    [[ -f "$cleanup" ]] || die "no $cleanup — remove risx by hand, then re-run"
    [[ -s "$BACKUP_DIR/server.config.yaml" ]] || die "the backup is incomplete — refusing to remove risx"
    # A backup made by an older version of this script ("configuration only")
    # left the datastore in risx: move it now, before cleanup.sh deletes it.
    [[ -d "$DS" ]] || move_datastore
    [[ -d "$DS" ]] || die "the datastore is not in $DS — refusing to remove risx"
    # Its ~40 lines (a bare path after every app) go to the log; the screen gets
    # the list of what it removed. `username` set and stdin closed: cleanup.sh
    # asks for one (read -p) when risx's .env has none, and must never wait
    # unseen. risx builds its paths from /home/$username/setup_platform.
    say "running risx's own cleanup.sh (its output goes to the log)"
    local out rc=0
    out="$(cd "$RISX_ROOT/scripts" && username="$(basename "$(dirname "$RISX_ROOT")")" bash cleanup.sh </dev/null 2>&1)" || rc=$?
    printf '%s\n' "$out" >> "$LOG"
    local gone; gone="$(sed -n 's/^Deleting the \(.*\) app files.*/\1/p' <<<"$out" | grep -vx '.env' | paste -sd, - | sed 's/,/, /g')"
    say "removed: ${gone:-nothing listed}"
    if (( rc != 0 )); then
        warn "cleanup.sh stopped with exit $rc; its last lines:"; tail -8 <<<"$out" | sed 's/^/    /'
    fi
    mark removed      # from here risx is gone even if the rest is interrupted
    # cleanup.sh only takes down the apps in its APPS_TO_INSTALL: QA's box kept
    # MISP (installed, not listed), elk-setup and a few one-off `docker run`s.
    local left; left="$(docker ps -a --format '{{.Names}}  ({{.Image}}, {{.Status}})' | grep -v '^intact_' || true)"
    if [[ -n "$left" ]]; then
        warn "still present after cleanup.sh:"; echo "$left" | sed 's/^/    /'
        echo "  cleanup.sh --force removes EVERY container, network and volume on this host,"
        echo "  not only risx's. Right on a dedicated box, a disaster on a shared one."
        if confirm "Run cleanup.sh --force?"; then
            # its output (container ids, "bridge is a pre-defined network") goes to the log
            rc=0
            out="$(cd "$RISX_ROOT/scripts" && username="$(basename "$(dirname "$RISX_ROOT")")" bash cleanup.sh --force </dev/null 2>&1)" || rc=$?
            printf '%s\n' "$out" >> "$LOG"
            left="$(docker ps -a --format '{{.Names}}' | grep -v '^intact_' || true)"
            if [[ -z "$left" ]]; then say "removed the rest"
            else warn "still present after cleanup.sh --force (exit $rc): $(paste -sd' ' <<<"$left")"; fi
        fi
    fi
}

edit_config() {
    step config "3. Configure Intact (config.yaml)" || return 0
    [[ -f "$CFG" ]] || die "$CFG not found"
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
        say "opening config.yaml — choose modules; leave the passwords empty to be asked (or have them generated) by the install; save and exit"
        # the editor needs the real terminal, not the logging pipe
        if { : >/dev/tty; } 2>/dev/null; then ${EDITOR:-nano} "$CFG" </dev/tty >/dev/tty 2>&1
        else ${EDITOR:-nano} "$CFG"; fi
        local summary
        # Every publicly known value, not just 123123: the install refuses them
        # (lib/secrets.sh), so say so here, before it stops.
        summary="$(python3 - "$CFG" "${INTACT_KNOWN_DEFAULT_PASSWORDS[@]}" <<'PYEOF'
import sys, yaml
c = yaml.safe_load(open(sys.argv[1])) or {}
known = set(sys.argv[2:])
m = c.get('modules') or {}
on = sorted(k for k, v in m.items() if isinstance(v, dict) and v.get('enabled', True))
weak = sorted(k for k, v in m.items() if isinstance(v, dict) and v.get('enabled', True)
              and (str(v.get('password') or '') in known or str(v.get('api_password') or '') in known))
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
        [[ "$domain" == "$ID_HOST" ]] || warn "domain $domain is NOT what the clients dial ($ID_HOST): every deployed client would be stranded"
        [[ "$port" == "$ID_PORT" ]] || warn "Velociraptor port $port is NOT the port the clients dial ($ID_PORT)"
        [[ -n "$weak" ]] && warn "these modules have a publicly known password, which the install refuses — empty it: $weak"
        if [[ "$velo_on" != yes ]]; then
            warn "Velociraptor is DISABLED — the migration needs it; enable it"; continue
        fi
        local ans; ask ans "  y = use this config / e = edit again: "
        [[ "$ans" == y || "$ans" == Y ]] || continue
        if [[ "$domain" != "$ID_HOST" || "$port" != "$ID_PORT" ]]; then
            confirm "Are you SURE? Clients will only arrive if you repoint DNS/IP to $domain:$port yourself." || continue
        fi
        break
    done
    mark config
}

# What the steps after the removal need, checked while risx still runs: the
# old migrate_from_risx.sh found a missing piece only after it had deleted
# risx (QA, 2026-11-17). Runs again on a re-run until risx is removed.
check_ready() {
    done_step removed && return 0
    echo; say "=== 4. Check that everything the rest needs is here === ($(date '+%F %T'))"
    local f
    for f in install.sh lib/secrets.sh scripts/adopt_velociraptor_identity.sh scripts/migrate/transform_config.py; do
        [[ -f "$ROOT/$f" ]] || die "this Intact checkout ($ROOT) has no $f — use a complete release, then re-run"
    done
    [[ -z "$PACKAGE" || -r "$PACKAGE" ]] || die "cannot read --package $PACKAGE"
    echo "    Intact checkout  : $ROOT (complete)"
    # Lab-verified client window (docs/RISX_MIGRATION.md): 0.6.9 and newer.
    if [[ -n "$ID_VER" && "$(printf '%s\n' 0.6.9 "$ID_VER" | sort -V | head -1)" != 0.6.9 ]]; then
        warn "risx runs Velociraptor $ID_VER, older than the tested 0.6.9: its clients may not reconnect"
        confirm "Continue anyway (see the stepping-stone path in docs/RISX_MIGRATION.md)?" || die "stopped before anything changed"
    fi
    local src="$VELO_DATA" kb root gb
    [[ -d "$DS" ]] && src="$DS"
    kb=$(ds_kb "$src"); kb="${kb:-0}"
    root="$(docker info -f '{{.DockerRootDir}}' 2>/dev/null)"; root="${root:-/var/lib/docker}"
    gb="$(df -B1G --output=avail "$root" 2>/dev/null | tail -1 | tr -d ' ')"
    echo "    risx's datastore : $((kb/1024)) MB (moves into Intact)"
    echo "    free for Docker  : ${gb:-?} GB under $root"
    if [[ -n "$gb" ]]; then
        (( gb * 1024 * 1024 > kb )) \
            || die "not enough space under $root for the history ($((kb/1024)) MB, ${gb} GB free) — free some, then re-run"
        if (( gb * 1024 * 1024 < kb + 100 * 1024 * 1024 )); then
            warn "Intact wants 100 GB free on top of the history (README); this box has ${gb} GB"
            confirm "Continue anyway?" || die "stopped before anything changed"
        fi
    fi
}

install_intact() {
    step installed "8. Install Intact.AI" || return 0
    if docker ps --format '{{.Names}}' 2>/dev/null | grep -qx intact_velociraptor \
            && ! confirm "Intact is already running on this box. Re-run install.sh anyway?"; then
        say "keeping the running install"; mark installed; return 0
    fi
    say "running install.sh${PACKAGE:+ --package $PACKAGE} (this takes a while)"
    (cd "$ROOT" && sudo bash install.sh ${PACKAGE:+--package "$PACKAGE"}) \
        || die "install.sh failed — fix the cause and re-run this script; it continues from the install"
    mark installed
}

# The cheapest history source the backup holds: the moved datastore as it is;
# an archive from an older version of this script, unpacked ONCE into $DS
# and kept there, so a retry does not unpack it again.
history_source() {
    [[ -d "$DS" ]] && return 0
    local tarball; tarball="$(ls -t "$BACKUP_DIR"/velociraptor-full-*.tar.gz 2>/dev/null | head -1)"
    [[ -n "$tarball" ]] || { warn "no datastore in $DS: only the identity moves, history starts empty"; return 1; }
    local dskb; dskb="$(state_val dskb)"; dskb="${dskb:-$(( $(stat -c %s "$tarball") * 3 / 1024 ))}"
    if (( $(free_kb "$BACKUP_DIR") < dskb )); then
        warn "not enough free space to unpack $tarball (about $((dskb/1024)) MB): the history stays in it"
        return 1
    fi
    say "unpacking $tarball into $DS (once; a retry reuses it)…"
    sudo rm -rf "$DS.part"; mkdir -p "$DS.part" && sudo tar -xzf "$tarball" -C "$DS.part" --strip-components=1 \
        || { sudo rm -rf "$DS.part"; die "could not unpack $tarball"; }
    sudo chown -R "$(id -un):$(id -gn)" "$DS.part" && mv "$DS.part" "$DS"
}

adopt() {
    step adopted "9. Adopt the fleet's Velociraptor identity, with its history" || return 0
    echo "  the fleet's CA     : $ID_FP"
    echo "  CA on this box now : $(live_fp || true)"
    local ds=()
    if history_source; then
        # One copy, into the Velociraptor datastore volume (adopt's rsync).
        local dskb root; dskb="$(state_val dskb)"; dskb="${dskb:-0}"
        root="$(docker info -f '{{.DockerRootDir}}' 2>/dev/null)"
        if [[ -n "$root" ]] && (( $(free_kb "$root") < dskb )); then
            warn "not enough free space under $root to bring the history (about $((dskb/1024)) MB needed)."
            warn "  The identity still moves and clients reconnect; the history stays in $DS."
        else
            ds=(--datastore "$DS")
        fi
    fi
    # -y: the address check is this script's (step 5), and there is nothing on a
    # fresh install to protect from the swap.
    local rc=0
    (cd "$ROOT" && sudo bash scripts/adopt_velociraptor_identity.sh --from "$BACKUP_DIR" -y "${ds[@]}") || rc=$?
    (( rc == 0 )) || die "the adopt step failed (exit $rc) — see adopt_velo_identity_*.log in $ROOT; re-run to retry"
    [[ "$(live_fp)" == "$ID_FP" ]] \
        || die "the adopt step finished but this box does not run $ID_FP — re-run to retry"
    mark adopted
}

# A stored Velociraptor password, read as root (the store is 0600 root).
velo_secret() {
    sudo bash -c 'SCRIPT_DIR="$1"; source "$1/lib/secrets.sh" && secret_get velociraptor "$2"' _ "$ROOT" "$1"
}

# The users came across with the RISX datastore, so they still have RISX's
# passwords, not the ones the install stored and shows (show-credentials.sh).
# `user add` on an existing user replaces only its password (0.77.3). `api` is
# the backend's API-certificate identity: re-passworded with its random stored
# value, never removed. The values stay out of the log (output dropped) and
# out of the host argv and `docker events` (exec_create logs the full command):
# the exec gets the value in its environment (-e _P names it, never the value).
#
# A RUNNING server does not see a `user add` until its process restarts (the
# old password keeps working, the new one is refused -- proven on 0.77.3), so
# the container is RECREATED afterwards (a plain restart would also do that,
# but recreate re-reads env_file, and the entrypoint re-applies `api` from it),
# then both logins are checked over the GUI port.
apply_velo_passwords() {
    local envf="$ROOT/modules/velociraptor/.env" gui role api row k u r pw users=()
    gui="$(sed -n 's/^VELOX_USER=//p' "$envf" 2>/dev/null | tail -1)"
    [[ -n "$gui" ]] || gui="$(python3 -c 'import sys,yaml; print(((yaml.safe_load(open(sys.argv[1])) or {}).get("modules") or {}).get("velociraptor",{}).get("id") or "")' "$CFG" 2>/dev/null)"
    role="$(sed -n 's/^VELOX_ROLE=//p' "$envf" 2>/dev/null | tail -1)"
    api="$(sed -n 's/^VELOX_USER_2=//p' "$envf" 2>/dev/null | tail -1)"
    for row in "VELOX_PASSWORD|${gui:-tenroot}|${role:-administrator}" "VELOX_PASSWORD_2|${api:-api}|api,administrator"; do
        IFS='|' read -r k u r <<<"$row"
        pw="$(velo_secret "$k")" || { warn "no stored $k in modules/velociraptor/secrets/creds.env"; return 1; }
        _P="$pw" docker exec -e _P intact_velociraptor sh -c \
            'exec /velociraptor/velociraptor --config /velociraptor/server.config.yaml user add "$1" "$_P" --role "$2"' \
            _ "$u" "$r" >/dev/null 2>&1 || { warn "user add $u failed"; return 1; }
        users+=("$k|$u")
    done
    # sudo: compose reads secrets/creds.env, which is root's 0600 file.
    (cd "$ROOT/modules/velociraptor" && sudo docker compose up -d --force-recreate --no-build --pull never velociraptor) \
        >/dev/null 2>&1 || { warn "could not recreate intact_velociraptor"; return 1; }
    local i
    for row in "${users[@]}"; do
        IFS='|' read -r k u <<<"$row"
        pw="$(velo_secret "$k")" || return 1
        for (( i = 0; i < ${VELO_LOGIN_WAIT:-30}; i++ )); do
            velo_login "$u" "$pw" && break
            sleep 3
        done
        (( i < ${VELO_LOGIN_WAIT:-30} )) || { warn "Velociraptor does not accept the stored password of '$u' after the recreate"; return 1; }
    done
    say "Velociraptor users '${gui:-tenroot}' and '${api:-api}' now log in with the passwords this install stored"
    say "  (sudo bash $ROOT/scripts/show-credentials.sh shows the GUI one)"
}

# velo_login <user> <password> -- 0 when the GUI (127.0.0.1:8889, Basic auth)
# accepts it. The credentials go to curl as a config on stdin, never in argv.
velo_login() {
    local v="$1:$2" code
    v="${v//\\/\\\\}"; v="${v//\"/\\\"}"
    code="$(printf 'user = "%s"\n' "$v" | curl -s -K - -o /dev/null -w '%{http_code}' --max-time 5 \
            "${INTACT_VELO_GUI:-http://127.0.0.1:8889}/velociraptor/app/index.html" 2>/dev/null)"
    [[ "$code" == 200 ]]
}

# How many clients the NEW server knows, against how many the old datastore held.
# Asked of the running server through its API: a separate `query --config`
# process reads the datastore on its own and finds NO clients -- QA's run
# (2026-11-17) reported 0 of 12 that way, and a healthy box 0 of 19. The server
# also converts risx's older client index on its first start, so the count is
# polled until it reaches the old one or stops for VELO_COUNT_WAIT seconds.
count_clients() {
    local want=0 n=-1 last=-2 waited=0 out hosts
    if sudo test -d "$DS/clients"; then want=$(sudo find "$DS/clients" -mindepth 1 -maxdepth 1 -type d -name 'C.*' | wc -l); fi
    while :; do
        out="$(docker exec intact_velociraptor ./velociraptor --api_config /velociraptor/api.config.yaml \
               query "SELECT client_id, os_info.hostname AS host FROM clients()" --format json 2>/dev/null)"
        hosts="$(python3 -c '
import json, re, sys
rows = []
for chunk in re.findall(r"\[[\s\S]*?\]", sys.stdin.read()):
    try: rows += json.loads(chunk)
    except ValueError: pass
names = [str(r.get("host") or r.get("client_id")) for r in rows if isinstance(r, dict)]
print(len(names)); print(", ".join(names[:5]))' <<<"$out" 2>/dev/null)"
        n="$(head -1 <<<"$hosts")"; n="${n:-0}"
        (( n >= want || waited >= ${VELO_COUNT_WAIT:-90} )) && break
        (( n == last && waited >= 30 )) && break
        last=$n; sleep 5; waited=$((waited + 5))
    done
    local eg; eg="$(sed -n 2p <<<"$hosts")"
    say "clients known to the new server: $n of the $want risx had${eg:+ (e.g. $eg)}"
    if (( n < want )); then
        say "  the other $((want - n)) appear as they reconnect (minutes to hours on a large fleet)"
    fi
}

verify() {
    step verified "10. Verify" || return 0
    local live; live="$(live_fp)"
    [[ "$live" == "$ID_FP" ]] \
        || die "CA in use is '${live:-unreadable}', the backup's is $ID_FP — the adoption did not take"
    say "CA in use matches the backup: $live"
    if ! docker ps --filter 'name=^intact_velociraptor$' --format '{{.Status}}' 2>/dev/null | grep -q '^Up'; then
        die "intact_velociraptor is not running. Start it, then re-run:
    (cd $ROOT && sudo docker compose -f modules/velociraptor/docker-compose.yaml up -d --no-build --pull never)"
    fi
    say "intact_velociraptor is up"
    apply_velo_passwords || die "could not give the Velociraptor users the passwords Intact stored — re-run to retry"
    count_clients
    mark verified
    cat <<EOF

  Done. Next:
    - open https://${ID_HOST}/ and finish the first-login setup
    - a large fleet reconnects over minutes to hours; check that a collection reaches one client
    - ${BACKUP_DIR}/server.config.yaml is a plain copy of the fleet's CA key: delete it
      (shred -u) once you are satisfied$([[ -d "$DS" ]] && printf '; %s is the old datastore\n      (also holds the CA): keep it safe until you no longer need the history' "$DS")
EOF
    # cleanup.sh empties workdir/ but leaves risx's scripts and resources
    local risx="${RISX_ROOT:-$(state_val risx_root)}"
    if [[ -n "$risx" && -d "$risx" ]]; then
        echo "    - $risx now holds only risx's scripts: delete it (sudo rm -rf $risx)"
    fi
}

# --- main --------------------------------------------------------------------

ensure_yaml
if done_step verified; then say "this migration is already complete (see $STATE)"; exit 0; fi
docker ps >/dev/null 2>&1 || die "this user cannot run docker — add it to the docker group and log in again"
# risx already removed (finished, or cut off mid-removal): work from the backup.
if done_step backup && ! risx_present && ! done_step removed; then
    warn "risx-mssp is no longer on this box — continuing from the backup"; mark removed
fi
# Every question and check while risx still runs; from the pause on, unattended.
done_step removed || { find_risx; choose_mode; edit_config; check_ready; backup; pause_for_copy; remove_risx_box; }
identity "$BACKUP_DIR/server.config.yaml"
# config.yaml is normally done before the removal; a state from an older
# version of this script reaches it only here.
done_step config || edit_config
install_intact; adopt; verify
