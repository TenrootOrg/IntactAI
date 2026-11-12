#!/bin/bash
# risx_to_intact.sh — replace risx-mssp with Intact.AI on the SAME machine.
#
# The deployed Velociraptor fleet is kept: every client keeps its client_id and
# nothing is touched on an endpoint. Everything else from risx starts fresh.
# (Moving to ANOTHER machine is a manual procedure: docs/RISX_TO_INTACT_RUNBOOK.md.)
#
# Run it as your normal login user (sudo is used where needed), from anywhere:
#
#   bash risx_to_intact.sh [--backup-dir DIR] [--package TAR]
#
# Outside an Intact checkout it clones the latest Intact release into ~/intact
# (or $INTACT_DIR) and carries on from there. Run it; do not pipe it into bash.
#
# What it does — it stops only twice:
#   1 find risx and show the fleet's identity
#   2 back up (graceful stop, server.config.yaml, the datastore)
#   3 PAUSE: scp lines to copy the backup off; press r to continue  <- you
#   4 remove risx (its own cleanup.sh)
#   5 config.yaml in nano, then: y = install / e = edit again        <- you
#   6 install.sh   7 adopt the identity, with the old history   8 verify
# Other questions appear only when something is wrong (the address clients dial
# does not match, containers are left after the cleanup, ...).
#
# Each finished step is recorded in <backup-dir>/.risx_to_intact.<machine>.state,
# so a re-run after a failure or Ctrl+C carries on where it stopped. Everything
# printed, and every answer, is logged to <backup-dir>/risx_to_intact-*.log
# (mode 600); on an error it lists every log to collect.
#
# Options:
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
confirm() {  # y/N, with the answer in the log
    local _a; read -r -p "$1 [y/N] " _a || _a=""
    log_answer "${_a:-<none>}"
    [[ "$_a" == y || "$_a" == Y || "$_a" == yes ]]
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

# --- steps -------------------------------------------------------------------

find_risx() {
    if done_step find; then          # re-run: re-read what later steps need
        discover_risx; identity "$VELO_DATA/server.config.yaml" sudo; return 0
    fi
    step find "1. Find risx-mssp and its Velociraptor identity"
    discover_risx
    say "this is the identity your whole fleet is pinned to (write the fingerprint down):"
    identity "$VELO_DATA/server.config.yaml" sudo
    show_identity
    mark find
}

backup() {
    step backup "2. Back up the Velociraptor files to $BACKUP_DIR" || return 0
    # A graceful stop flushes the fleet list (client_info/snapshot.json); without
    # it Intact shows an EMPTY client list until each endpoint re-enrols.
    graceful_stop_legacy_velo
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
    sudo tar -czf "$tarball" -C "$(dirname "$VELO_DATA")" \
        --exclude='velociraptor/clients/linux' --exclude='velociraptor/clients/mac' \
        --exclude='velociraptor/clients/windows' "$(basename "$VELO_DATA")" || rc=$?
    if (( rc != 0 )); then sudo rm -f "$tarball"; die "the archive failed (tar exit $rc) — nothing else was done"; fi
    sudo chown "$(id -un):$(id -gn)" "$tarball" && chmod 600 "$tarball"
    tar -tzf "$tarball" "velociraptor/server.config.yaml" >/dev/null 2>&1 \
        || die "the archive is not readable — nothing else was done"
    echo "dskb=$need" >> "$STATE"
    echo; ls -lh "$BACKUP_DIR"
    mark backup
}

pause_for_copy() {
    step copied "3. Copy the backup off this machine (optional), then continue" || return 0
    local ip; ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
    local src; src="$(id -un)@${ip:-<this-box-ip>}:${BACKUP_DIR}"
    cat <<EOF

  The backup is ready in ${BACKUP_DIR} (it holds the fleet's CA key: a credential).
  To keep a copy off this box, run on your laptop:

    PowerShell:              scp -r "${src}" .
    bash (Linux/macOS):      scp -r "${src}" .

  NEXT: risx-mssp is REMOVED from this box.
  (Ctrl+C stops here; risx's Velociraptor is stopped — to start it again:
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
    step removed "4. Remove risx-mssp from this machine" || return 0
    local cleanup="$RISX_ROOT/scripts/cleanup.sh"
    [[ -f "$cleanup" ]] || die "no $cleanup — remove risx by hand, then re-run"
    [[ -s "$BACKUP_DIR/server.config.yaml" ]] && compgen -G "$BACKUP_DIR/velociraptor-full-*.tar.gz" >/dev/null \
        || die "the backup is incomplete — refusing to remove risx"
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
}

edit_config() {
    step config "5. Configure Intact (config.yaml)" || return 0
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
        say "opening config.yaml — choose modules, set passwords; save and exit"
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
        [[ "$domain" == "$ID_HOST" ]] || warn "domain $domain is NOT what the clients dial ($ID_HOST): every deployed client would be stranded"
        [[ "$port" == "$ID_PORT" ]] || warn "Velociraptor port $port is NOT the port the clients dial ($ID_PORT)"
        [[ -n "$weak" ]] && warn "these modules still use the default password 123123: $weak"
        if [[ "$velo_on" != yes ]]; then
            warn "Velociraptor is DISABLED — the migration needs it; enable it"; continue
        fi
        local ans; ask ans "  y = install with this config / e = edit again: "
        [[ "$ans" == y || "$ans" == Y ]] || continue
        if [[ "$domain" != "$ID_HOST" || "$port" != "$ID_PORT" ]]; then
            confirm "Are you SURE? Clients will only arrive if you repoint DNS/IP to $domain:$port yourself." || continue
        fi
        break
    done
    mark config
}

install_intact() {
    step installed "6. Install Intact.AI" || return 0
    if docker ps --format '{{.Names}}' 2>/dev/null | grep -qx intact_velociraptor \
            && ! confirm "Intact is already running on this box. Re-run install.sh anyway?"; then
        say "keeping the running install"; mark installed; return 0
    fi
    say "running install.sh${PACKAGE:+ --package $PACKAGE} (this takes a while)"
    (cd "$ROOT" && sudo bash install.sh ${PACKAGE:+--package "$PACKAGE"}) \
        || die "install.sh failed — fix the cause and re-run this script; it continues from the install"
    mark installed
}

adopt() {
    step adopted "7. Adopt the fleet's Velociraptor identity, with its history" || return 0
    echo "  the fleet's CA     : $ID_FP"
    echo "  CA on this box now : $(live_fp || true)"
    local tarball extract="" ds=()
    tarball="$(ls -t "$BACKUP_DIR"/velociraptor-full-*.tar.gz 2>/dev/null | head -1)"
    if [[ -z "$tarball" ]]; then
        warn "no datastore archive in $BACKUP_DIR: only the identity moves, history starts empty"
    else
        # Unpacked here, then copied into the datastore volume: about 2x its size.
        local dskb; dskb="$(sed -n 's/^dskb=//p' "$STATE" | tail -1)"
        dskb="${dskb:-$(( $(stat -c %s "$tarball") * 3 / 1024 ))}"
        if (( $(free_kb "$BACKUP_DIR") < dskb * 2 )); then
            warn "not enough free space to bring the old history (about $((dskb*2/1024)) MB needed)."
            warn "  The identity still moves and clients reconnect; the history stays in $tarball."
        else
            extract="$BACKUP_DIR/.datastore-extract"
            say "unpacking $tarball…"
            sudo rm -rf "$extract"; mkdir -p "$extract"
            sudo tar -xzf "$tarball" -C "$extract" || die "could not unpack $tarball"
            ds=(--datastore "$extract/velociraptor")
        fi
    fi
    # -y: the address check is this script's (step 5), and there is nothing on a
    # fresh install to protect from the swap.
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
    local out rc=0
    out="$(docker exec intact_velociraptor ./velociraptor --config /velociraptor/server.config.yaml \
           query "SELECT client_id, os_info.hostname AS host FROM clients()" 2>&1)" || rc=$?
    if (( rc != 0 )); then
        warn "could not list the clients (exit $rc):"; tail -5 <<<"$out" | sed 's/^/    /'
    else
        python3 -c '
import json, re, sys
raw = sys.stdin.read()
rows = []
for chunk in re.findall(r"\[[\s\S]*?\]", raw):
    try: rows += json.loads(chunk)
    except ValueError: pass
hosts = [r.get("host") or r.get("client_id") for r in rows if isinstance(r, dict)]
print("[migrate] clients known to the new server: %d" % len(hosts)
      + (" (e.g. %s)" % ", ".join(map(str, hosts[:5])) if hosts else
         " -- the old fleet list did not come across; clients re-appear as they reconnect"))
' <<<"$out" || warn "could not read the client list: $(tail -1 <<<"$out")"
    fi
    mark verified
    cat <<EOF

  Done. Next:
    - open https://${ID_HOST}/ and finish the first-login setup
    - a large fleet reconnects over minutes to hours; check that a collection reaches one client
    - ${BACKUP_DIR}/server.config.yaml is a plain copy of the fleet's CA key: delete it
      (shred -u) once you are satisfied; keep the velociraptor-full-*.tar.gz archive safe
EOF
    echo; list_logs
}

# --- main --------------------------------------------------------------------

ensure_yaml
if done_step verified; then say "this migration is already complete (see $STATE)"; exit 0; fi
docker ps >/dev/null 2>&1 || die "this user cannot run docker — add it to the docker group and log in again"
# risx already removed (finished, or cut off mid-removal): work from the backup.
if done_step backup && ! risx_present && ! done_step removed; then
    warn "risx-mssp is no longer on this box — continuing from the backup"; mark removed
fi
done_step removed || { find_risx; backup; pause_for_copy; remove_risx_box; }
identity "$BACKUP_DIR/server.config.yaml"
edit_config; install_intact; adopt; verify
