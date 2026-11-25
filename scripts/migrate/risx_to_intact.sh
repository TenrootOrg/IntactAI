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
# (hunts, collections, client list). Every question comes first, while risx
# still runs: the sudo password, the backup choice, config.yaml, the tools'
# passwords, and the one stop before risx is removed. After it, nothing asks:
#   1 find risx and show the fleet's identity
#   2 what goes into the backup you copy off the box: 1 config / 2 config + data
#   3 config.yaml in nano, then: y = use it / e = edit again; then the tools'
#     passwords (type one, or Enter to generate)                       <- you
#   4 check everything the rest needs (the checkout, docker, disk space)
#   5 back up (graceful stop, server.config.yaml; the datastore is MOVED next
#     to it — instant on the same disk, no archive)
#   6 PAUSE: one scp line to copy the backup off; press r to continue  <- you
#   7 remove risx: everything Docker says is risx's (stacks, one-offs, volumes,
#     networks, images), its cron lines and folders -- risx's cleanup.sh is not used
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
        # --package means no network: fetching a checkout here would only hang
        # on api.github.com, and would not be the package's release anyway.
        for _a in "$@"; do
            [[ "$_a" == --package* ]] || continue
            echo "--package is an air-gapped migration: run it from the extracted release tree" >&2
            echo "  (bash <release-tree>/scripts/migrate/risx_to_intact.sh --package ...), not standalone." >&2
            exit 1
        done
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
STOP_BEFORE_INSTALL=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --backup-dir) BACKUP_DIR="${2:?--backup-dir needs a directory}"; shift ;;
        --package)    PACKAGE="${2:?--package needs a file}"; shift ;;
        # not in --help: for testing, stops once risx is removed (step 7) so the
        # box can be looked at; run again without it to continue from the install
        --stop-before-install) STOP_BEFORE_INSTALL=1 ;;
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
# The terminal gets every byte at once (a prompt shows before its answer); the
# log gets every line with the time it was printed, so a run can be followed
# and read back from another machine. printf's %(...)T is a bash builtin: no
# `date` per line through the install's thousands of lines.
_ts() { local _l; while IFS= read -r _l || [[ -n "$_l" ]]; do printf '[%(%F %T)T] %s\n' -1 "$_l"; done; }
# Two execs, not one with both redirects: tests/test_stderr_not_silenced.sh
# flags any bare exec that carries a stderr redirect after another one (the
# shape of the lock line that once sent stderr to /dev/null). Here stderr is
# MERGED into the logged stream, not silenced; the split behaves the same.
exec > >(tee >(_ts >> "$LOG"))
exec 2>&1

# Masks what looks like a credential: KEY=value / key: value pairs named like a
# password, token, secret or key, and whole PEM blocks. A safety net for the
# bundle -- the log itself is written to hold none.
redact() {
    python3 -c '
import re, sys
# bytes, not strict UTF-8: one stray byte (a Hebrew-layout keystroke in an
# answer, odd Docker output) crashed this and the bundle lost that log (2026-11-18)
t = sys.stdin.buffer.read().decode("utf-8", "replace")
t = re.sub(r"-----BEGIN [A-Z ]+-----[\s\S]*?-----END [A-Z ]+-----", "[REDACTED PEM]", t)
# A yes/no or empty value is not a secret: allow_weak_passwords: true was masked.
t = re.sub(r"(?im)^(\s*[\w.-]*(?:password|passwd|token|secret|api_?key|private_key|nonce)[\w.-]*\s*[:=]\s*)(\S.*)$",
           lambda m: m.group(0) if re.fullmatch(r"(?i)(true|false|yes|no|\x27\x27|\"\")\s*(#.*)?", m.group(2).strip())
                     else m.group(1) + "[REDACTED]", t)
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
    local ip; ip="$(box_ip)"
    echo "  Everything to send back is in one file (passwords and keys masked):"
    echo "    $out"
    echo "  To copy it to your laptop (PowerShell or a Linux/macOS shell):"
    echo "    scp \"$(id -un)@${ip:-<this-box-ip>}:$out\" ."
}
on_exit() {
    local rc=$?
    [[ -n "${SUDO_KEEPALIVE:-}" ]] && kill "$SUDO_KEEPALIVE" 2>/dev/null
    # plain, not a second WARN: the ERROR above already said what went wrong
    if (( rc != 0 )); then echo "  stopped at $(date '+%F %T') (exit $rc)"; fi
    echo; bundle_logs || echo "  (could not pack the logs; send $LOG)"
    # also after a failure: the tools that did come up need them
    [[ -n "${SHOW_LOGINS:-}" ]] && show_logins
}

# The logins, the last thing on screen: install.sh showed them at step 8, and
# steps 9-10 and the log bundle scrolled them away. Written to the terminal
# only -- never the log or the bundle (stdout here is tee'd into both).
show_logins() {
    if ! { : > /dev/tty; } 2>/dev/null; then
        echo "  Logins and the dashboard setup token: sudo bash $ROOT/scripts/show-credentials.sh"; return 0
    fi
    local rows tok
    rows="$(sudo bash "$ROOT/scripts/show-credentials.sh" 2>/dev/null | grep -v '^Dashboard setup token')"
    tok="$(sudo cat "$ROOT/data/state/backend/setup_token" 2>/dev/null | tr -d '[:space:]')"
    {
        echo
        echo "  ---- logins (shown here only, never in a log; again: sudo bash scripts/show-credentials.sh) ----"
        [[ -n "$rows" ]] && sed 's/^/  /' <<<"$rows"
        echo "  ----------------------------------------------------------------------------------------------"
        if [[ -n "$tok" ]]; then
            echo
            echo "  Dashboard setup: https://${ID_HOST}/setup.html"
            echo "  Setup token:     $tok"
        fi
        echo
    } > /dev/tty
}
trap on_exit EXIT
echo "risx_to_intact.sh: $(date '+%F %T') on $(hostname) as $(id -un); Intact $(git -C "$ROOT" describe --tags --always 2>/dev/null || echo '?') at $ROOT"

# --- small helpers -----------------------------------------------------------

done_step() { grep -qx "$1" "$STATE" 2>/dev/null; }
mark()      { echo "$1" >> "$STATE"; }
# Each step runs once; on a re-run a finished step is skipped with a note.
step() {
    if done_step "$1"; then say "step '$1' already done — skipping"; return 1; fi
    echo; say "=== $2 === ($(date '+%F %T'))"
    need_sudo
    return 0
}
# A refused sudo must stop the run, not leave a step half done: QA mistyped it
# three times in step 9 and the step went on with an empty CA (2026-11-18).
need_sudo() {
    sudo -n true 2>/dev/null && return 0
    sudo -v || die "sudo was refused — run the script again; it continues from this step"
}
# Asked once at the start, then kept fresh: the install alone outlasts sudo's
# 15-minute memory, so step 9 asked again with nobody watching (QA, 2026-11-18).
keep_sudo() {
    # Already passwordless (NOPASSWD): nothing to ask. Checked with `-n true`, not
    # `-v`: validating checks EVERY matching rule, so a NOPASSWD user who is also
    # in the sudo group is still asked by `sudo -v` (mssp-demo, 2026-11-18).
    sudo -n true 2>/dev/null || sudo -v || die "this script needs sudo (it is asked once, here)"
    # Kept fresh even when nothing was asked: `-n true` also passes on a password
    # still cached from an earlier sudo, which runs out during the install;
    # mssp-demo's step 9 then sat 20 min at a prompt nobody saw (2026-11-18).
    # its own output to /dev/null: holding the log pipe, its `sleep` kept the
    # run from ending for up to 50 s after the last line
    ( while kill -0 "$$" 2>/dev/null; do sudo -n -v 2>/dev/null; sleep 50; done ) >/dev/null 2>&1 </dev/null &
    SUDO_KEEPALIVE=$!
}
log_answer() { printf '[%(%F %T)T] answer: %s\n' -1 "$1" >> "$LOG"; }
# A Hebrew keyboard layout types ר/ט/ק for r/y/e, and Backspace may erase only
# one byte of such a 2-byte letter: mssp-demo's pause read 0xD7 + "r", asked
# again, and the stray byte made grep call the log binary (2026-11-18). So the
# three letters count as theirs, and anything not printable ASCII is dropped.
clean_answer() {
    local a="${1//ר/r}"; a="${a//ט/y}"; a="${a//ק/e}"
    printf '%s' "$a" | LC_ALL=C tr -cd '\40-\176'
}
ask() {  # ask VAR "prompt" — dies on end of input instead of looping forever
    local _a; read -r -p "$2" _a || die "no answer (end of input) — stopped"
    _a="$(clean_answer "$_a")"
    log_answer "$_a"; printf -v "$1" '%s' "$_a"
}
confirm() {  # y/N, with the answer in the log
    local _a; read -r -p "$1 [y/N] " _a || _a=""
    _a="$(clean_answer "$_a")"
    log_answer "${_a:-<none>}"
    [[ "$_a" == y || "$_a" == Y || "$_a" == yes ]]
}
risx_present() {
    local base="${RISX_ROOT:-/home/*/setup_platform}"
    compgen -G "$base/workdir/velociraptor/velociraptor/server.config.yaml" >/dev/null && return 0
    # step 5 moved the datastore out; the rest of risx stays
    # until step 7 deletes setup_platform
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
_gb() { awk -v k="${1:-0}" 'BEGIN {printf "%.1f", k/1024/1024}'; }
# The history's size: risx keeps its client installers under clients/<os>,
# which are not history and do not come across (a test box: 317 MB in all, 75 MB of history).
ds_kb() { sudo du -sk --exclude=clients/linux --exclude=clients/mac --exclude=clients/windows "$1" 2>/dev/null | cut -f1; }

ensure_yaml() {
    python3 -c 'import yaml' 2>/dev/null && return 0
    # Air-gapped: the package's system bundle carries python3-yaml, and the
    # live mirror is out of reach. Found and installed the way install.sh does
    # (lib/args.sh, lib/deps.sh); exit 4 = this package has no bundle.
    if [[ -n "$PACKAGE" ]]; then
        say "installing python3-yaml from the package's system bundle"
        local rc=0
        sudo env SCRIPT_DIR="$ROOT" LOG_FILE=/dev/null PKG="$PACKAGE" bash -c '
            for l in common deps args; do source "$SCRIPT_DIR/lib/$l.sh" >/dev/null || exit 3; done
            INTACT_SYSTEM_BUNDLE_SRC=""
            _note_system_bundle_candidate "$PKG"
            tmp=""
            if [[ -z "$INTACT_SYSTEM_BUNDLE_SRC" && -f "$PKG" ]] && ! _args_is_gzip "$PKG"; then
                # A wrapper (<tag>-package.tar) carries the bundle as a member.
                mkdir -p "$SCRIPT_DIR/data/tmp" && tmp="$(mktemp -d -p "$SCRIPT_DIR/data/tmp" unwrap-XXXXXX)" || exit 3
                trap "rm -rf \"$tmp\" \"$SCRIPT_DIR/data/tmp/system-bundle-pkg\"" EXIT
                tar -xf "$PKG" -C "$tmp" --wildcards "*-system-bundle.tar" 2>/dev/null
                INTACT_SYSTEM_BUNDLE_SRC="$(find "$tmp" -maxdepth 1 -name "*-system-bundle.tar" | head -1)"
            fi
            [[ -n "$INTACT_SYSTEM_BUNDLE_SRC" ]] || exit 4
            [[ -n "$tmp" ]] || trap "rm -rf \"$SCRIPT_DIR/data/tmp/system-bundle-pkg\"" EXIT
            _stage_system_bundle_from_source "$INTACT_SYSTEM_BUNDLE_SRC" \
                && _verify_system_bundle_os_match "$_STAGED_BUNDLE_DIR" \
                && _apt_install_from_bundle "$_STAGED_BUNDLE_DIR" python3-yaml' || rc=$?
        case "$rc" in
            0) return 0 ;;
            4) warn "the package carries no system bundle — trying the apt mirror" ;;
            *) die "could not install python3-yaml from the package's system bundle — install it on this box first" ;;
        esac
    fi
    say "installing python3-yaml (needed to read the Velociraptor config)"
    sudo apt-get install -y python3-yaml >/dev/null 2>&1 || die "could not install python3-yaml — run: sudo apt-get install -y python3-yaml"
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
    # The config's version is the one that generated it; a newer binary never
    # updates it: risx upgraded to 0.77.2 still said 0.75.5 (mssp-demo,
    # 2026-11-18). The running server knows -- the config is the fallback.
    local live
    live="$(docker exec velociraptor ./velociraptor version 2>/dev/null | sed -n 's/^version: *//p' | head -1)"
    [[ -n "$live" ]] && ID_VER="$live"
    return 0
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

# Step 7 deletes setup_platform, so the datastore has to leave it first
# (always: Intact gets the history whatever the backup choice).
# A rename, not tar.gz + unzip: risx is removed next anyway, and on the same
# disk it is instant and needs no space. Another disk makes mv a plain copy.
move_datastore() {
    if [[ -d "$DS" ]]; then say "the datastore is already in $DS"; return 0; fi
    local need; need=$(ds_kb "$VELO_DATA")
    if [[ "$(stat -c %d "$VELO_DATA")" == "$(stat -c %d "$BACKUP_DIR")" ]]; then
        say "datastore moved to $DS ($(_gb "$need") GB, same disk: instant)"
    else
        (( $(free_kb "$BACKUP_DIR") > need )) \
            || die "not enough free space in $BACKUP_DIR: the datastore is $((need/1024)) MB, $(( $(free_kb "$BACKUP_DIR")/1024 )) MB free"
        say "copying the datastore to $DS ($(_gb "$need") GB, another disk: this takes a while)"
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
    mark backup
}

# The address this box reaches the network from: once Intact is installed the
# first of `hostname -I` is a Docker bridge, and the bundle's scp line said
# 172.20.0.1 instead of 10.10.10.47 (mssp-demo, 2026-11-18).
box_ip() {
    local ip; ip="$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p')"
    [[ -n "$ip" ]] || ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
    echo "$ip"
}

pause_for_copy() {
    step copied "6. Copy the backup off this box (optional)" || return 0
    local ip; ip="$(box_ip)"
    local src; src="$(id -un)@${ip:-<this-box-ip>}:${BACKUP_DIR}"
    local what line shells="PowerShell or Linux/macOS. "
    if [[ "$(backup_mode)" == data ]]; then
        # One .tar streamed over ssh, not `scp -r`: that unpacked hundreds of
        # thousands of datastore files loose into the laptop's Downloads
        # (risksrv, 2026-11-25), one round trip each. Nothing extra is written
        # on this box. cmd's `>` is byte-exact; Windows PowerShell's re-encodes
        # binary output, hence its own line through cmd /c.
        local tarcmd
        tarcmd="ssh $(id -un)@${ip:-<this-box-ip>} tar -cf - -C $(dirname "$BACKUP_DIR") $(basename "$BACKUP_DIR") > velociraptor_backup.tar"
        what="configuration + data, $(_gb "$(state_val dskb)") GB, as one file"
        line="cmd, Linux or macOS:"$'\n'"       ${tarcmd}"$'\n'"     PowerShell:"$'\n'"       cmd /c '${tarcmd}'"
        shells=""
    else
        # the two config files only: the datastore next to them is root's and large
        what="configuration only, a few KB"; line="scp \"${src}/*.config.yaml\" ."
    fi
    # The one thing to do here: framed and highlighted (QA: lost in the text).
    local b=$'\e[1;33m' o=$'\e[0m' bar="  ═══════════════════════════════════════════════════════════════════════"
    printf '\n%s%s\n   COPY THE BACKUP TO YOUR LAPTOP NOW (%s):\n\n     %s\n\n   %sIt holds the fleet'"'"'s CA key: keep it safe.\n%s%s\n\n' \
        "$b" "$bar" "$what" "$line" "$shells" "$bar" "$o"
    # Named here, before the r: nothing asks about it later. The full list and
    # how to start risx again after a Ctrl+C go to the log.
    risx_inventory
    { show_risx_inventory
      echo "To start risx's Velociraptor again after a Ctrl+C at the pause:"
      echo "  sudo mv ${DS} ${VELO_DATA}"
      echo "  docker update --restart=unless-stopped velociraptor && docker start velociraptor"; } | _ts >> "$LOG"
    echo "  Next, risx is removed: ${#INV_PROJ[@]} stacks, ${#INV_CONT[@]} containers, ${#INV_VOL[@]} volumes, ${#INV_NET[@]} networks,"
    echo "  ${#INV_IMG[@]} images (${INV_IMG_GB} GB)$([[ -n "$INV_BUILD_CACHE" && "$INV_BUILD_CACHE" != 0B ]] && echo ", build cache ${INV_BUILD_CACHE}"), its folders$( (( ${#INV_CRON[@]} )) && echo " and cron lines"). The full list is in the log."
    local kept=()
    (( ${#RISX_HOME_LEFTOVERS[@]} )) && kept+=("${#RISX_HOME_LEFTOVERS[@]} loose risx files (moved into the backup)")
    (( ${#INV_KEEP[@]} )) && kept+=("${#INV_KEEP[@]} thing(s) not risx's")
    (( ${#kept[@]} )) && echo "  Kept: $(printf '%s\n' "${kept[@]}" | paste -sd, - | sed 's/,/, /g')."
    echo "  Ctrl+C now keeps risx (how to start it again: in the log)."
    echo
    local ans
    while true; do
        ask ans "  Press r to continue: "
        [[ "$ans" == r || "$ans" == R ]] && break
    done
    mark copied
}

# --- what risx owns -----------------------------------------------------------
# Read from Docker itself, not from risx's cleanup.sh: that takes down only the
# apps in its APPS_TO_INSTALL, never removes an image, and its --force removes
# everything on the host. QA's mssp-demo (2026-11-18) had 12 risx compose
# stacks (timesketch one folder deeper than cleanup.sh looks), 8 one-off
# `docker run`s, 63 volumes, 7 networks, 47 images (~40 GB, kept by both
# modes) and risx's installer clone next to setup_platform.
#   risx's      every compose project whose folder is under setup_platform, the
#               stacks whose compose files are there, exited one-off containers,
#               everything those use (images, volumes, networks), main_network,
#               untagged images, unused anonymous volumes, risx's cron lines
#   not risx's  anything else: listed, never removed
# Fills INV_* (arrays of ids/names), RISX_HOME_LEFTOVERS and INV_IMG_GB.
risx_inventory() {
    INV_DIRS=() INV_PROJ=() INV_CONT=() INV_VOL=() INV_NET=() INV_IMG=() INV_KEEP=() INV_CRON=() RISX_HOME_LEFTOVERS=()
    INV_IMG_GB=0 INV_BUILD_CACHE=""
    local -A projs=() wds=() best=() score=()
    local id name proj wd status f d p sc v n img vols nets
    while IFS='|' read -r id name proj wd status; do
        [[ -n "$id" && "$name" != intact_* ]] || continue
        if [[ -n "$proj" && ( "$wd" == "$RISX_ROOT" || "$wd" == "$RISX_ROOT"/* ) ]]; then
            INV_CONT+=("$id"); projs[$proj]=1; wds[$wd]=1
        elif [[ -z "$proj" && "$status" != Up* ]]; then
            INV_CONT+=("$id")                             # an exited one-off `docker run`
        else
            INV_KEEP+=("container $name ($status${proj:+, compose project $proj in $wd})")
        fi
    done < <(docker ps -a --format '{{.ID}}|{{.Names}}|{{.Label "com.docker.compose.project"}}|{{.Label "com.docker.compose.project.working_dir"}}|{{.Status}}' 2>/dev/null)
    # stacks with no container left still own volumes and networks
    # One folder per compose project (its folder name, as compose names it):
    # risx keeps an unconfigured template of each stack in resources/ (no .env)
    # next to the one it runs in workdir/. Taking both downed every stack twice,
    # and the template's unset variables broke Timesketch's file -- "compose
    # down failed" on screen (mssp-demo, 2026-11-18). The folder its containers
    # ran from wins, then one with a .env.
    if [[ -d "$RISX_ROOT" ]]; then
        while IFS= read -r f; do
            d="$(dirname "$f")"; p="$(basename "$d" | tr 'A-Z' 'a-z' | tr -cd 'a-z0-9_-')"
            sc=0; [[ -f "$d/.env" ]] && sc=1; [[ -n "${wds[$d]:-}" ]] && sc=2
            if [[ -z "${best[$p]:-}" ]] || (( sc > ${score[$p]} )); then best[$p]="$d"; score[$p]=$sc; fi
            projs[$p]=1
        done < <(find "$RISX_ROOT" -maxdepth 5 \( -name docker-compose.yml -o -name docker-compose.yaml \
                    -o -name compose.yml -o -name compose.yaml \) 2>/dev/null | sort)
        (( ${#best[@]} )) && mapfile -t INV_DIRS < <(printf '%s\n' "${best[@]}" | sort)
    fi
    INV_PROJ=("${!projs[@]}")
    if (( ${#INV_CONT[@]} )); then
        while IFS='|' read -r img vols nets; do
            [[ -n "$img" ]] && INV_IMG+=("$img")
            for v in ${vols//,/ }; do INV_VOL+=("$v"); done
            for n in ${nets//,/ }; do case "$n" in bridge|host|none) ;; *) INV_NET+=("$n") ;; esac; done
        done < <(docker inspect -f '{{.Image}}|{{range .Mounts}}{{if eq .Type "volume"}}{{.Name}},{{end}}{{end}}|{{range $k, $v := .NetworkSettings.Networks}}{{$k}},{{end}}' "${INV_CONT[@]}" 2>/dev/null)
    fi
    local p
    for p in "${INV_PROJ[@]}"; do
        while IFS= read -r v; do [[ -n "$v" ]] && INV_VOL+=("$v"); done \
            < <(docker volume ls -q --filter "label=com.docker.compose.project=$p" 2>/dev/null)
        while IFS= read -r n; do [[ -n "$n" ]] && INV_NET+=("$n"); done \
            < <(docker network ls --format '{{.Name}}' --filter "label=com.docker.compose.project=$p" 2>/dev/null)
    done
    docker network inspect main_network >/dev/null 2>&1 && INV_NET+=(main_network)
    while IFS= read -r v; do [[ "$v" =~ ^[0-9a-f]{64}$ ]] && INV_VOL+=("$v"); done \
        < <(docker volume ls -q --filter dangling=true 2>/dev/null)
    while IFS= read -r img; do [[ -n "$img" ]] && INV_IMG+=("$img"); done \
        < <(docker images -q --no-trunc --filter dangling=true 2>/dev/null)
    # older versions of those images (same name, another tag) that nothing runs
    # any more: risx's upgrades left them -- mssp-demo had three Timesketch ones
    if (( ${#INV_IMG[@]} )); then
        local -A repos=(); local ref
        while read -r ref; do [[ -n "$ref" ]] && repos[${ref%:*}]=1; done \
            < <(docker image inspect -f '{{range .RepoTags}}{{println .}}{{end}}' "${INV_IMG[@]}" 2>/dev/null)
        while IFS='|' read -r img ref; do
            [[ "$ref" != "<none>:<none>" && -n "${repos[${ref%:*}]:-}" ]] && INV_IMG+=("$img")
        done < <(docker images --no-trunc --format '{{.ID}}|{{.Repository}}:{{.Tag}}' 2>/dev/null)
    fi
    mapfile -t INV_CONT < <(printf '%s\n' "${INV_CONT[@]}" | grep . | sort -u)
    mapfile -t INV_VOL  < <(printf '%s\n' "${INV_VOL[@]}"  | grep . | sort -u)
    mapfile -t INV_NET  < <(printf '%s\n' "${INV_NET[@]}"  | grep . | sort -u)
    mapfile -t INV_IMG  < <(printf '%s\n' "${INV_IMG[@]}"  | grep . | sort -u)
    if (( ${#INV_IMG[@]} )); then
        INV_IMG_GB="$(docker image inspect -f '{{.Size}}' "${INV_IMG[@]}" 2>/dev/null \
                      | awk '{s+=$1} END {printf "%.1f", s/1024/1024/1024}')"
    fi
    # images nothing of risx uses: named, kept
    local -A risx_img=(); for img in "${INV_IMG[@]}"; do risx_img[$img]=1; done
    while IFS='|' read -r img name; do
        [[ -n "$img" && -z "${risx_img[$img]:-}" ]] && INV_KEEP+=("image $name")
    done < <(docker images --no-trunc --format '{{.ID}}|{{.Repository}}:{{.Tag}}' 2>/dev/null)
    # risx builds some images itself (velociraptor-tenroot, risx-mssp-*, elk-*):
    # their build cache stays behind (mssp-demo: 107 entries, 1.9 GB)
    INV_BUILD_CACHE="$(docker system df --format '{{.Type}}|{{.Size}}' 2>/dev/null | sed -n 's/^Build Cache|//p')"
    # MISP's installer adds a `docker exec misp-...` job to the crontab (and,
    # when the crontab was empty, a "# empty crontab" line)
    local who
    for who in user root; do
        while IFS= read -r f; do [[ -n "$f" ]] && INV_CRON+=("$who: $f"); done \
            < <(_crontab "$who" -l 2>/dev/null | grep -E 'docker exec misp|setup_platform|risx|^# empty crontab$' || true)
    done
    # risx's own files next to setup_platform: moved into the backup, never deleted
    local h; h="$(dirname "$RISX_ROOT")"
    for f in upgrade-scripts upgrade-scripts.zip dfiq .timesketchrc .timesketch.token; do
        [[ -e "$h/$f" ]] && RISX_HOME_LEFTOVERS+=("$h/$f")
    done
    for f in "$h"/*api.config.yaml; do [[ -f "$f" ]] && RISX_HOME_LEFTOVERS+=("$f"); done
    return 0
}
_crontab() { if [[ "$1" == root ]]; then shift; sudo crontab "$@"; else shift; crontab "$@"; fi; }

# _rm_listed KIND "inspect args" "rm args" ITEM... -- removes each item that
# still exists; what is still there afterwards goes into the caller's `left`,
# how many are gone into RM_GONE. Checked first: each stack's compose down
# already removed most of them, and removing them again put 48 "No such
# container/network" errors in the log that were no problem (mssp-demo, 2026-11-18).
# shellcheck disable=SC2086  # $insp and $rm are docker subcommands with options: split on purpose
_rm_listed() {
    local kind="$1" insp="$2" rm="$3" x; shift 3
    RM_GONE=0
    for x in "$@"; do
        docker $insp "$x" >/dev/null 2>&1 && { docker $rm "$x" 2>&1 | _ts >> "$LOG"; }
        if docker $insp "$x" >/dev/null 2>&1; then left+=("$kind $x"); else RM_GONE=$((RM_GONE + 1)); fi
    done
    return 0
}

# risx's installer clone, next to setup_platform. Its install moves the scripts
# out, so the clone keeps only setup_platform/workdir (mssp-demo, 2026-11-18).
risx_installer_clone() {
    local c; c="$(dirname "$RISX_ROOT")/Risx-MSSP"
    [[ -d "$c/setup_platform" ]] && echo "$c"
}

# One line per kind, for the pause and the log.
show_risx_inventory() {
    local stacks; stacks="$(printf '%s\n' "${INV_PROJ[@]}" | grep . | sort | paste -sd, - | sed 's/,/, /g')"
    echo "    ${#INV_PROJ[@]} compose stack(s): ${stacks:-none}"
    echo "    ${#INV_CONT[@]} container(s), ${#INV_VOL[@]} volume(s), ${#INV_NET[@]} network(s), ${#INV_IMG[@]} image(s) (${INV_IMG_GB} GB)$([[ -n "$INV_BUILD_CACHE" && "$INV_BUILD_CACHE" != 0B ]] && echo ", the build cache ($INV_BUILD_CACHE)")"
    echo "    the folders $RISX_ROOT$(c="$(risx_installer_clone)"; [[ -n "$c" ]] && echo " and $c")"
    if (( ${#INV_CRON[@]} )); then echo "    ${#INV_CRON[@]} cron line(s) of risx's:"; printf '      %s\n' "${INV_CRON[@]}"; fi
    if (( ${#RISX_HOME_LEFTOVERS[@]} )); then
        echo "  Moved into $BACKUP_DIR/risx-leftovers (not deleted): $(printf '%s\n' "${RISX_HOME_LEFTOVERS[@]##*/}" | paste -sd, - | sed 's/,/, /g')"
    fi
    if (( ${#INV_KEEP[@]} )); then
        echo "  Not risx's, so left alone:"; printf '    %s\n' "${INV_KEEP[@]}"
    fi
}

remove_risx_box() {
    step removed "7. Remove risx-mssp from this machine" || return 0
    [[ -s "$BACKUP_DIR/server.config.yaml" ]] || die "the backup is incomplete — refusing to remove risx"
    # A backup made by an older version of this script ("configuration only")
    # left the datastore in risx: move it now, before the removal deletes it.
    [[ -d "$DS" ]] || move_datastore
    [[ -d "$DS" ]] || die "the datastore is not in $DS — refusing to remove risx"
    risx_inventory
    { echo "risx inventory before the removal:"; show_risx_inventory
      printf 'container %s\n' "${INV_CONT[@]}"; printf 'volume %s\n' "${INV_VOL[@]}"
      printf 'network %s\n' "${INV_NET[@]}"; printf 'image %s\n' "${INV_IMG[@]}"; } | _ts >> "$LOG"
    # On screen, a line as each part finishes: "details in the log" and then
    # ~5 silent minutes looked stuck (mssp-demo, 2026-11-18). Docker's own
    # output goes to the log only.
    say "removing risx:"
    local d i=0 left=() line
    # 1. each stack by its own compose file: also what it declares and never started
    for d in "${INV_DIRS[@]}"; do
        printf '  stack %d/%d %s: ' $((++i)) "${#INV_DIRS[@]}" "$(basename "$d")"
        echo "== docker compose down in $d" | _ts >> "$LOG"
        if (cd "$d" && docker compose down --volumes --remove-orphans --timeout 20) 2>&1 | _ts >> "$LOG"
        then echo removed; else echo "docker compose down failed (the log says why)"; fi
    done
    # 2-5. whatever is left of the list, then cron lines and files
    _rm_listed container inspect "rm -f -v" "${INV_CONT[@]}"; line="  containers: $RM_GONE removed"
    _rm_listed volume "volume inspect" "volume rm -f" "${INV_VOL[@]}"; line+="   volumes: $RM_GONE"
    _rm_listed network "network inspect" "network rm" "${INV_NET[@]}"; echo "$line   networks: $RM_GONE"
    _rm_listed image "image inspect" "image rm -f" "${INV_IMG[@]}"; line="  images: $RM_GONE removed (${INV_IMG_GB} GB)"
    if docker builder prune -af 2>&1 | _ts >> "$LOG"; then echo "$line   build cache: cleared"
    else echo "$line   build cache: not cleared (the log says why)"; fi
    local who tmp cron=0 n
    for who in user root; do
        n="$(_crontab "$who" -l 2>/dev/null | grep -cE 'docker exec misp|setup_platform|risx|^# empty crontab$')"
        if (( n )); then
            tmp="$(mktemp)"; _crontab "$who" -l 2>/dev/null | grep -vE 'docker exec misp|setup_platform|risx|^# empty crontab$' > "$tmp"
            if _crontab "$who" "$tmp" 2>&1 | _ts >> "$LOG"; then cron=$((cron + n))
            else warn "could not remove risx's lines from the $who crontab"; fi
            rm -f "$tmp"
        fi
    done
    if (( ${#RISX_HOME_LEFTOVERS[@]} )); then
        mkdir -p "$BACKUP_DIR/risx-leftovers" && chmod 700 "$BACKUP_DIR/risx-leftovers"
        for d in "${RISX_HOME_LEFTOVERS[@]}"; do
            echo "moving $d into $BACKUP_DIR/risx-leftovers/" | _ts >> "$LOG"
            sudo mv "$d" "$BACKUP_DIR/risx-leftovers/" 2>&1 | _ts >> "$LOG" || true
        done
        sudo chown -R "$(id -un):$(id -gn)" "$BACKUP_DIR/risx-leftovers" 2>/dev/null
    fi
    local clone; clone="$(risx_installer_clone)"
    echo "deleting $RISX_ROOT${clone:+ and $clone}" | _ts >> "$LOG"
    sudo rm -rf "$RISX_ROOT" ${clone:+"$clone"} 2>&1 | _ts >> "$LOG" || true
    [[ -e "$RISX_ROOT" ]] && left+=("folder $RISX_ROOT")
    local gone=""
    for d in "$RISX_ROOT" ${clone:+"$clone"}; do [[ -e "$d" ]] || gone+="${gone:+, }$(basename "$d")"; done
    echo "  cron lines: $cron removed   folders deleted: ${gone:-none}"
    (( ${#RISX_HOME_LEFTOVERS[@]} )) && echo "  ${#RISX_HOME_LEFTOVERS[@]} loose risx files moved into $BACKUP_DIR/risx-leftovers"
    mark removed      # from here risx is gone even if the rest is interrupted
    if (( ${#left[@]} )); then
        warn "${#left[@]} thing(s) of risx could not be removed (the log lists why):"
        printf '    %s\n' "${left[@]:0:10}"
    else
        say "risx removed: ${#INV_PROJ[@]} stack(s), ${#INV_CONT[@]} container(s), ${#INV_VOL[@]} volume(s), ${#INV_NET[@]} network(s), ${#INV_IMG[@]} image(s) (${INV_IMG_GB} GB freed), its folders$( (( ${#INV_CRON[@]} )) && echo " and cron lines")"
    fi
    if (( ${#RISX_HOME_LEFTOVERS[@]} )); then say "moved into $BACKUP_DIR/risx-leftovers: $(printf '%s\n' "${RISX_HOME_LEFTOVERS[@]##*/}" | paste -sd, - | sed 's/,/, /g')"; fi
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
        local domain port velo_on mods weak lab=0
        { read -r domain; read -r port; read -r velo_on; read -r mods; read -r weak; } <<<"$summary"
        # Lab mode lets them through: the install's own rule (lib/secrets.sh), so
        # the two cannot disagree. QA's lab box was warned "the install refuses"
        # and the install then accepted them (2026-11-18).
        CONFIG_FILE="$CFG" secret_weak_allowed && lab=1
        echo
        echo "  ------- config summary -------"
        echo "  domain             : $domain"
        echo "  Velociraptor port  : $port"
        echo "  enabled modules    : ${mods:-none}"
        echo "  default passwords  : ${weak:-none}$( [[ -n "$weak" ]] && (( lab )) && echo '  (allowed: lab mode, allow_weak_passwords: true)')"
        echo "  ------------------------------"
        [[ "$domain" == "$ID_HOST" ]] || warn "domain $domain is NOT what the clients dial ($ID_HOST): every deployed client would be stranded"
        [[ "$port" == "$ID_PORT" ]] || warn "Velociraptor port $port is NOT the port the clients dial ($ID_PORT)"
        [[ -n "$weak" ]] && (( ! lab )) && warn "these modules have a publicly known password, which the install refuses — empty it: $weak"
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
    store_passwords
    mark config
}

# The install's password questions, asked here with the others rather than
# minutes into the unattended part. It is the installer's own step: each
# enabled tool whose password is empty in config.yaml is asked (type one, or
# Enter to generate), everything is stored under modules/<m>/secrets and
# config.yaml is blanked -- so install.sh later finds them stored and asks
# nothing. A refused password stops here, before anything changed.
store_passwords() {
    say "the tools' passwords: type one for each, or press Enter to have it generated (all are shown at the end)"
    # On a terminal the prompts go straight to it: Ubuntu's sudo (use_pty) sets
    # the terminal raw while its command runs, and through this script's log
    # pipe each prompt began where the last one ended (mssp-demo, 2026-11-18).
    # Its log_* lines then reach the log through LOG_FILE; without a terminal
    # they go to stdout, which is logged, so LOG_FILE=/dev/null (else twice).
    if { : > /dev/tty; } 2>/dev/null; then
        _store_passwords "$LOG" >/dev/tty 2>&1   # answers still from stdin
    else
        _store_passwords /dev/null
    fi || die "the passwords were not stored (see above) — fix config.yaml and run the script again; nothing has changed yet"
}
_store_passwords() {   # <LOG_FILE for the installer's log_* lines>
    sudo env SCRIPT_DIR="$ROOT" CONFIG_FILE="$CFG" LOG_FILE="$1" bash -c '
        for l in common secrets config state_registry; do
            source "$SCRIPT_DIR/lib/$l.sh" >/dev/null || exit 3
        done
        declare -F state_restore_missing >/dev/null && state_restore_missing "$SCRIPT_DIR" >/dev/null 2>&1
        ensure_module_credentials'
}

# What the steps after the removal need, checked while risx still runs: the
# old migrate_from_risx.sh found a missing piece only after it had deleted
# risx (QA, 2026-11-17). Runs again on a re-run until risx is removed.
check_ready() {
    done_step removed && return 0
    echo; say "=== 4. Checks === ($(date '+%F %T'))"
    local f
    for f in install.sh lib/secrets.sh scripts/adopt_velociraptor_identity.sh scripts/migrate/transform_config.py; do
        [[ -f "$ROOT/$f" ]] || die "this Intact checkout ($ROOT) has no $f — use a complete release, then re-run"
    done
    [[ -z "$PACKAGE" || -r "$PACKAGE" ]] || die "cannot read --package $PACKAGE"
    # Newer than Intact's own Velociraptor would be a downgrade: the older server
    # may not read the newer datastore. Stops here, before anything changed.
    local intact_velo
    intact_velo="$(python3 -c 'import sys,yaml; print(((yaml.safe_load(open(sys.argv[1])) or {}).get("versions") or {}).get("velociraptor") or "")' "$CFG" 2>/dev/null)"
    if [[ -n "$ID_VER" && -n "$intact_velo" && "$ID_VER" != "$intact_velo" \
          && "$(printf '%s\n' "$intact_velo" "$ID_VER" | sort -V | tail -1)" == "$ID_VER" ]]; then
        die "risx runs Velociraptor $ID_VER, newer than Intact's $intact_velo: its datastore may not be readable by the older server — use an Intact release with Velociraptor $ID_VER or newer"
    fi
    # Lab-verified client window (docs/RISX_MIGRATION.md): 0.6.9 and newer.
    if [[ -n "$ID_VER" && "$(printf '%s\n' 0.6.9 "$ID_VER" | sort -V | head -1)" != 0.6.9 ]]; then
        warn "risx runs Velociraptor $ID_VER, older than the tested 0.6.9: its clients may not reconnect (docs/RISX_MIGRATION.md, stepping-stone path)"
    fi
    local src="$VELO_DATA" kb root gb
    [[ -d "$DS" ]] && src="$DS"
    kb=$(ds_kb "$src"); kb="${kb:-0}"
    root="$(docker info -f '{{.DockerRootDir}}' 2>/dev/null)"; root="${root:-/var/lib/docker}"
    gb="$(df -B1G --output=avail "$root" 2>/dev/null | tail -1 | tr -d ' ')"
    echo "    checkout complete, risx's datastore $(_gb "$kb") GB, ${gb:-?} GB free for Docker"
    if [[ -n "$gb" ]]; then
        # Stop only below the history + 30 GB (the images alone are about 8 GB
        # packed, more unpacked); below the README's 100 GB it is a warning.
        (( gb * 1024 * 1024 >= kb + 30 * 1024 * 1024 )) \
            || die "not enough space under $root: the history ($((kb/1024)) MB) and Intact need at least 30 GB more, ${gb} GB free — free some, then re-run"
        if (( gb * 1024 * 1024 < kb + 100 * 1024 * 1024 )); then
            warn "Intact wants 100 GB free on top of the history (README); this box has ${gb} GB — going on"
        fi
    fi
}

install_intact() {
    step installed "8. Install Intact.AI" || return 0
    docker ps --format '{{.Names}}' 2>/dev/null | grep -qx intact_velociraptor \
        && say "Intact is already running here — install.sh runs again (it can be repeated)"
    say "running install.sh${PACKAGE:+ --package $PACKAGE} (this takes a while)"
    SHOW_LOGINS=1   # install.sh leaves them to this script's end
    # INTACT_REINIT=1: install.sh's "Re-initialize?" is answered here, not asked
    # half an hour after every other question.
    (cd "$ROOT" && sudo env INTACT_REINIT=1 INTACT_LOGINS_LATER=1 bash install.sh ${PACKAGE:+--package "$PACKAGE"}) \
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
    echo "  CA on this box now : $(live_fp || echo unreadable)"
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
    local want=0 folders=0 n=-1 last=-2 waited=0 out hosts
    if sudo test -d "$DS/clients"; then folders=$(sudo find "$DS/clients" -mindepth 1 -maxdepth 1 -type d -name 'C.*' | wc -l); fi
    # Compared with risx's own client list, not its folders: folders of clients
    # risx no longer listed stay behind with their history. mssp-demo had 12
    # folders and 4 listed clients, and "4 of the 12" read as a loss (2026-11-18).
    want=$(sudo cat "$DS/client_info/snapshot.json" 2>/dev/null \
           | grep -aoE '"client_id": ?"C\.[0-9a-f]+"' | sort -u | wc -l)
    (( want > 0 )) || want=$folders
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
    if (( folders > want )); then
        say "  $((folders - want)) more client folder(s) hold only history (clients risx itself no longer listed)"
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
    SHOW_LOGINS=1
    cat <<EOF

  Done. Next:
    - open https://${ID_HOST}/ and finish the first-login setup
    - a large fleet reconnects over minutes to hours; check that a collection reaches one client
    - ${BACKUP_DIR}/server.config.yaml is a plain copy of the fleet's CA key: delete it
      (shred -u) once you are satisfied$([[ -d "$DS" ]] && printf '; %s is the old datastore\n      (also holds the CA): keep it safe until you no longer need the history' "$DS")
EOF
    # step 7 deletes setup_platform; one left by an older version of this script
    local risx="${RISX_ROOT:-$(state_val risx_root)}"
    if [[ -n "$risx" && -d "$risx" ]]; then
        echo "    - $risx is risx's leftover: delete it (sudo rm -rf $risx)"
    fi
}

# --- main --------------------------------------------------------------------

if done_step verified; then say "this migration is already complete (see $STATE)"; exit 0; fi
docker ps >/dev/null 2>&1 || die "this user cannot run docker — add it to the docker group and log in again"
keep_sudo
ensure_yaml
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
if (( STOP_BEFORE_INSTALL )) && ! done_step installed; then
    say "stopped before the install (--stop-before-install): risx is removed and the backup is in $BACKUP_DIR"
    say "  run the script again without it to install Intact; it continues from step 8"
    exit 0
fi
install_intact; adopt; verify
