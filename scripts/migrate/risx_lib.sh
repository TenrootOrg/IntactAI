#!/bin/bash
# risx_lib.sh — phase functions for the risx-mssp -> intact migration.
# Sourced by migrate_from_risx.sh; not meant to be executed directly.
#
# Design constraints (see docs/RISX_MIGRATION.md):
#  * The deployed Velociraptor clients pin the legacy CA + nonce and dial the
#    legacy server_urls. Those three things, plus the datastore, are the only
#    sacred state on the box. Everything else is rebuilt fresh by intact.
#  * The backup dir created in phase 1 is BOTH the seed source and the only
#    rollback artifact. It is never mutated (except in --datastore-mode bind,
#    where it deliberately becomes the live datastore).

MIG_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ---------------------------------------------------------------------------
# logging / prompting
# ---------------------------------------------------------------------------
c_red=$'\e[31m'; c_grn=$'\e[32m'; c_yel=$'\e[33m'; c_off=$'\e[0m'
say()  { echo "${c_grn}[migrate]${c_off} $*"; }
warn() { echo "${c_yel}[migrate] WARN:${c_off} $*"; }
die()  { echo "${c_red}[migrate] ERROR:${c_off} $*" >&2; exit 1; }

confirm() {  # confirm "question" -> returns 0 on yes
    local ans
    read -r -p "$1 [y/N] " ans
    [[ "$ans" == "y" || "$ans" == "Y" || "$ans" == "yes" ]]
}

# ---------------------------------------------------------------------------
# discovery
# ---------------------------------------------------------------------------
discover_risx() {
    # Sets: RISX_ROOT (setup_platform), VELO_DIR (compose dir), VELO_DATA
    # (the bind dir = config + datastore + filestore, all in one).
    # With $1=optional, returns 1 instead of dying when no install exists —
    # used to resume from a backup after risx was already removed.
    if [[ -n "${RISX_ROOT:-}" ]]; then
        [[ -d "$RISX_ROOT" ]] || die "RISX_ROOT=$RISX_ROOT does not exist"
    else
        local cands=(/home/*/setup_platform)
        local matches=()
        local c
        for c in "${cands[@]}"; do
            [[ -f "$c/workdir/velociraptor/velociraptor/server.config.yaml" ]] \
                && matches+=("$c")
        done
        if [[ ${#matches[@]} -eq 0 ]]; then
            [[ "${1:-}" == "optional" ]] && return 1
            die "no risx-mssp install found (looked for \
/home/*/setup_platform/workdir/velociraptor/velociraptor/server.config.yaml); \
set RISX_ROOT=... to point at it"
        fi
        if [[ ${#matches[@]} -gt 1 ]]; then
            die "multiple risx-mssp candidates found under /home/*/setup_platform \
(${matches[*]}) — refusing to guess which one is trusted; set RISX_ROOT=... \
after verifying the correct one yourself"
        fi
        RISX_ROOT="${matches[0]}"
        local owner
        owner="$(stat -c %U "$RISX_ROOT")" \
            || die "cannot stat $RISX_ROOT to verify ownership"
        if [[ "$owner" != "$(id -un)" && "$owner" != "root" ]]; then
            die "$RISX_ROOT is owned by '$owner', not by you ($(id -un)) or \
root — refusing to trust a risx-mssp install planted by another local user; \
verify it yourself and set RISX_ROOT=... to override"
        fi
    fi
    VELO_DIR="$RISX_ROOT/workdir/velociraptor"
    VELO_DATA="$VELO_DIR/velociraptor"
    [[ -f "$VELO_DATA/server.config.yaml" ]] \
        || die "no server.config.yaml under $VELO_DATA"
    say "risx-mssp found at $RISX_ROOT"
}

_yq() {  # _yq FILE 'python-ish key path e.g. Client.nonce'
    python3 - "$1" "$2" <<'PYEOF'
import sys, yaml
cfg = yaml.safe_load(open(sys.argv[1]))
node = cfg
for part in sys.argv[2].split('.'):
    node = (node or {}).get(part)
if isinstance(node, list):
    print(' '.join(str(x) for x in node))
elif node is not None:
    print(node)
PYEOF
}

ca_fingerprint() {  # sha256[:16] of CA.private_key (matches upgrade code's fp)
    python3 - "$1" <<'PYEOF'
import sys, yaml, hashlib
cfg = yaml.safe_load(open(sys.argv[1]))
key = (cfg.get('CA') or {}).get('private_key') or \
      (cfg.get('Client') or {}).get('ca_certificate') or ''
print(hashlib.sha256(key.encode()).hexdigest()[:16])
PYEOF
}

# ---------------------------------------------------------------------------
# phase 0 — preflight
# ---------------------------------------------------------------------------
preflight() {
    say "=== Phase 0: preflight ==="
    local scfg="$VELO_DATA/server.config.yaml"
    local ccfg="$VELO_DATA/client.config.yaml"

    LEGACY_VERSION="$(_yq "$scfg" version.version)"
    LEGACY_CA_FP="$(ca_fingerprint "$scfg")"
    LEGACY_NONCE="$(_yq "$scfg" Client.nonce)"
    LEGACY_URLS="$(_yq "${ccfg:-$scfg}" Client.server_urls)"
    [[ -n "$LEGACY_URLS" ]] || LEGACY_URLS="$(_yq "$scfg" Client.server_urls)"
    # the host every deployed client dials — intact's domain MUST equal it
    LEGACY_HOST="$(echo "$LEGACY_URLS" | sed -E 's#^[a-z]+://##; s#[:/].*##')"

    [[ -n "$LEGACY_NONCE" ]] || die "Client.nonce missing from $scfg — this \
config cannot preserve client trust; aborting"
    grep -q 'BEGIN RSA PRIVATE KEY\|BEGIN PRIVATE KEY' "$scfg" \
        || die "CA private key missing from $scfg"

    CLIENT_COUNT=$(find "$VELO_DATA/clients" -maxdepth 1 -name 'C.*' \
        2>/dev/null | sed 's/\.db$//' | sort -u | wc -l)
    LEGACY_FLOW_COUNT=$(find "$VELO_DATA/clients" -maxdepth 3 -type d \
        -path '*/collections/F.*' 2>/dev/null | wc -l)
    VELO_DU_KB=$(du -sk "$VELO_DATA" | cut -f1)
    local free_kb
    free_kb=$(df -k --output=avail "$(dirname "$RISX_ROOT")" | tail -1 | tr -d ' ')

    echo "  legacy velociraptor : ${LEGACY_VERSION:-unknown}"
    echo "  CA fingerprint      : $LEGACY_CA_FP"
    echo "  client nonce        : present"
    echo "  server_urls         : $LEGACY_URLS  (host: $LEGACY_HOST)"
    echo "  enrolled clients    : $CLIENT_COUNT"
    echo "  velo data size      : $((VELO_DU_KB / 1024)) MB"
    echo "  free disk           : $((free_kb / 1024)) MB"
    [[ -f "$VELO_DATA/server.config.yaml.bak" ]] \
        && echo "  note: server.config.yaml.bak exists (a frontend-cert" \
                "rotation ran at some point; the CA itself never rotates)"

    # fleet version histogram, best effort from datastore client records
    echo "  client agent versions (best effort):"
    python3 - "$VELO_DATA" <<'PYEOF' || echo "    (unreadable)"
import sys, os, json, glob, collections
root = sys.argv[1]
hist = collections.Counter()
for path in glob.glob(os.path.join(root, 'clients', 'C.*.db')) + \
            glob.glob(os.path.join(root, 'clients', 'C.*', '*.db')):
    try:
        with open(path) as f:
            data = json.load(f)
    except Exception:
        continue
    ver = ((data.get('agent_information') or {}).get('version')
           or data.get('agent_version'))
    if ver:
        hist[ver] += 1
if not hist:
    print("    unknown (no parseable client records)")
for ver, n in hist.most_common():
    print(f"    {ver}: {n}")
PYEOF

    # disk requirement: backup copy (1x) + datastore volume copy (1x) + slack
    local need_kb=$((VELO_DU_KB * 2 + VELO_DU_KB / 5))
    [[ "$DATASTORE_MODE" == "bind" ]] && need_kb=$((VELO_DU_KB + VELO_DU_KB / 5))
    if (( free_kb < need_kb )); then
        die "not enough free disk: need ~$((need_kb/1024)) MB \
(mode=$DATASTORE_MODE), have $((free_kb/1024)) MB. Consider \
--datastore-mode bind (needs only 1x)."
    fi

    # tiered compat verdict — see docs/RISX_MIGRATION.md for the lab results
    # Lab-verified 2026-07-26 (docs/RISX_MIGRATION.md): 0.6.9 / 0.7.0 /
    # 0.7.1 / 0.72.4 / 0.75.8 clients all enroll + interrogate + complete
    # collections against a 0.77.1 server.
    case "$LEGACY_VERSION" in
        0.7[2-9]*|0.7[2-9]) say "compat: GREEN — direct migration supported" ;;
        0.7.*|0.6.9*) warn "compat: YELLOW — old fleet (lab-verified against \
0.77.1); migrate, then run the fleet upgrade (phase 7) soon" ;;
        0.[0-6]*) if [[ "$FORCE" == "1" ]]; then
                    warn "compat: ORANGE (<0.6.9, untested) — proceeding due \
to --force; verify a canary client reconnects before walking away"
                else
                    die "compat: ORANGE — '$LEGACY_VERSION' is older than the \
lab-tested window (>=0.6.9). Re-run with --force, or use the stepping-stone \
path in docs/RISX_MIGRATION.md."
                fi ;;
        *)      warn "compat: UNKNOWN legacy version '$LEGACY_VERSION' — \
proceeding, but verify a canary client reconnects" ;;
    esac
}

# ---------------------------------------------------------------------------
# phase 1 — backup
# ---------------------------------------------------------------------------
graceful_stop_legacy_velo() {
    # Velociraptor keeps the fleet records — hostname, OS, agent version,
    # last seen — in an in-memory client_info cache that is flushed to
    # <datastore>/client_info/snapshot.json periodically and on a GRACEFUL
    # shutdown. The risx entrypoint starts the server as a CHILD of the shell
    # script (no exec), so `docker stop` sends SIGTERM to the shell and the
    # server is SIGKILLed when the grace period expires — snapshot never
    # written. Collections all survive either way, but the migrated GUI would
    # show an EMPTY fleet until every endpoint happens to re-enroll (which
    # only occurs when the client process restarts). So signal the server
    # itself and wait for the snapshot to land.
    docker ps --format '{{.Names}}' | grep -qx velociraptor || {
        say "legacy velociraptor container is not running"; return 0; }

    say "stopping legacy velociraptor gracefully (flushing the client_info \
snapshot so the fleet list survives the migration)"
    # the container restarts itself when the server exits — disable that first
    docker update --restart=no velociraptor >/dev/null 2>&1 || true
    # Match on /proc/<pid>/comm (the executable name) rather than the command
    # line: this helper's own shell carries the search words in its argv and
    # would otherwise match — and kill — itself instead of the server.
    local signalled
    signalled=$(docker exec velociraptor sh -c \
        'for p in $(ls /proc 2>/dev/null | grep -E "^[0-9]+$"); do
             [ "$p" = "$$" ] && continue
             case "$(cat /proc/$p/comm 2>/dev/null)" in
                 velociraptor*) kill -TERM "$p" && echo "$p" ;;
             esac
         done' 2>/dev/null) || true
    if [[ -z "$signalled" ]]; then
        warn "could not locate the velociraptor server process inside the \
container; falling back to docker stop"
    fi

    # Poll for the snapshot regardless of container state: the server writes
    # it during shutdown, and the container can disappear a moment BEFORE the
    # file lands — bailing out on container-exit alone reports a false miss.
    local t=0 gone=0
    while (( t < 120 )); do
        [[ -f "$VELO_DATA/client_info/snapshot.json" ]] && break
        if ! docker ps --format '{{.Names}}' | grep -qx velociraptor; then
            ((gone+=1))
            (( gone > 5 )) && break      # ~15s of grace after the exit
        fi
        sleep 3; ((t+=3))
    done
    docker stop velociraptor >/dev/null 2>&1 || true

    if [[ -f "$VELO_DATA/client_info/snapshot.json" ]]; then
        say "client_info snapshot flushed (${t}s) — the fleet list will \
appear in intact immediately"
    else
        warn "no client_info snapshot was written. All collections and client \
keys still migrate, but the fleet list in intact will start EMPTY and fill in \
as endpoints re-enroll (on client/service restart). See \
docs/RISX_MIGRATION.md."
    fi
}

backup_velo() {
    say "=== Phase 1: backup ==="
    BACKUP_DIR="${BACKUP_DIR:-$(dirname "$RISX_ROOT")/velo-migration-backup-$(date +%Y%m%d_%H%M%S)}"

    graceful_stop_legacy_velo

    say "copying $VELO_DATA -> $BACKUP_DIR/velociraptor (this may take a while)"
    mkdir -p "$BACKUP_DIR"
    # -a keeps ownership/perms; sudo because datastore files may be uid 0/1000
    sudo rsync -a "$VELO_DATA/" "$BACKUP_DIR/velociraptor/"
    for extra in "$RISX_ROOT/workdir/.env" "$VELO_DIR/.env" \
        "$RISX_ROOT/workdir/risx-mssp/backend/python-scripts/modules/Velociraptor/dependencies/api.config.yaml"; do
        [[ -f "$extra" ]] && sudo cp -a "$extra" \
            "$BACKUP_DIR/$(basename "$(dirname "$extra")").$(basename "$extra")"
    done
    sudo chown -R "$(id -u):$(id -g)" "$BACKUP_DIR"

    local src_n dst_n src_kb dst_kb
    src_n=$(sudo find "$VELO_DATA" -type f | wc -l)
    dst_n=$(find "$BACKUP_DIR/velociraptor" -type f | wc -l)
    src_kb=$(sudo du -sk "$VELO_DATA" | cut -f1)
    dst_kb=$(du -sk "$BACKUP_DIR/velociraptor" | cut -f1)
    echo "  files : src=$src_n backup=$dst_n"
    echo "  size  : src=$((src_kb/1024))MB backup=$((dst_kb/1024))MB"
    (( dst_n >= src_n )) || die "backup file count mismatch ($dst_n < $src_n) \
— NOT proceeding"
    say "backup complete: $BACKUP_DIR (keep it until you have verified the \
migration; delete it by hand later)"
}

# ---------------------------------------------------------------------------
# phase 2 — remove risx-mssp
# ---------------------------------------------------------------------------
remove_risx() {
    say "=== Phase 2: remove risx-mssp ==="
    echo "About to PERMANENTLY remove the risx-mssp platform:"
    echo "  - all compose stacks under $RISX_ROOT/workdir/"
    docker ps -a --format '  - container: {{.Names}} ({{.Image}})' \
        | grep -Ev 'intact_' || true
    echo "  - directory $RISX_ROOT ($(du -sh "$RISX_ROOT" 2>/dev/null | cut -f1))"
    echo "The Velociraptor backup at $BACKUP_DIR is kept."
    local ans
    read -r -p "Type REMOVE to continue: " ans
    [[ "$ans" == "REMOVE" ]] || die "aborted (you typed '$ans')"

    # re-verify the backup RIGHT before the destructive step
    [[ -f "$BACKUP_DIR/velociraptor/server.config.yaml" ]] \
        || die "backup vanished?! refusing to remove risx-mssp"
    local bkb; bkb=$(du -sk "$BACKUP_DIR/velociraptor" | cut -f1)
    (( bkb * 10 >= VELO_DU_KB * 9 )) \
        || die "backup smaller than expected ($((bkb/1024))MB vs \
$((VELO_DU_KB/1024))MB) — refusing to remove risx-mssp"

    local d
    for d in "$RISX_ROOT"/workdir/*/; do
        if compgen -G "$d/docker-compose.y*ml" >/dev/null; then
            say "  down: $(basename "$d")"
            # legacy datastore is a bind mount, not a volume, so --volumes
            # only removes throwaway named volumes (mysql etc.) — data we are
            # deliberately discarding. The velo backup is already safe.
            (cd "$d" && docker compose down --volumes --remove-orphans \
                --timeout 30 >/dev/null 2>&1) || true
        fi
    done
    docker network rm main_network >/dev/null 2>&1 || true
    docker image rm velociraptor-tenroot >/dev/null 2>&1 || true
    say "removing $RISX_ROOT"
    sudo rm -rf "$RISX_ROOT"
    say "risx-mssp removed"
}

# ---------------------------------------------------------------------------
# phase 3 — download intact
# ---------------------------------------------------------------------------
download_intact() {
    say "=== Phase 3: download intact ==="
    INTACT_DIR="${INTACT_DIR:-$HOME/intact}"

    if [[ -n "${FROM_DIR:-}" ]]; then
        [[ -f "$FROM_DIR/install.sh" ]] || die "--from-dir $FROM_DIR has no install.sh"
        if [[ "$FROM_DIR" != "$INTACT_DIR" ]]; then
            say "using pre-extracted tree $FROM_DIR -> $INTACT_DIR"
            cp -a "$FROM_DIR" "$INTACT_DIR"
        else
            say "using pre-extracted tree $INTACT_DIR"
        fi
        return
    fi

    [[ -e "$INTACT_DIR" ]] && die "$INTACT_DIR already exists — remove it or \
set INTACT_DIR=... elsewhere"

    local token="${GITHUB_TOKEN:-}"
    if [[ -z "$token" ]]; then
        read -r -s -p "GitHub token (repo read access to TenrootOrg/IntactAI): " token
        echo
    fi
    [[ -n "$token" ]] || die "a GitHub token is required to fetch intact"

    local tag="${RELEASE_TAG:-}"
    if [[ -z "$tag" ]]; then
        tag=$(curl -sf -H "Authorization: Bearer $token" \
            https://api.github.com/repos/TenrootOrg/IntactAI/releases/latest \
            | python3 -c 'import json,sys; print(json.load(sys.stdin)["tag_name"])') \
            || die "could not resolve the latest release (bad token?)"
    fi
    say "cloning intact release $tag -> $INTACT_DIR"
    git clone --depth 1 --branch "$tag" \
        "https://x-access-token:${token}@github.com/TenrootOrg/IntactAI.git" \
        "$INTACT_DIR" 2>&1 | grep -v x-access-token || true
    [[ -f "$INTACT_DIR/install.sh" ]] || die "clone failed"
    # do not leave the token inside .git/config
    git -C "$INTACT_DIR" remote set-url origin \
        "https://github.com/TenrootOrg/IntactAI.git"
}

# ---------------------------------------------------------------------------
# phase 4 — config.yaml edit with exit-guard
# ---------------------------------------------------------------------------
edit_config() {
    say "=== Phase 4: configure intact ==="
    local cfg="$INTACT_DIR/config.yaml"
    [[ -f "$cfg" ]] || die "$cfg not found"

    # pre-set the one value that must be right: domain = the host every
    # deployed client dials
    sed -i "s/^domain:.*/domain: $LEGACY_HOST/" "$cfg"
    say "pre-set domain: $LEGACY_HOST (from legacy server_urls)"

    while true; do
        say "opening config.yaml — set your modules and review the IP; save \
and exit when done"
        ${EDITOR:-nano} "$cfg"

        local domain modules
        domain=$(_yq "$cfg" domain)
        modules=$(python3 - "$cfg" <<'PYEOF'
import sys, yaml
cfg = yaml.safe_load(open(sys.argv[1]))
mods = cfg.get('modules') or {}
on = [k for k, v in mods.items()
      if not isinstance(v, dict) or v.get('enabled', True)]
print(', '.join(sorted(on)) or '(none)')
PYEOF
)
        echo
        echo "  ------- config summary -------"
        echo "  domain          : $domain"
        echo "  enabled modules : $modules"
        echo "  ------------------------------"
        if [[ "$domain" != "$LEGACY_HOST" ]]; then
            warn "domain ($domain) != the host your deployed clients dial \
($LEGACY_HOST). If you keep this, EVERY deployed client is stranded."
            confirm "Are you absolutely sure you want domain=$domain?" \
                || { say "re-opening editor"; continue; }
        fi
        if ! echo ",$modules," | grep -q ',velociraptor,'; then
            warn "velociraptor module is DISABLED — the migration is \
pointless without it"
            say "re-opening editor"; continue
        fi
        local ans
        read -r -p "Proceed with this configuration? [p]roceed / [e]dit again / [a]bort: " ans
        case "$ans" in
            p|P|proceed) INTACT_DOMAIN="$domain"; break ;;
            a|A|abort)   die "aborted at configuration review" ;;
            *)           say "re-opening editor" ;;
        esac
    done
}

# ---------------------------------------------------------------------------
# phase 5 — seed the transplant, then install
# ---------------------------------------------------------------------------
_helper_image() {
    local img
    for img in alpine ubuntu:22.04 busybox; do
        docker image inspect "$img" >/dev/null 2>&1 && { echo "$img"; return; }
    done
    docker pull alpine >/dev/null 2>&1 && { echo alpine; return; }
    die "no helper image (alpine/ubuntu) available to populate the datastore volume"
}

seed_and_install() {
    say "=== Phase 5: transplant + install ==="
    local seed_cfg="$INTACT_DIR/data/velociraptor/server.config.yaml"
    mkdir -p "$INTACT_DIR/data/velociraptor"

    python3 "$MIG_LIB_DIR/transform_config.py" \
        "$BACKUP_DIR/velociraptor/server.config.yaml" "$seed_cfg" \
        --domain "$INTACT_DOMAIN" \
        || die "config transform failed — nothing was installed"
    chmod 0600 "$seed_cfg"

    # datastore volume, named exactly as compose will expect it
    # (project 'velociraptor' from modules/velociraptor + volume
    # 'velociraptor_datastore'), labeled so compose adopts it silently.
    local vol=velociraptor_velociraptor_datastore
    if docker volume inspect "$vol" >/dev/null 2>&1; then
        die "volume $vol already exists — an intact velociraptor was \
installed here before. Remove it first (docker volume rm $vol) if you are \
sure, then re-run."
    fi
    docker volume create \
        --label com.docker.compose.project=velociraptor \
        --label com.docker.compose.volume=velociraptor_datastore \
        --label com.docker.compose.version=2.0.0 \
        "$vol" >/dev/null

    if [[ "$DATASTORE_MODE" == "bind" ]]; then
        docker volume rm "$vol" >/dev/null
        docker volume create \
            --label com.docker.compose.project=velociraptor \
            --label com.docker.compose.volume=velociraptor_datastore \
            --label com.docker.compose.version=2.0.0 \
            -o type=none -o o=bind -o device="$BACKUP_DIR/velociraptor" \
            "$vol" >/dev/null
        warn "bind mode: $BACKUP_DIR/velociraptor IS the live datastore now \
(no isolated rollback copy)"
    else
        say "copying datastore into volume $vol \
($((VELO_DU_KB/1024)) MB — this is the long step)"
        local helper; helper=$(_helper_image)
        # Exclusions: identity/config files live in data/velociraptor, not in
        # the datastore; clients/{linux,mac,windows} are repacked BINARIES that
        # happen to share the datastore's clients/ namespace; the binary and
        # .env are legacy runtime, not data.
        tar -C "$BACKUP_DIR/velociraptor" \
            --exclude='./server.config.yaml*' \
            --exclude='./client.config.yaml' \
            --exclude='./api.config.yaml' \
            --exclude='./velociraptor' \
            --exclude='./clients/linux' \
            --exclude='./clients/mac' \
            --exclude='./clients/windows' \
            --exclude='./.env' \
            -cf - . | docker run --rm -i -v "$vol":/var. "$helper" \
                tar -C /var. -xf -
        say "datastore volume populated"
    fi

    say "running intact install.sh (velociraptor will adopt the transplanted \
identity instead of generating a new one)"
    (cd "$INTACT_DIR" && sudo -E bash install.sh) \
        || die "install.sh failed — check $INTACT_DIR/install_*.log. The \
backup at $BACKUP_DIR is untouched; fix and re-run."
}

# ---------------------------------------------------------------------------
# phase 6 — verify
# ---------------------------------------------------------------------------
verify_migration() {
    say "=== Phase 6: verify ==="
    local fail=0
    local live_fp; live_fp=$(ca_fingerprint "$INTACT_DIR/data/velociraptor/server.config.yaml")
    if [[ "$live_fp" == "$LEGACY_CA_FP" ]]; then
        say "CA fingerprint preserved: $live_fp"
    else
        warn "CA fingerprint CHANGED ($LEGACY_CA_FP -> $live_fp) — clients \
will NOT trust this server"; fail=1
    fi

    # api.config.yaml must be signed by the transplanted CA (the entrypoint
    # re-issues it on boot, but silently — || true — so check, don't assume)
    if docker exec intact_velociraptor sh -c \
        'test -f /velociraptor/api.config.yaml' 2>/dev/null; then
        local api_ca_ok
        api_ca_ok=$(docker exec intact_velociraptor cat /velociraptor/api.config.yaml \
            | python3 -c '
import sys, yaml, hashlib
api = yaml.safe_load(sys.stdin)
srv = yaml.safe_load(open(sys.argv[1]))
print("ok" if api.get("ca_certificate","").strip()
      == (srv.get("Client") or {}).get("ca_certificate","").strip() else "STALE")' \
            "$INTACT_DIR/data/velociraptor/server.config.yaml")
        if [[ "$api_ca_ok" == "ok" ]]; then
            say "api.config.yaml re-issued from the transplanted CA"
        else
            warn "api.config.yaml is signed by a DIFFERENT CA — backend gRPC \
will fail. Try: docker restart intact_velociraptor"; fail=1
        fi
    else
        warn "api.config.yaml missing in the container"; fail=1
    fi

    # client.config.yaml must carry the legacy nonce + server_urls (content,
    # not existence — generate_clients.sh only checks existence)
    local ccfg; ccfg=$(docker exec intact_velociraptor cat /velociraptor/client.config.yaml 2>/dev/null)
    if echo "$ccfg" | grep -qF "$LEGACY_NONCE" \
        && echo "$ccfg" | grep -qF "$LEGACY_HOST"; then
        say "client.config.yaml carries the legacy nonce + endpoint"
    else
        warn "client.config.yaml does NOT match the legacy identity"; fail=1
    fi

    # datastore visible: client record count
    local n
    n=$(docker exec intact_velociraptor sh -c \
        'ls /var./clients 2>/dev/null | grep -c "^C\."' || echo 0)
    if (( n >= CLIENT_COUNT && CLIENT_COUNT > 0 )); then
        say "datastore transplanted: $n client records (expected $CLIENT_COUNT)"
    elif (( CLIENT_COUNT == 0 )); then
        say "datastore transplanted ($n client records; legacy had none)"
    else
        warn "client records: $n found, expected $CLIENT_COUNT"; fail=1
    fi

    # history: at least one legacy collection must still be on disk
    local flows
    flows=$(docker exec intact_velociraptor sh -c \
        'ls -d /var./clients/C.*/collections/F.* 2>/dev/null | wc -l' || echo 0)
    if (( flows > 0 )); then
        say "historical collections preserved: $flows flow(s) on disk"
    elif (( LEGACY_FLOW_COUNT > 0 )); then
        warn "no historical collections found (legacy had $LEGACY_FLOW_COUNT)"
        fail=1
    else
        say "no historical collections to migrate (legacy had none)"
    fi

    # backend round-trip over gRPC with the fresh api cert
    if docker ps --format '{{.Names}}' | grep -qx intact_backend; then
        docker restart intact_backend >/dev/null
        say "waiting for backend..."
        local i; for i in $(seq 1 30); do
            docker exec intact_backend true 2>/dev/null && break; sleep 2
        done
        sleep 8
        local rt
        rt=$(docker exec intact_backend python3 -c '
from services.velociraptor_service import setup_velociraptor_connection
from pyvelociraptor import api_pb2, api_pb2_grpc
import grpc, json
ch = setup_velociraptor_connection()
stub = api_pb2_grpc.APIStub(ch)
req = api_pb2.VQLCollectorArgs(max_wait=5, Query=[api_pb2.VQLRequest(
    Name="mig", VQL="SELECT client_id FROM clients() LIMIT 5")])
rows = []
for resp in stub.Query(req):
    if resp.Response:
        rows += json.loads(resp.Response)
print(len(rows))' 2>/dev/null | tail -1)
        if [[ "$rt" =~ ^[0-9]+$ ]] && (( rt > 0 || CLIENT_COUNT == 0 )); then
            say "backend gRPC round-trip OK (clients() returned $rt rows)"
        else
            warn "backend could not query velociraptor over gRPC"; fail=1
        fi
    else
        warn "intact_backend is not running — skipping the gRPC round-trip"
    fi

    (( fail == 0 )) || die "verification FAILED — the legacy backup at \
$BACKUP_DIR is intact; fix the reported problem and re-run (phases are \
idempotent: existing backup is reused)."

    # live reconnection — informational, clients poll on their own schedule
    say "waiting up to 5 minutes for a deployed client to reconnect..."
    local t=0 seen=""
    while (( t < 300 )); do
        seen=$(docker exec intact_backend python3 -c '
from services.velociraptor_service import setup_velociraptor_connection
from pyvelociraptor import api_pb2, api_pb2_grpc
import json
ch = setup_velociraptor_connection()
stub = api_pb2_grpc.APIStub(ch)
req = api_pb2.VQLCollectorArgs(max_wait=5, Query=[api_pb2.VQLRequest(
    Name="mig", VQL="SELECT client_id FROM clients() WHERE last_seen_at > (now() - 300) * 1000000 LIMIT 1")])
rows = []
for resp in stub.Query(req):
    if resp.Response:
        rows += json.loads(resp.Response)
print(rows[0]["client_id"] if rows else "")' 2>/dev/null | tail -1)
        [[ -n "$seen" ]] && break
        sleep 15; ((t+=15))
    done
    if [[ -n "$seen" ]]; then
        say "LIVE: client $seen reconnected with its original client_id 🎉"
    else
        warn "no client reconnected within 5 min — normal if endpoints poll \
slowly or are offline; watch the GUI. Trust chain checks all passed."
    fi
}

# ---------------------------------------------------------------------------
# phase 7 — optional fleet upgrade
# ---------------------------------------------------------------------------
fleet_upgrade_hint() {
    say "=== Phase 7: fleet client upgrade (optional) ==="
    cat <<'EOF'
Deployed clients still run the legacy binary. To upgrade them THROUGH the new
server (no endpoint touch; client_id and writeback survive):
  1. GUI -> Hunts -> New hunt -> artifact 'Admin.Client.Upgrade'
     (Windows) / 'Admin.Client.Upgrade.Linux' — set the version to the
     server's own (0.77.x).
  2. Start with a hunt limited to one label/canary host; confirm it comes
     back on the new version; then widen to the fleet.
Air-gapped fleets: point the artifact's tool at this server's own installers
(Server Artifacts -> tools) instead of GitHub.
EOF
}
