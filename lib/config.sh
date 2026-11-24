#!/bin/bash
# Intact.AI Platform Installer - Configuration Functions
# Config reading, validation, and env file updates

# Module passwords (secret_get/secret_set/...). Sourced here and not only by
# install.sh because every entry point that touches credentials sources this
# file: scripts/upgrade.sh, change_ip.sh, show-credentials.sh.
declare -F secret_get >/dev/null || source "$(dirname "${BASH_SOURCE[0]}")/secrets.sh"

# ============================================================================
# Configuration Reading
# ============================================================================

check_config() {
    # config.yaml is TRACKED. There is no config.yaml.example any more: the
    # pre-commit hook (scripts/git-hooks/sanitize-config-yaml.sh) rewrites the
    # STAGED copy back to shipping defaults on every commit -- empty
    # github_token, empty module passwords, first_login: true -- so what is in
    # git is always the template while the operator's working file keeps their
    # real values. That means a clone or an extracted release already has a
    # config.yaml to edit before install, which the old seed-on-first-run dance
    # could not provide (it created the file and then immediately carried on,
    # so its own "review it before continuing" advice was impossible to follow).
    if [[ ! -f "$CONFIG_FILE" ]]; then
        log_error "Config file not found: $CONFIG_FILE"
        log_error "  config.yaml is tracked in git — a complete checkout or"
        log_error "  release package always contains one. Restore it with:"
        log_error "    git checkout -- config.yaml"
        exit 1
    fi

    # The shipped config.yaml carries a placeholder domain, because a tracked
    # file cannot ship a real one without imposing the last committer's IP on
    # every install. Stop here rather than build an appliance around it: domain
    # becomes the TLS certificate CN, the callback address compiled into every
    # Velociraptor client installer, and VolWeb's CSRF trusted origin, so a
    # wrong value does not fail here -- it fails days later as certificate
    # warnings and agents that never check in. Nothing prompts (install is
    # non-interactive), so this message is the only thing that makes an operator
    # aware the value is theirs to set.
    # Strict on INSTALL, advisory on UPGRADE. An install is about to bake this
    # value into certificates and client installers, so stopping costs nothing
    # and saves a rebuild. An upgrade of a box that somehow already carries the
    # placeholder is a box that is ALREADY misconfigured -- refusing it would
    # only withhold the fixes without repairing anything -- so it warns instead.
    # scripts/upgrade.sh sets INTACT_CONFIG_DOMAIN_SOFT before calling.
    local _domain
    _domain="$(read_config "['domain']" 2>/dev/null || echo '')"
    if [[ -z "$_domain" || "$_domain" == "None" || "$_domain" == "CHANGE-ME" ]]; then
        if [[ "${INTACT_CONFIG_DOMAIN_SOFT:-0}" == "1" ]]; then
            log_warn "config.yaml has the placeholder domain (${_domain:-unset})."
            log_warn "  This box's TLS certificate and Velociraptor client installers"
            log_warn "  are built from it, so they are almost certainly wrong. Fix with:"
            log_warn "    sudo bash scripts/change_ip.sh <ip-or-hostname>"
        else
            log_error "config.yaml still has the placeholder domain."
            log_error "  Set it to THIS box's IP or hostname before installing:"
            log_error "    domain: <ip-or-hostname>      # in ${CONFIG_FILE}"
            log_error ""
            log_error "  It is baked into the TLS certificate, the Velociraptor client"
            log_error "  installers and VolWeb's trusted origins, so it cannot be left"
            log_error "  as a default. To change it after an install, use:"
            log_error "    sudo bash scripts/change_ip.sh <new-ip>"
            exit 1
        fi
    fi

    # Public ports: refused on install (a bad one stops nginx or Velociraptor
    # from starting); on upgrade the ports already in the .env files are kept.
    local _port_errs _l
    if ! _port_errs="$(config_public_ports 2>&1 >/dev/null)"; then
        if [[ "${INTACT_CONFIG_DOMAIN_SOFT:-0}" == "1" ]]; then
            while IFS= read -r _l; do log_warn "config.yaml: $_l"; done <<< "$_port_errs"
            log_warn "  Keeping the ports already in use. Fix config.yaml, then run:"
            log_warn "    sudo bash scripts/change_ip.sh"
        else
            log_error "config.yaml has an unusable public port:"
            while IFS= read -r _l; do log_error "  $_l"; done <<< "$_port_errs"
            log_error "  Ports must be 1-65535, all different, and not 80/443/8080"
            log_error "  (the dashboard) or a port a module keeps on 127.0.0.1."
            exit 1
        fi
    fi

    log_success "Config file found"
}

# Public (browser- and agent-facing) host ports, set per module in config.yaml.
# Prints VAR=port for each one, a missing key meaning today's default so a box
# whose config predates the keys keeps its ports. Problems go to stderr and the
# call fails; callers must not write anything then.
config_public_ports() {
    python3 - "$CONFIG_FILE" <<'PYPORTS'
import sys, yaml
SPECS = [  # .env var, module, key, default
    ("KIBANA_PORT", "elk", "kibana_port", 5602),
    ("PORTAINER_PORT", "portainer", "port", 9444),
    ("IRIS_PORT", "iris", "port", 8444),
    ("TIMESKETCH_PORT", "timesketch", "port", 5443),
    ("VOLWEB_PORT", "volweb", "port", 8002),
    ("VELOX_AGENT_PORT", "velociraptor", "agent_port", 8000),
]
# A public bind on any of these collides with the dashboard or with a module's
# 127.0.0.1-only publish (0.0.0.0:N cannot bind while 127.0.0.1:N is held).
RESERVED = {80: "the dashboard", 443: "the dashboard", 8080: "the dashboard",
            9200: "Elasticsearch", 5601: "Kibana (box-only)", 5044: "Logstash",
            9600: "Logstash", 50000: "Logstash", 8443: "IRIS (box-only)",
            9443: "Portainer (box-only)", 5000: "Timesketch (box-only)",
            5001: "the backend", 8889: "the Velociraptor GUI", 8001: "the Velociraptor API"}
try:
    mods = (yaml.safe_load(open(sys.argv[1])) or {}).get("modules") or {}
except Exception as e:
    sys.exit(f"cannot read {sys.argv[1]}: {e}")
errs, seen = [], {}
for var, mod, key, default in SPECS:
    name, raw = f"modules.{mod}.{key}", (mods.get(mod) or {}).get(key)
    if raw is None:
        port = default
    elif isinstance(raw, int) and not isinstance(raw, bool):
        port = raw
    elif isinstance(raw, str) and raw.strip().isdigit():
        port = int(raw)
    else:
        port = None
    print(f"{var}={port if port is not None else raw}")
    if port is None or not 1 <= port <= 65535:
        errs.append(f"{name}: '{raw}' is not a port number (1-65535)")
    elif port in RESERVED:
        errs.append(f"{name}: {port} is already used by {RESERVED[port]}")
    elif port in seen:
        errs.append(f"{name}: {port} is also {seen[port]}")
    else:
        seen[port] = name
for e in errs:
    print(e, file=sys.stderr)
sys.exit(1 if errs else 0)
PYPORTS
}

# One public port by .env var name, for printed URLs (prints even when invalid).
public_port() { config_public_ports 2>/dev/null | sed -n "s/^$1=//p"; }

# Write the public ports into the .env files compose reads. nginx and
# Velociraptor listen on fixed container ports; only the host side moves.
write_public_port_env() {
    local lines var val
    lines="$(config_public_ports)" || return 1
    local nginx_env="${SCRIPT_DIR}/modules/nginx/.env"
    local velo_env="${SCRIPT_DIR}/modules/velociraptor/.env"
    [[ -f "$nginx_env" ]] || touch "$nginx_env"
    while IFS='=' read -r var val; do
        if [[ "$var" == VELOX_AGENT_PORT ]]; then
            [[ -f "$velo_env" ]] && update_env_var "$velo_env" "$var" "$val"
        else
            update_env_var "$nginx_env" "$var" "$val"
        fi
    done <<< "$lines"
    return 0
}

# Read value from config.yaml
# Usage: value=$(read_config "['domain']")
read_config() {
    local key="$1"

    if [[ ! -f "$CONFIG_FILE" ]]; then
        echo ""
        return 1
    fi

    # YAML null prints as '' -- never the string "None", which used to land in
    # .env files and, for a password, became the password.
    python3 -c "import yaml; v = yaml.safe_load(open('${CONFIG_FILE}'))${key}; print('' if v is None else v)" 2>/dev/null || echo ""
}

# ============================================================================
# Module credentials
# ============================================================================
# config.yaml is INPUT ONLY for module passwords: a value typed there is
# checked, stored under modules/<m>/secrets (see lib/secrets.sh) and blanked.
# The file is tracked in git and bind-mounted into the backend, so a password
# left in it is one `git commit -a` or one container compromise from public.

INTACT_CRED_MODULES=(elk timesketch velociraptor iris volweb portainer)

_cred_label() {
    case "$1" in
        elk) echo "Elasticsearch/Kibana" ;; timesketch) echo "Timesketch" ;;
        velociraptor) echo "Velociraptor" ;; iris) echo "IRIS" ;;
        volweb) echo "VolWeb" ;; portainer) echo "Portainer" ;;
    esac
}

# Login name: config.yaml `id`, else the name the tool's own code defaults to.
_cred_user() {
    local u; u="$(read_config "['modules']['$1']['id']")"
    if [[ -z "$u" ]]; then
        case "$1" in elk) u=elastic ;; iris) u=administrator ;; portainer) u=admin ;; *) u=tenroot ;; esac
    fi
    printf '%s' "$u"
}

# elk/timesketch/velociraptor keep theirs in creds.env (compose env_file).
# IRIS, VolWeb and Portainer keep their one-value files: their composes and
# consumers (IRIS's /run/secrets, volweb_client.py, --admin-password-file)
# already read exactly those paths.
_cred_key() {
    case "$1" in elk) echo ELASTIC_PASSWORD ;; timesketch) echo TIMESKETCH_PASSWORD ;; velociraptor) echo VELOX_PASSWORD ;; esac
}
_cred_file() {
    case "$1" in
        iris) echo "$(secret_dir iris)/IRIS_ADM_PASSWORD" ;;
        volweb) echo "$(secret_dir volweb)/ADMIN_PASSWORD" ;;
        portainer) echo "$(secret_dir portainer)/admin_password" ;;
    esac
}

# Portainer only reads its password file at FIRST start, so a Portainer with
# data whose password was lost gets a random file (the bind mount needs one)
# plus this empty marker: the file's value is NOT the admin password.
_cred_placeholder() { printf '%s.placeholder' "$(_cred_file "$1")"; }

# cred_get <module> -- the stored human password on stdout, or exit 1.
# "unknown" for a Portainer placeholder (see _cred_placeholder).
cred_get() {
    local k f
    k="$(_cred_key "$1")"
    if [[ -n "$k" ]]; then secret_get "$1" "$k"; return; fi
    f="$(_cred_file "$1")"
    [[ -n "$f" && -s "$f" ]] || return 1
    if [[ -e "$(_cred_placeholder "$1")" ]]; then printf 'unknown'; return 0; fi
    cat "$f"
}

_cred_put() {
    local m="$1" v="$2" k f d
    k="$(_cred_key "$m")"
    if [[ -n "$k" ]]; then secret_set "$m" "$k" "$v"; return; fi
    [[ -n "$v" ]] || return 1
    f="$(_cred_file "$m")"; d="${f%/*}"
    # readlink -m: a dangling secrets symlink (see secret_set) is recreated.
    { ( umask 077; mkdir -p "$(readlink -m "$d")" ) && chmod 700 "$d"; } || return 1
    # Truncate in place, never temp+mv: state_registry hard-links these files
    # into data/state, and a rename would split the link.
    ( umask 077; printf '%s' "$v" > "$f" ) || return 1
    # IRIS reads its file as uid 65534 through a compose file-secret bind mount:
    # 0644 inside the 0700 dir is readable there and by nobody else on the host
    # (proven with a throwaway iris_app container; see lib/permissions.sh).
    if [[ "$m" == iris ]]; then chmod 644 "$f"; else chmod 600 "$f"; fi
    # A real value replaces a placeholder.
    rm -f "$(_cred_placeholder "$m")"
}

# _cred_tool_has_data <module> -- 0 when the tool already holds a password
# that a newly minted one would NOT replace. Three tools are like that:
# Elasticsearch reads ELASTIC_PASSWORD on an empty data dir only, Portainer
# reads its password file at first start only. Velociraptor's entrypoint now
# re-applies a stored value that differs from its stamp, so a minted one would
# take effect there -- it stays listed so an old box keeps the password its
# operator knows (the legacy value) instead of silently getting a new one.
# The other three get the stored value re-applied
# on every install/upgrade (tsctl create-user, enforce_iris_admin_password,
# seed_volweb_admin), so a value minted for them always takes effect.
_cred_tool_has_data() {
    case "$1" in
        elk) ! secret_tool_is_new vol:elk_elasticsearch_data ;;
        portainer) ! secret_tool_is_new vol:portainer_portainer_data ;;
        velociraptor) ! secret_tool_is_new vol:velociraptor_velociraptor_datastore ;;
        *) return 1 ;;
    esac
}

# _config_password_raw <module> <key> -- the value exactly as typed. Not
# read_config: safe_load turns 0x1F2e... into an int, 1e10 into a float, yes
# into True and an empty value into None.
_config_password_raw() {
    python3 - "$CONFIG_FILE" "$1" "$2" 2>/dev/null <<'PYRAW'
import sys, yaml
try:
    d = yaml.load(open(sys.argv[1]), Loader=yaml.BaseLoader)
except Exception:
    sys.exit(0)
for k in ("modules", sys.argv[2], sys.argv[3]):
    d = d.get(k) if isinstance(d, dict) else None
if isinstance(d, str) and d not in ("~", "null", "Null", "NULL"):
    sys.stdout.write(d)
PYRAW
}

# _cred_legacy <module> -- the value a box from before the stores ran with:
# its live modules/<m>/.env, else config.yaml. Taken unchecked: it is what the
# tool's data already has, and refusing it locks the operator out.
_cred_legacy() {
    local v=""
    # Where a pre-change box kept the value its tool's data was created with.
    case "$1" in
        elk) v="$(sed -n 's/^ELASTIC_PASSWORD=//p' "${SCRIPT_DIR}/modules/elk/.env" 2>/dev/null | tail -1)" ;;
        velociraptor) v="$(sed -n 's/^VELOX_PASSWORD=//p' "${SCRIPT_DIR}/modules/velociraptor/.env" 2>/dev/null | tail -1)" ;;
    esac
    [[ -n "$v" ]] || v="$(_config_password_raw "$1" password)"
    [[ -n "$v" ]] && printf '%s' "$v"
}

# A seam for tests; an install with stdin from a pipe or /dev/null never asks.
_cred_have_tty() { [[ -t 0 ]]; }

# _cred_prompt <module> <user> -- typed (hidden, twice) or generated on Enter.
_cred_prompt() {
    local label a b reason
    label="$(_cred_label "$1")"
    while :; do
        read -r -s -p "Password for ${label} (${2}) — type one, or press Enter to generate: " a || a=""
        echo >&2
        if [[ -z "$a" ]]; then secret_generate; return 0; fi
        if ! reason="$(secret_check "$a")"; then
            echo "  Not accepted: ${reason}. Rule: ${INTACT_PASSWORD_RULE}" >&2
            continue
        fi
        read -r -s -p "Type it again: " b || b=""
        echo >&2
        if [[ "$a" == "$b" ]]; then printf '%s' "$a"; return 0; fi
        echo "  The two entries differ — try again." >&2
    done
}

# ensure_module_credentials [module...] -- every module (default: all six,
# enabled or not) ends up with a stored password and config.yaml with none.
# Runs before update_env_files, so before any container or image build.
#   stored         -> kept; a DIFFERENT config.yaml value stops the install
#                     (changing one is scripts/apply-passwords.sh's job)
#   tool has data  -> (no stored value) the old value from .env/config.yaml,
#                     else stop -- never mint one the tool would reject.
#                     Portainer is the exception: a placeholder, shown "unknown"
#   config.yaml    -> must pass secret_check, else stop
#   enabled + tty  -> asked, typed twice hidden, or generated on Enter
#   otherwise      -> generated
# Everything is resolved before anything is stored, so a refusal leaves the
# stores and config.yaml exactly as they were.
#
# With module arguments (generate_elk_secrets, create_timesketch_admin_user,
# ...) only those modules' config.yaml lines are blanked and no EXIT trap is
# armed: a deploy step for elk must not wipe a timesketch value the operator
# typed for scripts/apply-passwords.sh.
ensure_module_credentials() {
    local -a mods=("$@")
    local full=0
    (( ${#mods[@]} )) || { mods=("${INTACT_CRED_MODULES[@]}"); full=1; }
    local -A new=() placeholder=()
    local m stored cfg reason v enabled
    for m in "${mods[@]}"; do
        cfg="$(_config_password_raw "$m" password)"
        enabled="$(read_config "['modules']['$m']['enabled']")"
        if stored="$(cred_get "$m")"; then
            if [[ -n "$cfg" && "$cfg" != "$stored" ]]; then
                log_error "config.yaml modules.${m}.password: the $(_cred_label "$m") password is already set — to change it,"
                log_error "  keep the new value in config.yaml and run: sudo scripts/apply-passwords.sh"
                log_error "  (the current one: sudo scripts/show-credentials.sh)"
                return 1
            fi
            continue
        fi
        if _cred_tool_has_data "$m"; then
            if v="$(_cred_legacy "$m")"; then
                secret_is_known_default "$v" && ! secret_weak_allowed && \
                    log_warn "  $(_cred_label "$m") keeps the publicly known password its data was created with — change it in the tool"
                new[$m]="$v"
                continue
            fi
            if [[ "$m" == portainer ]]; then
                # Portainer ignores the file once it has data, so a random one is
                # harmless, and the rest of the box must not wait on Portainer.
                log_warn "  Portainer already has data but its admin password is not stored on this box — shown as \"unknown\"."
                log_warn "  Set it in the Portainer UI, then put that value in config.yaml and run: sudo scripts/apply-passwords.sh"
                new[$m]="$(secret_generate)"; placeholder[$m]=1
                continue
            fi
            if is_enabled "$enabled"; then
                local rel
                if [[ -n "$(_cred_key "$m")" ]]; then rel="secrets/creds.env"; else rel="secrets/$(basename "$(_cred_file "$m")")"; fi
                log_error "$(_cred_label "$m") already has data but its password is not stored anywhere on this box."
                log_error "  A new one would be refused by the existing data. Restore modules/${m}/${rel}"
                log_error "  (an upgraded box keeps a copy at data/state/${m}/${rel} — install.sh re-links it when present),"
                [[ "$m" == elk ]] && log_error "  or read ELASTIC_PASSWORD from: docker inspect intact_elasticsearch (older boxes passed it in the environment),"
                log_error "  or set modules.${m}.password in config.yaml to the password it was created with."
                return 1
            fi
            log_info "  ${m}: disabled, has old data and no stored password — left alone"
            continue
        fi
        if [[ -n "$cfg" ]]; then
            if ! reason="$(secret_check "$cfg")"; then
                log_error "config.yaml modules.${m}.password is not accepted: ${reason}."
                log_error "  Rule: ${INTACT_PASSWORD_RULE}."
                log_error "  Fix it, or blank it to be asked (or have one generated)."
                return 1
            fi
            new[$m]="$cfg"
        elif is_enabled "$enabled" && _cred_have_tty; then
            new[$m]="$(_cred_prompt "$m" "$(_cred_user "$m")")"
        else
            new[$m]="$(secret_generate)"
        fi
    done

    for m in "${!new[@]}"; do
        _cred_put "$m" "${new[$m]}" || { log_error "Could not store the ${m} password"; return 1; }
        if [[ -n "${placeholder[$m]:-}" ]]; then
            ( umask 077; : > "$(_cred_placeholder "$m")" ) || return 1
        fi
    done
    # Only now: every typed value is stored, so blanking (also on EXIT) can no
    # longer destroy the operator's only copy.
    (( full )) && _cred_arm_exit_blank
    # Machine-only companions nobody types or sees: kibana_system is re-set by
    # the elk setup container and Velociraptor's `api` user re-added by its
    # entrypoint on every start, so minting one when missing is always safe.
    for m in "${mods[@]}"; do
        case "$m" in
            elk) secret_get elk KIBANA_PASSWORD >/dev/null || secret_set elk KIBANA_PASSWORD "$(secret_generate)" || return 1 ;;
            velociraptor) secret_get velociraptor VELOX_PASSWORD_2 >/dev/null || secret_set velociraptor VELOX_PASSWORD_2 "$(secret_generate)" || return 1 ;;
        esac
    done
    (( ${#new[@]} )) && log_success "Module passwords stored under modules/<module>/secrets"
    if (( full )); then blank_config_passwords; else blank_config_passwords "${mods[@]}"; fi
}

# From the first stored value on, any exit blanks config.yaml -- an install
# aborted between storing and blanking must not leave typed passwords there.
# Chains whatever EXIT trap was already set (lib/deps.sh sets one).
_cred_arm_exit_blank() {
    [[ -n "${_CRED_EXIT_ARMED:-}" ]] && return 0
    _CRED_EXIT_ARMED=1
    _CRED_PREV_EXIT="$(trap -p EXIT)"
    trap '_cred_on_exit' EXIT
}
_cred_on_exit() {
    blank_config_passwords >/dev/null 2>&1 || true
    if [[ -n "${_CRED_PREV_EXIT:-}" ]]; then
        eval "set -- ${_CRED_PREV_EXIT#trap -- }"
        eval "$1"
    fi
}

# blank_config_passwords [module...] -- empty every modules.<m>.password /
# api_password in config.yaml (only those modules' when named). Same rules as
# _pin_module_version: a line edit (comments and key order kept) and
# truncate-in-place (the backend mounts the file by inode).
blank_config_passwords() {
    [[ -f "$CONFIG_FILE" ]] || return 0
    local out
    out="$(python3 - "$CONFIG_FILE" "$@" <<'PYBLANK'
import os, re, sys, tempfile
path = sys.argv[1]
only = set(sys.argv[2:])
with open(path, encoding="utf-8") as fh:
    lines = fh.readlines()
key = re.compile(r"^(\s+(?:password|api_password)\s*:[ \t]*)(.*?)(\r?\n?)\Z")

def split_value(rest):
    """(value, tail): tail is a trailing comment, kept as written."""
    if rest[:1] in ("'", '"'):
        q, i = rest[0], 1
        while i < len(rest):
            if q == '"' and rest[i] == "\\":
                i += 2
                continue
            if rest[i] == q:
                if q == "'" and rest[i + 1:i + 2] == "'":
                    i += 2
                    continue
                return rest[:i + 1], rest[i + 1:]
            i += 1
        return rest, ""
    m = re.search(r"\s#", rest)
    return (rest[:m.start()], rest[m.start():]) if m else (rest, "")

section = re.compile(r"^(\s+)([A-Za-z0-9_]+)\s*:\s*(#.*)?$")
in_modules = changed = False
mod = None
mod_indent = None
for i, line in enumerate(lines):
    if line[:1] not in (" ", "\t", "#", "\r", "\n", ""):      # a column-0 key
        in_modules = re.match(r"modules\s*:", line) is not None
        mod = mod_indent = None
        continue
    if not in_modules:
        continue
    s = section.match(line.rstrip("\r\n"))
    if s and (mod_indent is None or len(s.group(1)) <= mod_indent):
        mod, mod_indent = s.group(2), len(s.group(1))     # "  elk:"
        continue
    m = key.match(line)
    if not m or (only and mod not in only):
        continue
    value, tail = split_value(m.group(2))
    if value.strip() in ("", "''", '""'):
        continue
    lines[i] = m.group(1) + "''" + tail + m.group(3)
    changed = True

if changed:
    payload = "".join(lines)
    d = os.path.dirname(os.path.abspath(path)) or "."
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".config.yaml.blank-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(payload); fh.flush(); os.fsync(fh.fileno())
        with open(path, "w", encoding="utf-8") as fh:     # in place: keeps the inode
            fh.write(payload); fh.flush(); os.fsync(fh.fileno())
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass
    print("blanked")
PYBLANK
)" || { log_warn "Could not blank the module passwords in ${CONFIG_FILE} — blank them by hand"; return 1; }
    [[ "$out" == blanked ]] && log_info "  config.yaml: module passwords blanked (stored under modules/<module>/secrets)"
    return 0
}

# es_curl <curl args...> -- curl as Elasticsearch's user with the stored
# password fed through `-K -` (stdin), so it never sits in argv / ps.
es_curl() {
    local u p
    u="$(_cred_user elk)"
    p="$(cred_get elk 2>/dev/null)" || p=""
    p="${p//\\/\\\\}"; p="${p//\"/\\\"}"
    printf 'user = "%s:%s"\n' "$u" "$p" | curl -K - "$@"
}

# credential_lines [--enabled|--ids] -- "label|user|password" for every stored
# human login: input for secret_show_once. --enabled: enabled modules only;
# --ids: the module id instead of the label (scripts/show-credentials.sh, which
# QA parses). Velociraptor's `api` and kibana_system are machine-only and never
# listed.
credential_lines() {
    local m pw name
    for m in "${INTACT_CRED_MODULES[@]}"; do
        if [[ "${1:-}" == --enabled ]] && ! is_enabled "$(read_config "['modules']['$m']['enabled']")"; then
            continue
        fi
        pw="$(cred_get "$m")" || continue
        name="$(_cred_label "$m")"; [[ "${1:-}" == --ids ]] && name="$m"
        if [[ -e "$(_cred_placeholder "$m")" ]]; then
            # A 4th field: QA's parse_show_credentials skips non-3-field lines,
            # so "unknown" is never mistaken for a password to redact.
            printf '%s|%s|unknown|set it in the Portainer UI, then put that value in config.yaml and run sudo scripts/apply-passwords.sh\n' "$name" "$(_cred_user "$m")"
            continue
        fi
        printf '%s|%s|%s\n' "$name" "$(_cred_user "$m")" "$pw"
    done
}

# Point the backend container at the operator's OWN codex install.
#
# The appliance stopped installing and signing in to codex: the operator does
# that on the host, whichever way they like, and the backend just uses it. It
# runs in a container, so what it needs has to be bind-mounted in — and this
# works out where.
#
# THE RULE IS: MOUNT SOMETHING THAT DOES NOT MOVE WHEN THEY UPGRADE.
#
# Asking the shell where codex is (which is how a person would check) and
# mounting the answer is the obvious approach, and it is subtly wrong on its
# own: `codex` resolves to
#   ~/.codex/packages/standalone/releases/0.149.1-x86_64-unknown-linux-musl/bin/codex
# and mounting that directory pins the appliance to 0.149.1 — the next `codex
# upgrade` writes 0.150.0 beside it and the mount points at a version the
# operator no longer runs, silently, until someone re-runs this function.
#
# So three roots go in, and the two that matter carry no version at all:
#
#   ~/.codex          — the credential home. Exists for anyone who has ever run
#                       codex, and the official installer
#                       (curl https://chatgpt.com/codex/install.sh | sh) puts
#                       every release under it. Version-independent.
#   npm root -g       — where `npm i -g @openai/codex` puts the package, asked of
#                       npm rather than assumed, so a custom prefix or an nvm
#                       node still resolves. Version-independent.
#   the resolved root — whatever `command -v codex` actually points at, for an
#                       install in neither of those places. This is the one that
#                       CAN go stale, and it is the fallback, not the mechanism.
#
# Two things this must NOT do, both learned the hard way:
#   * never resolve through a "current" convenience symlink — the standalone
#     installer's is ABSOLUTE (/home/<them>/.codex/...), so inside the container
#     it points at nothing while the file sits right there under the mount;
#   * never read $HOME. This runs under sudo, so $HOME is /root and the
#     credential it would look for is the wrong user's every single time.
#
# A DASHBOARD UPGRADE RUNS THIS INSIDE THE BACKEND CONTAINER, where the
# operator's account does not exist and the host's /home is not mounted. It used
# to stamp the empty placeholder there -- on a box where codex worked, that
# REPLACED the good path, and codex vanished at the next recreate; on a box
# installed before codex, ~/.codex was never mounted, so installing codex the
# documented way was never seen ("codex still not visible", 2026-10-19). There,
# the home comes from the host's own /etc/passwd via docker (the socket is the
# one thing this container does reach), and nothing resolved replaces a real
# path stamped earlier.
_host_codex_home_via_docker() {
    local uid gid img home
    command -v docker >/dev/null 2>&1 || return 1
    uid="$(stat -c %u "$SCRIPT_DIR" 2>/dev/null)"; gid="$(stat -c %g "$SCRIPT_DIR" 2>/dev/null)"
    [[ -n "$uid" && "$uid" != 0 ]] || return 1
    img="$(docker inspect -f '{{.Config.Image}}' intact_backend 2>/dev/null)"
    [[ -n "$img" ]] || return 1
    home="$(docker run --rm --network none -v /etc/passwd:/hostpasswd:ro --entrypoint awk "$img" \
            -F: -v u="$uid" '$3 == u { print $6; exit }' /hostpasswd 2>/dev/null)"
    [[ "$home" == /* && "$home" != "/" ]] || return 1
    docker run --rm --network none -v "${home}:/h" --entrypoint sh "$img" \
        -c "mkdir -p /h/.codex && chown ${uid}:${gid} /h/.codex" >/dev/null 2>&1 || return 1
    echo "${home}/.codex"
}

_stamp_host_codex_paths() {
    local backend_env="$1" bin dir pkg npmroot home user

    mkdir -p "${SCRIPT_DIR}/data/agentic_cli/host-pkg" \
             "${SCRIPT_DIR}/data/agentic_cli/host-home" 2>/dev/null || true
    pkg="${SCRIPT_DIR}/data/agentic_cli/host-pkg"
    npmroot="${SCRIPT_DIR}/data/agentic_cli/host-pkg"

    # As the OPERATOR, not as root: a per-user install (~/.local/bin, nvm) is
    # not on root's PATH, and this runs under sudo.
    user="${SUDO_USER:-}"
    [[ -z "$user" ]] && user="$(stat -c '%U' "$SCRIPT_DIR" 2>/dev/null || true)"
    _as_operator() { su - "$user" -c "$1" 2>/dev/null || true; }

    bin="$(_as_operator 'command -v codex')"
    [[ -z "$bin" ]] && bin="$(command -v codex 2>/dev/null || true)"
    if [[ -n "$bin" ]]; then
        bin="$(readlink -f "$bin" 2>/dev/null || echo "$bin")"
        dir="$(dirname "$bin")"
        # <root>/bin/codex -> <root>; the helper binaries and codex-resources/
        # sit beside bin/, so mounting bin/ alone would leave them behind.
        [[ "$(basename "$dir")" == "bin" ]] && pkg="$(dirname "$dir")" || pkg="$dir"

        # THEN WALK UP OUT OF THE VERSION.
        #
        # The package root for a standalone install is
        #   ~/.codex/packages/standalone/releases/0.149.1-x86_64-unknown-linux-musl
        # and mounting THAT pins the appliance to 0.149.1 — measured: `codex
        # upgrade` writes 0.150.0 beside it and the box goes on running the old
        # one, silently, because the old binary is still there and still works.
        #
        # So climb while the last path component carries a version, and mount the
        # stable parent (…/releases). The versioned component is then resolved
        # inside the container at request time, where it can follow an upgrade
        # without anything being re-run out here. A path with no version in it
        # (/opt/codex, an npm vendor dir) is already stable and does not move.
        while [[ "$(basename "$pkg")" =~ [0-9]+\.[0-9]+ && "$pkg" != "/" ]]; do
            pkg="$(dirname "$pkg")"
        done
    fi

    # AN OPERATOR-DECLARED PATH BEATS ANYTHING DISCOVERED.
    #
    # Everything above is a heuristic run as one particular user, and no
    # heuristic covers every install: a shared /opt tree, a second account's
    # home, a custom prefix, a codex that is simply not on the PATH of the user
    # who owns the appliance directory. This is the escape hatch, and it is the
    # only thing that makes "any path" actually true — the container can see
    # exactly what compose mounted and not one byte more, so no amount of
    # searching on the inside can reach a directory nobody mounted.
    #
    # Point config.yaml's `agentic.codex_path` at the binary or at the directory
    # holding it; both shapes resolve inside the container.
    local override pkg_note="version stripped: an upgrade needs no re-stamp"
    override="$(read_config "['agentic']['codex_path']" 2>/dev/null || true)"
    if [[ -n "$override" && "$override" != "None" ]]; then
        if [[ -e "$override" ]]; then
            override="$(readlink -f "$override" 2>/dev/null || echo "$override")"
            if [[ -f "$override" ]]; then pkg="$(dirname "$override")"; else pkg="$override"; fi
            bin="$override"
            pkg_note="declared in config.yaml"
            log_info "  codex: agentic.codex_path overrides discovery -> ${pkg}"
        else
            log_warn "  codex: agentic.codex_path is set to '${override}' but nothing is there — ignoring it"
        fi
    fi

    local r
    r="$(_as_operator 'npm root -g')"
    [[ -d "$r" ]] && npmroot="$r"

    # ~/.codex holds BOTH the credential and every release the official
    # installer has ever fetched, and its path never changes across upgrades --
    # but it does not exist until codex is first installed. An appliance
    # installed BEFORE codex therefore stamped the empty placeholder here, and
    # nothing ever re-stamps afterwards: the operator then installed codex
    # exactly the documented way and the backend still could not see it, with
    # no error anywhere to say why. Create the directory (as them, so it is
    # theirs) and mount the real path even while it is empty — a later install
    # then lands inside a mount that is already there, and needs no re-stamp
    # and no container recreate to be found.
    home="$(getent passwd "$user" 2>/dev/null | cut -d: -f6)"
    if [[ -n "$home" && -d "$home" ]]; then
        [[ -d "${home}/.codex" ]] || _as_operator 'mkdir -p ~/.codex'
        [[ -d "${home}/.codex" ]] && home="${home}/.codex" || home=""
    else
        home="$(_host_codex_home_via_docker)" || home=""
    fi

    # Never downgrade: what could not be found from HERE keeps what was stamped
    # before (see _host_codex_home_via_docker for why "here" may be a container).
    local placeholder="${SCRIPT_DIR}/data/agentic_cli/" prev
    _keep_stamped() {
        prev="$(sed -n "s/^$1=//p" "$backend_env" 2>/dev/null | tail -1)"
        [[ -n "$prev" && "$prev" != "${placeholder}"* ]] && echo "$prev"
    }
    [[ -z "$home" ]] && home="$(_keep_stamped INTACT_HOST_CODEX_HOME)"
    [[ -z "$home" ]] && home="${SCRIPT_DIR}/data/agentic_cli/host-home"
    [[ "$pkg" == "${placeholder}"* ]] && prev="$(_keep_stamped INTACT_HOST_CODEX_PKG)" && pkg="$prev"
    [[ "$npmroot" == "${placeholder}"* ]] && prev="$(_keep_stamped INTACT_HOST_CODEX_NPM)" && npmroot="$prev"

    update_env_var "$backend_env" "INTACT_HOST_CODEX_PKG" "$pkg"
    update_env_var "$backend_env" "INTACT_HOST_CODEX_NPM" "$npmroot"
    update_env_var "$backend_env" "INTACT_HOST_CODEX_HOME" "$home"
    # No apostrophe inside ${bin:-...}: bash starts a quote on it even within a
    # double-quoted string, and the rest of the file parses as one long string.
    log_info "  codex (operator-installed): ${bin:-not found on the PATH}"
    log_info "    home=${home}   (version-independent)"
    log_info "    npm=${npmroot}  (version-independent)"
    log_info "    pkg=${pkg}  (${pkg_note})"
}

# Write a single pin into config.yaml's `versions:` block.
# Usage: _pin_module_version backend intact-20260810
#
# Called from update_env_files when the release package disagrees with the pin
# (see the long comment at the call site). It was referenced there for a long
# time without ever being defined anywhere in the repo -- and because neither
# install.sh nor lib/*.sh use `set -e`, the missing function printed
# "command not found" and the run carried on, so the write-back the call site
# describes silently never happened.
#
# Two properties this MUST have, both learned the hard way:
#
#   * Line-scan, never yaml.safe_load + dump. A round-trip through PyYAML
#     strips every comment and reorders keys, and config.yaml is the operator's
#     file -- it carries their github_token, ports and the
#     explanatory comments above half the pins.
#
#   * INODE-PRESERVING. config.yaml is bind-mounted into the backend BY INODE
#     (modules/backend/docker-compose.yaml: ../../config.yaml:/app/config.yaml).
#     Writing a temp file and `mv`-ing it over the original swaps the file out
#     from under the live mount: the edit lands on disk, the container keeps
#     reading the old inode, and the change looks applied while having no
#     effect. So: fsync a temp copy for durability, then truncate the REAL
#     file in place and write into it.
_pin_module_version() {
    local key="$1" value="$2"

    if [[ -z "$key" || -z "$value" ]]; then
        log_warn "_pin_module_version: refusing empty key/value ('${key}'/'${value}')"
        return 1
    fi
    if [[ ! -f "$CONFIG_FILE" ]]; then
        log_warn "_pin_module_version: ${CONFIG_FILE} not found"
        return 1
    fi

    if python3 - "$CONFIG_FILE" "$key" "$value" <<'PYPIN'
import os, re, sys, tempfile

path, key, value = sys.argv[1], sys.argv[2], sys.argv[3]

with open(path, "r", encoding="utf-8") as fh:
    lines = fh.readlines()

# Locate the top-level `versions:` block: from its header to the next line that
# starts in column 0 with something other than a comment.
start = None
for i, line in enumerate(lines):
    if re.match(r"^versions\s*:\s*$", line):
        start = i
        break
if start is None:
    sys.stderr.write("no top-level 'versions:' block in config.yaml\n")
    raise SystemExit(1)

end = len(lines)
for i in range(start + 1, len(lines)):
    stripped = lines[i].strip()
    if not stripped or stripped.startswith("#"):
        continue
    if not lines[i][:1].isspace():
        end = i
        break

# Preserve the operator's quoting style for this key if it already exists.
pat = re.compile(r"^(\s+)(" + re.escape(key) + r")(\s*:\s*)(.*?)(\s*)$")
for i in range(start + 1, end):
    m = pat.match(lines[i])
    if not m:
        continue
    indent, name, sep, old, _tail = m.groups()
    old = old.strip()
    if old.startswith("'") and old.endswith("'") and len(old) >= 2:
        new = "'%s'" % value.replace("'", "''")
    elif old.startswith('"') and old.endswith('"') and len(old) >= 2:
        new = '"%s"' % value.replace('"', '\\"')
    else:
        # Unquoted in the file. Quote only if the bare value would not survive
        # a YAML round-trip as a string (e.g. '9.4' would load as a float).
        new = value if re.match(r"^[A-Za-z][A-Za-z0-9._+-]*$", value) else "'%s'" % value
    if old == new:
        raise SystemExit(0)   # already correct; do not touch the file at all
    lines[i] = "%s%s%s%s\n" % (indent, name, sep, new)
    break
else:
    # Key absent. Two different situations wear the same clothes here:
    #
    #   * a genuinely NEW pin (a sidecar seeded for the first time, a module
    #     this config.yaml has never carried) -> the end of the block is the
    #     right home, and it is where every such key has always landed;
    #
    #   * a pin being PUT BACK after _unpin_module_version removed it -- the
    #     rollback path. Appending there moves the operator's key out of its
    #     slot, so an undo that is supposed to restore the file reformats it
    #     instead, and repeated rollbacks keep shuffling the block.
    #
    # Nothing in the file records where a removed key used to sit, but its
    # ORDERING does: the block opens with a run of plain, alphabetically
    # ordered module pins (elk, iris, plaso, portainer, timesketch,
    # velociraptor) before the commented, semantically grouped tail. If that
    # leading run is still sorted and the key belongs strictly inside its
    # range, sorted position IS the original position, and re-inserting there
    # restores the file byte-for-byte.
    #
    # Deliberately narrow -- STRICTLY inside the range, so a key outside it
    # (backend_tusd, dfiq, anything in the commented tail) still appends
    # exactly as before and first-time seeding is untouched. The cost of that
    # narrowness is the run's two endpoints: remove `elk` and the run now
    # starts at `iris`, so putting elk back is indistinguishable from adding a
    # brand-new key that happens to sort before iris, and it appends. Nothing
    # in the file separates those two cases, and appending a new key is the
    # behaviour that must not change, so the tie is broken that way on purpose.
    # No production path reaches it regardless: u_undo_pin re-pins only keys
    # that still EXIST (the in-place branch above, which never moves a line),
    # and unpins only keys that were absent before the run.
    indent = "  "
    for i in range(start + 1, end):
        m2 = re.match(r"^(\s+)\S", lines[i])
        if m2:
            indent = m2.group(1)
            break
    new = value if re.match(r"^[A-Za-z][A-Za-z0-9._+-]*$", value) else "'%s'" % value

    insert_at = end
    while insert_at > start + 1 and not lines[insert_at - 1].strip():
        insert_at -= 1

    # The leading run: plain "  name: value" lines, stopping at the first
    # comment (a comment introduces the annotated tail, and a key that follows
    # one belongs to it -- inserting there would orphan somebody's comment).
    run = []                                    # (line index, key name)
    for i in range(start + 1, end):
        stripped = lines[i].strip()
        if not stripped:
            continue
        if stripped.startswith("#"):
            break
        m3 = re.match(r"^\s+([A-Za-z_][A-Za-z0-9_]*)\s*:", lines[i])
        if not m3:
            break
        run.append((i, m3.group(1)))

    names = [n for _, n in run]
    if len(names) >= 2 and names == sorted(names) and names[0] < key < names[-1]:
        for i, n in run:
            if n > key:
                insert_at = i
                break

    lines.insert(insert_at, "%s%s: %s\n" % (indent, key, new))

payload = "".join(lines)

# Durability first: a complete, fsync'd copy exists on disk before the real
# file is truncated, so a crash mid-write leaves something to recover from.
d = os.path.dirname(os.path.abspath(path)) or "."
fd, tmp = tempfile.mkstemp(dir=d, prefix=".config.yaml.pin-")
try:
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(payload)
        fh.flush()
        os.fsync(fh.fileno())
    # Now truncate-in-place. NOT os.replace -- see the comment above.
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(payload)
        fh.flush()
        os.fsync(fh.fileno())
finally:
    try:
        os.unlink(tmp)
    except OSError:
        pass
PYPIN
    then
        log_info "  config.yaml: versions.${key} = ${value}"
        return 0
    fi

    log_warn "_pin_module_version: failed to set versions.${key} in ${CONFIG_FILE}"
    return 1
}

# _unpin_module_version <key>
#
# Remove versions.<key> from config.yaml entirely, so the file says "this module
# is not installed" rather than naming a version.
#
# Exists for rollback. A failed INSTALL that leaves its pin behind is worse than
# a cosmetic lie: the pin is what U_FROM reads, so the next attempt sees an
# installed version, plans an UPGRADE rather than an install, and every
# install-only branch stops firing. For timesketch that means the empty-alembic
# refusal triggers and the operator can never retry -- one failed install and
# the module is unreachable until someone hand-edits config.yaml.
#
# Absent key is success: this is an undo, and undoing a write that never landed
# is a no-op, not an error.
_unpin_module_version() {
    local key="$1"

    if [[ -z "$key" ]]; then
        log_warn "_unpin_module_version: refusing empty key"
        return 1
    fi
    if [[ ! -f "$CONFIG_FILE" ]]; then
        log_warn "_unpin_module_version: ${CONFIG_FILE} not found"
        return 1
    fi

    if python3 - "$CONFIG_FILE" "$key" <<'PYUNPIN'
import os, re, sys, tempfile

path, key = sys.argv[1], sys.argv[2]

with open(path, "r", encoding="utf-8") as fh:
    lines = fh.readlines()

start = None
for i, line in enumerate(lines):
    if re.match(r"^versions\s*:\s*$", line):
        start = i
        break
if start is None:
    sys.stderr.write("no top-level 'versions:' block in config.yaml\n")
    raise SystemExit(1)

end = len(lines)
for i in range(start + 1, len(lines)):
    stripped = lines[i].strip()
    if not stripped or stripped.startswith("#"):
        continue
    if not lines[i][:1].isspace():
        end = i
        break

pat = re.compile(r"^\s+" + re.escape(key) + r"\s*:")
for i in range(start + 1, end):
    if pat.match(lines[i]):
        del lines[i]
        break
else:
    raise SystemExit(0)          # nothing to undo

payload = "".join(lines)

# Same durability contract as _pin_module_version: a complete fsync'd copy
# exists before the real file is truncated, and the truncate is in-place rather
# than os.replace so the inode (and any bind-mount of it) survives.
d = os.path.dirname(os.path.abspath(path)) or "."
fd, tmp = tempfile.mkstemp(dir=d, prefix=".config.yaml.unpin-")
try:
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(payload)
        fh.flush()
        os.fsync(fh.fileno())
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(payload)
        fh.flush()
        os.fsync(fh.fileno())
finally:
    try:
        os.unlink(tmp)
    except OSError:
        pass
PYUNPIN
    then
        log_info "  config.yaml: removed versions.${key}"
        return 0
    fi

    log_warn "_unpin_module_version: failed to remove versions.${key} from ${CONFIG_FILE}"
    return 1
}

print_installation_config_summary() {
    log_info "=========================================="
    log_info "Installation configuration summary"
    log_info "=========================================="

    python3 - "$CONFIG_FILE" "$LOG_FILE" <<'PYCONFIG'
import sys
from datetime import datetime

import yaml

config_file, log_file = sys.argv[1], sys.argv[2]

with open(config_file, "r", encoding="utf-8") as fh:
    cfg = yaml.safe_load(fh) or {}


def truthy(value):
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in {"true", "yes", "1", "on"}


def emit(level, message):
    colors = {
        "INFO": "\033[0;34m",
        "SUCCESS": "\033[0;32m",
        "WARN": "\033[1;33m",
    }
    nc = "\033[0m"
    print(f"{colors.get(level, '')}[{level}]{nc} {message}")
    with open(log_file, "a", encoding="utf-8") as log:
        log.write(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] [{level}] {message}\n")


modules = cfg.get("modules") or {}
enabled = []
disabled = []

for name in sorted(modules):
    value = modules[name]
    if isinstance(value, dict):
        is_enabled = truthy(value.get("enabled", True))
    else:
        is_enabled = truthy(value)
    (enabled if is_enabled else disabled).append(name)

emit("INFO", f"Domain: {cfg.get('domain', 'not set')}")
emit("SUCCESS", f"Enabled modules ({len(enabled)}): {', '.join(enabled) if enabled else 'none'}")
emit("INFO", f"Disabled modules ({len(disabled)}): {', '.join(disabled) if disabled else 'none'}")

options = cfg.get("options") or {}

# NEVER print a secret's value here. This summary goes to stdout AND is teed
# into install_<ts>.log, which operators routinely attach to support tickets --
# .gitignore already warns those logs "have included a GitHub PAT", and this
# loop is how it got there. A token is only ever useful to confirm as
# "set / not set" plus enough of a tail to tell two tokens apart, so that is
# all we emit. Substring match, not an exact name list: a future
# `options.foo_token` or `options.api_secret` must be covered the day it is
# added, not the day someone remembers to update a list here.
SECRET_HINTS = ("token", "secret", "password", "passwd", "apikey", "api_key")


def redact(name, value):
    if not any(h in name.lower() for h in SECRET_HINTS):
        return value
    text = "" if value is None else str(value)
    if not text.strip():
        return "not set"
    # Last 4 chars only: enough to distinguish tokens in a support thread,
    # useless to anyone who intercepts the log.
    return f"set (…{text[-4:]}, {len(text)} chars)"


if options:
    emit("INFO", "Options:")
    for name in sorted(options):
        emit("INFO", f"  {name}: {redact(name, options[name])}")
PYCONFIG

    log_info "=========================================="
}

# ============================================================================
# Environment File Updates
# ============================================================================

# Update a single variable in an env file
# Usage: update_env_var "file" "VAR_NAME" "value"
update_env_var() {
    local env_file="$1"
    local var_name="$2"
    local var_value="$3"

    if [[ ! -f "$env_file" ]]; then
        log_warn "Env file not found: $env_file"
        return 1
    fi
    # An empty password in a .env is a password the tool then rejects (or, via
    # compose's own .env, one that overrides the real value from secrets/), and
    # "None" is read_config's old spelling of "not set". Neither is ever a value.
    if [[ "$var_value" == "None" || ( -z "$var_value" && "$var_name" == *PASSWORD* ) ]]; then
        log_warn "Refusing to write ${var_name}='${var_value}' to ${env_file}"
        return 1
    fi

    if grep -q "^${var_name}=" "$env_file"; then
        # ADD-ONLY MODE: leave an existing value exactly as it is.
        #
        # Set by the upgrade path (see _intact_add_missing_env_keys). An
        # upgrade must not rewrite .env values from config.yaml -- the pins in
        # there are what the engine itself is stamping module by module, and
        # overwriting them mid-run would tell plan_current_versions a module is
        # already at its target when it has not been touched yet. What an
        # upgrade DOES need is the keys a newer release added, which no box
        # gets today because update_env_files only ever runs from install.sh.
        [[ "${UPDATE_ENV_ADD_ONLY:-0}" == "1" ]] && return 0
        sed -i "s|^${var_name}=.*|${var_name}=${var_value}|" "$env_file"
    else
        # Variable doesn't exist, add it
        echo "${var_name}=${var_value}" >> "$env_file"
    fi
}

update_env_files() {
    log_info "Updating .env files from config.yaml..."

    local domain=$(read_config "['domain']")

    # Public ports first: VELOX_SERVER_URL below needs the agent port. An
    # unusable config keeps the ports the .env files already have.
    local agent_port
    if write_public_port_env; then
        agent_port="$(public_port VELOX_AGENT_PORT)"
        log_success "Updated public ports (modules/nginx/.env, modules/velociraptor/.env)"
    else
        log_warn "config.yaml has an unusable public port (above); keeping the current ones"
        agent_port="$(sed -n 's/^VELOX_AGENT_PORT=//p' "${SCRIPT_DIR}/modules/velociraptor/.env" 2>/dev/null | tail -1)"
    fi
    agent_port="${agent_port:-8000}"

    # Velociraptor - update domain/IP and version
    local velo_enabled=$(read_config "['modules']['velociraptor']['enabled']")
    if is_enabled "$velo_enabled"; then
        local velo_env="${SCRIPT_DIR}/modules/velociraptor/.env"
        if [[ -f "$velo_env" ]]; then
            local velo_version=$(read_config "['versions']['velociraptor']")
            local velo_user=$(read_config "['modules']['velociraptor']['id']")
            local velo_api_user=$(read_config "['modules']['velociraptor']['api_id']")
            # Elasticsearch user — consumed by the Custom.Elastic.Flows.Upload
            # server artifact via environ(). Passwords are NOT written here any
            # more: VELOX_PASSWORD(_2) and ELASTIC_PASSWORD reach the container
            # from modules/{velociraptor,elk}/secrets/creds.env (env_file), the
            # only copy on the box (see lib/secrets.sh).
            local es_user=$(read_config "['modules']['elk']['id']")

            # Extract major.minor tag from version (e.g., "0.75.6" -> "0.75")
            local velo_tag=$(echo "$velo_version" | sed 's/^\([0-9]*\.[0-9]*\).*/\1/')
            update_env_var "$velo_env" "VELOCIRAPTOR_TAG" "$velo_tag"
            update_env_var "$velo_env" "VELOCIRAPTOR_VERSION" "$velo_version"
            update_env_var "$velo_env" "VELOX_USER" "$velo_user"
            update_env_var "$velo_env" "VELOX_USER_2" "${velo_api_user:-api}"
            update_env_var "$velo_env" "VELOX_FRONTEND_HOSTNAME" "$domain"
            update_env_var "$velo_env" "VELOX_PUBLIC_IP" "$domain"
            update_env_var "$velo_env" "VELOX_SERVER_URL" "https://${domain}:${agent_port}/"
            [[ -n "$es_user" ]] && update_env_var "$velo_env" "ELASTIC_USER" "$es_user"
            log_success "Updated Velociraptor .env"
        else
            log_warn "Velociraptor .env not found, skipping"
        fi
    fi

    # TimeSketch - version and user (password: secrets/creds.env)
    local ts_enabled=$(read_config "['modules']['timesketch']['enabled']")
    if is_enabled "$ts_enabled"; then
        local ts_env="${SCRIPT_DIR}/modules/timesketch/.env"
        if [[ -f "$ts_env" ]]; then
            local ts_version=$(read_config "['versions']['timesketch']")
            local ts_user=$(read_config "['modules']['timesketch']['id']")

            update_env_var "$ts_env" "TIMESKETCH_VERSION" "$ts_version"
            update_env_var "$ts_env" "TIMESKETCH_USER" "$ts_user"
            log_success "Updated TimeSketch .env"
        else
            log_warn "TimeSketch .env not found, skipping"
        fi
    fi

    # IRIS - update version
    local iris_enabled=$(read_config "['modules']['iris']['enabled']")
    if is_enabled "$iris_enabled"; then
        local iris_env="${SCRIPT_DIR}/modules/iris/.env"
        if [[ -f "$iris_env" ]]; then
            local iris_version=$(read_config "['versions']['iris']")
            update_env_var "$iris_env" "IRIS_VERSION" "$iris_version"
            log_success "Updated IRIS .env"
        else
            log_warn "IRIS .env not found, skipping"
        fi
    fi

    # ELK - version and user (passwords: secrets/creds.env)
    local elk_enabled=$(read_config "['modules']['elk']['enabled']")
    if is_enabled "$elk_enabled"; then
        local elk_env="${SCRIPT_DIR}/modules/elk/.env"
        if [[ -f "$elk_env" ]]; then
            local elk_version=$(read_config "['versions']['elk']")
            local elk_user=$(read_config "['modules']['elk']['id']")

            update_env_var "$elk_env" "ELASTIC_VERSION" "$elk_version"
            update_env_var "$elk_env" "KIBANA_VERSION" "$elk_version"
            update_env_var "$elk_env" "ELASTIC_USER" "$elk_user"
            log_success "Updated ELK .env"
        else
            log_warn "ELK .env not found, skipping"
        fi
    fi

    # Portainer - update version
    local portainer_enabled=$(read_config "['modules']['portainer']['enabled']")
    if is_enabled "$portainer_enabled"; then
        local portainer_env="${SCRIPT_DIR}/modules/portainer/.env"
        if [[ -f "$portainer_env" ]]; then
            local portainer_version=$(read_config "['versions']['portainer']")
            update_env_var "$portainer_env" "PORTAINER_VERSION" "$portainer_version"
            # Portainer's own docs require the agent to run the SAME version
            # as the server — one config.yaml pin drives both (this was
            # previously only stamping the server's version, leaving the
            # agent permanently floating on the compose file's hardcoded
            # fallback regardless of what was pinned here).
            update_env_var "$portainer_env" "PORTAINER_AGENT_VERSION" "$portainer_version"
            log_success "Updated Portainer .env"
        else
            log_warn "Portainer .env not found, skipping"
        fi
    fi

    # Nginx reverse proxy - pin NGINX_VERSION (versions.nginx) into its .env so
    # the compose default (:-1.31.2-alpine) is overridden by the tracked pin. The
    # module ships no .env, so create it. Independent of timesketch's NGINX_VERSION
    # (different file / compose project).
    local nginx_env="${SCRIPT_DIR}/modules/nginx/.env"
    local nginx_version=$(read_config "['versions']['nginx']")
    if [[ -n "$nginx_version" && "$nginx_version" != "None" ]]; then
        [[ -f "$nginx_env" ]] || touch "$nginx_env"
        update_env_var "$nginx_env" "NGINX_VERSION" "$nginx_version"
        log_success "Updated Nginx .env (NGINX_VERSION=$nginx_version)"
    fi


    # Backend - service users and pins. The ES/Timesketch passwords reach the
    # backend from ../elk/secrets/creds.env and ../timesketch/secrets/creds.env
    # (compose env_file), never from this .env.
    local backend_env="${SCRIPT_DIR}/modules/backend/.env"
    if [[ -f "$backend_env" ]]; then
        local ts_user=$(read_config "['modules']['timesketch']['id']")
        local es_user=$(read_config "['modules']['elk']['id']")
        local plaso_version=$(read_config "['versions']['plaso']")
        local cloudtrail_version=$(read_config "['versions']['aws_sigma']")
        local o365rc_version=$(read_config "['versions']['o365rc']")
        local tusd_version=$(read_config "['versions']['backend_tusd']")
        local backend_version=$(read_config "['versions']['backend']")
        # Presidio PII NER image is run ON DEMAND by the backend (get_presidio_image),
        # so its pins live in the BACKEND .env, not a module .env — like PLASO_VERSION.
        local presidio_version=$(read_config "['versions']['presidio']")
        local presidio_model=$(read_config "['versions']['presidio_model']")

        update_env_var "$backend_env" "TIMESKETCH_USER" "$ts_user"
        [[ -n "$es_user" ]] && update_env_var "$backend_env" "ELASTICSEARCH_USER" "$es_user"
        update_env_var "$backend_env" "PLASO_VERSION" "$plaso_version"
        # Presidio on-demand image pins (versions.presidio / versions.presidio_model)
        # -> PRESIDIO_VERSION / PRESIDIO_MODEL in the backend .env, read by
        # config.get_presidio_image() and services/presidio_masker.py. Guarded so an
        # older config without the keys keeps the code defaults.
        [[ -n "$presidio_version" && "$presidio_version" != "None" ]] && update_env_var "$backend_env" "PRESIDIO_VERSION" "$presidio_version"
        [[ -n "$presidio_model" && "$presidio_model" != "None" ]] && update_env_var "$backend_env" "PRESIDIO_MODEL" "$presidio_model"
        # tusd sidecar pin (versions.backend_tusd) -> TUSD_VERSION in the backend
        # compose. Guarded so an older config without the key keeps the compose default.
        [[ -n "$tusd_version" && "$tusd_version" != "None" ]] && update_env_var "$backend_env" "TUSD_VERSION" "$tusd_version"
        # THE PACKAGE WINS OVER THE PIN. config.yaml versions.backend is only a
        # pin; the release package carries the image that was actually built
        # and tested. When they disagree the pin is stale, and trusting it is
        # what made a 20260804 install rebuild the backend from source:
        # VERSION said intact-20260804, config.yaml still said intact-20260803
        # (the release workflow stamps VERSION but not this key, and commits
        # after publish, so the tagged tree always trails by one), compose
        # could not find :intact-20260803, and `up -d` quietly rebuilt it from
        # source over ~380 lines of live PyPI + apt — impossible air-gapped,
        # and it replaced the tested image with an untested local build.
        #
        # The write-back to config.yaml is NOT cosmetic. app.py calls
        # self_heal_backend_swap() on EVERY backend boot, and that reads
        # config.yaml versions.backend (not .env) via backend_target_tag().
        # Correcting only .env would leave the two disagreeing, and the backend
        # would "self-heal" BACKWARD onto the stale tag — rebuilding from
        # source in-process, asynchronously, after the installer already
        # printed success. Fixing both is what makes the box converge.
        if [[ -n "${INTACT_PKG_BACKEND_TAG:-}" && "$INTACT_PKG_BACKEND_TAG" != "$backend_version" ]]; then
            log_warn "config.yaml versions.backend is '${backend_version}' but the release package"
            log_warn "  shipped intact-backend:${INTACT_PKG_BACKEND_TAG}. Using the package's tag and"
            log_warn "  correcting config.yaml — a stale pin makes compose rebuild from source."
            _pin_module_version backend "$INTACT_PKG_BACKEND_TAG"
            backend_version="$INTACT_PKG_BACKEND_TAG"
        fi
        # Wave F: backend image tag (versions.backend, e.g. a release id or
        # 'development') -> BACKEND_VERSION, so a fresh install BUILDS and tags
        # intact-backend:<that value> instead of relying on the compose :-1.0.0
        # default. Guarded so an old config without the key keeps the default.
        [[ -n "$backend_version" && "$backend_version" != "None" ]] && update_env_var "$backend_env" "BACKEND_VERSION" "$backend_version"
        # Wave F trap fix: INTACT_HOST_PATH was historically only a shell env var
        # exported by install.sh (never in .env) — `docker restart` preserves
        # mounts so it never mattered, but any container RECREATE resolves the
        # compose `:-` default, breaking non-default install paths silently.
        # Stamp it into .env so it survives every recreate, on every surface.
        update_env_var "$backend_env" "INTACT_HOST_PATH" "$SCRIPT_DIR"
        # Air-gapped or not, for the backend's own network fetches (the model
        # catalog, tool and Velociraptor downloads), which otherwise just time
        # out. Only install.sh decides it (parse_install_args always sets it):
        # change_ip.sh re-renders without it and keeps the box's value. The
        # upgrade's add-only pass is skipped too: upgrade.sh exports
        # INTACT_AIRGAP=1 for any --package run, and add-only would have
        # stamped it onto every ONLINE box imported from a package (reviewer,
        # 2026-11-24), silencing its catalog and tool downloads for good.
        [[ -n "${INTACT_AIRGAP:-}" && "${UPDATE_ENV_ADD_ONLY:-0}" != 1 ]] \
            && update_env_var "$backend_env" "INTACT_AIRGAP" "$INTACT_AIRGAP"
        _stamp_host_codex_paths "$backend_env"
        # AWS (CloudTrail SIGMA rule-pack) + Azure (DFIR-O365RC) versions — consumed
        # by the AWS/Azure detection pipelines + the module upgraders.
        [[ -n "$cloudtrail_version" ]] && update_env_var "$backend_env" "CLOUDTRAIL_VERSION" "$cloudtrail_version"
        [[ -n "$o365rc_version" ]] && update_env_var "$backend_env" "DFIR_O365RC_VERSION" "$o365rc_version"
        # GitHub token (options.github_token): authenticates the backend's
        # Online Upgrade / Prepare GitHub calls — 60/hr anonymous -> 5,000/hr.
        # Read-only-public token; see the full comment in config.yaml.
        local github_token=$(read_config "['options']['github_token']")
        if [[ -n "$github_token" && "$github_token" != "None" ]]; then
            update_env_var "$backend_env" "GITHUB_TOKEN" "$github_token"
            log_success "  GITHUB_TOKEN set in backend .env (authenticated GitHub API: 5,000 req/hr)"
        fi
        log_success "Updated Backend .env"
    else
        log_warn "Backend .env not found, skipping"
    fi
}

# ============================================================================
# Data Directory Setup
# ============================================================================

create_data_directory() {
    log_info "Creating data directory for SQLite database..."

    local data_dir="${SCRIPT_DIR}/data"

    # Create data directory if it doesn't exist
    if [[ ! -d "$data_dir" ]]; then
        mkdir -p "$data_dir"
        log_success "Created data directory: $data_dir"
    else
        log_info "Data directory already exists: $data_dir"
    fi

    # Create custom_artifacts directory for Velociraptor artifacts (ELK integration, etc.)
    local custom_artifacts_dir="${data_dir}/custom_artifacts"
    if [[ ! -d "$custom_artifacts_dir" ]]; then
        mkdir -p "$custom_artifacts_dir"
        log_success "Created custom_artifacts directory: $custom_artifacts_dir"
    fi

    # Set proper permissions (readable/writable by all)
    chmod 755 "$data_dir"
    chmod 755 "$custom_artifacts_dir"

    log_success "Data directory ready (SQLite database will be created on first startup)"
}
