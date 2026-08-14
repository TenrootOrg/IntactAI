#!/bin/bash
# Intact.AI Platform Installer - Configuration Functions
# Config reading, validation, and env file updates

# ============================================================================
# Configuration Reading
# ============================================================================

check_config() {
    # config.yaml is the OPERATOR'S file and is deliberately not tracked in git
    # config.yaml is TRACKED. There is no config.yaml.example any more: the
    # pre-commit hook (scripts/git-hooks/sanitize-config-yaml.sh) rewrites the
    # STAGED copy back to shipping defaults on every commit -- empty
    # github_token, module passwords 123123, first_login: true -- so what is in
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
    log_success "Config file found"
}

# Read value from config.yaml
# Usage: value=$(read_config "['domain']")
read_config() {
    local key="$1"

    if [[ ! -f "$CONFIG_FILE" ]]; then
        echo ""
        return 1
    fi

    python3 -c "import yaml; print(yaml.safe_load(open('${CONFIG_FILE}'))${key})" 2>/dev/null || echo ""
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
#     file -- it carries their github_token, module passwords and the
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
    # Key absent: append at the end of the block, matching sibling indentation.
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

    # Velociraptor - update domain/IP and version
    local velo_enabled=$(read_config "['modules']['velociraptor']['enabled']")
    if is_enabled "$velo_enabled"; then
        local velo_env="${SCRIPT_DIR}/modules/velociraptor/.env"
        if [[ -f "$velo_env" ]]; then
            local velo_version=$(read_config "['versions']['velociraptor']")
            local velo_user=$(read_config "['modules']['velociraptor']['id']")
            local velo_pass=$(read_config "['modules']['velociraptor']['password']")
            local velo_api_user=$(read_config "['modules']['velociraptor']['api_id']")
            local velo_api_pass=$(read_config "['modules']['velociraptor']['api_password']")
            # Elasticsearch credentials (config.yaml modules.elk) — consumed by
            # the Custom.Elastic.Flows.Upload server artifact via environ(), so
            # the auto-upload keeps working now that Elasticsearch requires auth.
            local es_user=$(read_config "['modules']['elk']['id']")
            local es_pass=$(read_config "['modules']['elk']['password']")

            # Extract major.minor tag from version (e.g., "0.75.6" -> "0.75")
            local velo_tag=$(echo "$velo_version" | sed 's/^\([0-9]*\.[0-9]*\).*/\1/')
            update_env_var "$velo_env" "VELOCIRAPTOR_TAG" "$velo_tag"
            update_env_var "$velo_env" "VELOCIRAPTOR_VERSION" "$velo_version"
            update_env_var "$velo_env" "VELOX_USER" "$velo_user"
            update_env_var "$velo_env" "VELOX_PASSWORD" "$velo_pass"
            update_env_var "$velo_env" "VELOX_USER_2" "$velo_api_user"
            update_env_var "$velo_env" "VELOX_PASSWORD_2" "$velo_api_pass"
            update_env_var "$velo_env" "VELOX_FRONTEND_HOSTNAME" "$domain"
            update_env_var "$velo_env" "VELOX_PUBLIC_IP" "$domain"
            update_env_var "$velo_env" "VELOX_SERVER_URL" "https://${domain}:8000/"
            [[ -n "$es_user" && "$es_user" != "None" ]] && update_env_var "$velo_env" "ELASTIC_USER" "$es_user"
            [[ -n "$es_pass" && "$es_pass" != "None" ]] && update_env_var "$velo_env" "ELASTIC_PASSWORD" "$es_pass"
            log_success "Updated Velociraptor .env"
        else
            log_warn "Velociraptor .env not found, skipping"
        fi
    fi

    # TimeSketch - update version and credentials
    local ts_enabled=$(read_config "['modules']['timesketch']['enabled']")
    if is_enabled "$ts_enabled"; then
        local ts_env="${SCRIPT_DIR}/modules/timesketch/.env"
        if [[ -f "$ts_env" ]]; then
            local ts_version=$(read_config "['versions']['timesketch']")
            local ts_user=$(read_config "['modules']['timesketch']['id']")
            local ts_pass=$(read_config "['modules']['timesketch']['password']")

            update_env_var "$ts_env" "TIMESKETCH_VERSION" "$ts_version"
            update_env_var "$ts_env" "TIMESKETCH_USER" "$ts_user"
            update_env_var "$ts_env" "TIMESKETCH_PASSWORD" "$ts_pass"
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

    # ELK - update version and credentials
    local elk_enabled=$(read_config "['modules']['elk']['enabled']")
    if is_enabled "$elk_enabled"; then
        local elk_env="${SCRIPT_DIR}/modules/elk/.env"
        if [[ -f "$elk_env" ]]; then
            local elk_version=$(read_config "['versions']['elk']")
            local elk_user=$(read_config "['modules']['elk']['id']")
            local elk_pass=$(read_config "['modules']['elk']['password']")

            update_env_var "$elk_env" "ELASTIC_VERSION" "$elk_version"
            update_env_var "$elk_env" "KIBANA_VERSION" "$elk_version"
            update_env_var "$elk_env" "ELASTIC_USER" "$elk_user"
            update_env_var "$elk_env" "ELASTIC_PASSWORD" "$elk_pass"
            update_env_var "$elk_env" "KIBANA_PASSWORD" "$elk_pass"
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

    # Backend - update credentials and Plaso version
    local backend_env="${SCRIPT_DIR}/modules/backend/.env"
    if [[ -f "$backend_env" ]]; then
        local ts_user=$(read_config "['modules']['timesketch']['id']")
        local ts_pass=$(read_config "['modules']['timesketch']['password']")
        local es_user=$(read_config "['modules']['elk']['id']")
        local es_pass=$(read_config "['modules']['elk']['password']")
        local plaso_version=$(read_config "['versions']['plaso']")
        local cloudtrail_version=$(read_config "['versions']['aws_sigma']")
        local o365rc_version=$(read_config "['versions']['o365rc']")
        local tusd_version=$(read_config "['versions']['backend_tusd']")
        local backend_version=$(read_config "['versions']['backend']")

        update_env_var "$backend_env" "TIMESKETCH_USER" "$ts_user"
        update_env_var "$backend_env" "TIMESKETCH_PASS" "$ts_pass"
        [[ -n "$es_user" && "$es_user" != "None" ]] && update_env_var "$backend_env" "ELASTICSEARCH_USER" "$es_user"
        [[ -n "$es_pass" && "$es_pass" != "None" ]] && update_env_var "$backend_env" "ELASTICSEARCH_PASSWORD" "$es_pass"
        update_env_var "$backend_env" "PLASO_VERSION" "$plaso_version"
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
