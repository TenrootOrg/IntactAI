#!/bin/bash
# Intact.AI — module passwords: generate, check, store, show once.
#
# WHERE THEY LIVE. Each module's passwords are in ONE private file,
# modules/<module>/secrets/creds.env (0600 inside a 0700 dir, gitignored). That
# file is the only copy on the box: compose loads it with env_file, so nothing
# else has to be kept in step with it. config.yaml is input only -- whatever
# the operator typed there is moved here and blanked. The tracked modules/*/.env
# files keep version pins and other non-secrets; a real password in a tracked
# file is one `git commit -a` away from the public repo.
#
# WHY "GENERATE ONLY WHEN THE TOOL IS NEW". Every tool takes its password at
# first start and keeps only a hash (Elasticsearch on an empty data dir,
# Velociraptor's `user add`, IRIS at DB init, Portainer's password file).
# Minting a new password for a tool whose data already exists produces a
# password the tool will never accept, and the operator is locked out of their
# own evidence. secret_tool_is_new is the guard for that.
#
# Values never go to the install log, to stdout, or into a command line: the
# generated ones are letters and digits only, so they are also safe in .env,
# YAML, shell and URLs, and exact enough to redact.

# Publicly known values -- in this repo or its history. Refused when typed; an
# old box still running one is rotated by that module's upgrade step where
# nothing in Intact logs in with it.
INTACT_KNOWN_DEFAULT_PASSWORDS=('123123' 'Ch4nge-Me!Intact2026' '1234qwer!@#$' 'changeme')

# One rule that every bundled tool accepts at first start: Elasticsearch >= 6,
# IRIS >= 12 with upper/lower/digit, Portainer >= 12, Timesketch/Velociraptor
# none, VolWeb seeds via set_password. Every one of them takes symbols, so a NEW
# password must hold one (2026-11-22). Left out: space, the quotes ' " ` and
# \ -- they break JSON, shell and the quoted config.yaml fields -- and $, which
# compose expands inside the .env files the passwords live in. It starts with a
# letter or digit: `velociraptor user add <user> <pw>` reads a leading '-' as a
# flag.
INTACT_PASSWORD_RULE="12+ characters with an uppercase letter, a lowercase letter, a digit and a symbol (such as ! @ # % ^ & * + = ? ~); no spaces, quotes (' \" \`), \\ or \$; starting with a letter or digit"

# secret_generate [length] -- random, from the kernel CSPRNG, meeting
# INTACT_PASSWORD_RULE: an uppercase letter, a lowercase letter, a digit and a
# symbol. Its symbols are the inert ones -- nothing in .env, JSON, YAML, a curl
# config, a shell glob or a printf format treats + = ^ ~ specially.
secret_generate() {
    local n="${1:-24}" v
    while :; do
        v="$(LC_ALL=C tr -dc 'A-Za-z0-9+=^~' </dev/urandom 2>/dev/null | head -c "$n")"
        if [[ ${#v} -eq $n && "$v" =~ ^[A-Za-z0-9] && "$v" =~ [A-Z] && "$v" =~ [a-z] && "$v" =~ [0-9] \
              && "$v" == *[+=^~]* ]]; then
            printf '%s' "$v"
            return 0
        fi
    done
}

# secret_weak_allowed -- 0 on a LAB box whose config.yaml says
# `allow_weak_passwords: true` (or INTACT_ALLOW_WEAK_PASSWORDS=1). Then weak and
# publicly known passwords such as 123123 are accepted and upgrades leave them
# alone. Off in the shipped config.yaml, and the pre-commit sanitizer forces it
# back to false, so a dev checkout's `true` can never reach the public repo.
# Only true/True/TRUE, exactly what the backend's weak_passwords_allowed()
# accepts: a `yes` the shell took and the dashboard did not left the two halves
# of one box on different rules.
secret_weak_allowed() {
    [[ "${INTACT_ALLOW_WEAK_PASSWORDS:-0}" == "1" ]] && return 0
    [[ -n "${CONFIG_FILE:-}" && -r "$CONFIG_FILE" ]] || return 1
    grep -qE '^allow_weak_passwords:[[:space:]]*(true|True|TRUE)[[:space:]]*(#.*)?$' "$CONFIG_FILE"
}

# _secret_chars_ok <value> -- printable ASCII, starting with a letter or digit,
# none of: space ' " ` \ $ (why: INTACT_PASSWORD_RULE above).
_secret_chars_ok() {
    local LC_ALL=C v="$1"
    [[ "$v" =~ ^[A-Za-z0-9] ]] || return 1
    [[ "$v" == *[![:graph:]]* ]] && return 1      # space, control, non-ASCII
    [[ "$v" == *[\$\'\"\`\\]* ]] && return 1
    return 0
}

# secret_check <value> [existing] -- 0 when the value meets INTACT_PASSWORD_RULE;
# otherwise 1, with the reason on stdout (never the value itself).
# `existing`: a value already in use (upgrade carry-over) is not refused for
# lacking a symbol -- only new passwords need one, or every box would get new
# tool passwords on its next upgrade.
secret_check() {
    local v="$1" mode="${2:-new}" d
    if [[ -z "$v" ]]; then echo "it is empty"; return 1; fi
    if ! _secret_chars_ok "$v"; then
        echo "it may not hold spaces, quotes (' \" \`), \\ or \$, and must start with a letter or digit"; return 1
    fi
    # Lab box: only what would break .env/YAML/shell handling is refused.
    secret_weak_allowed && return 0
    for d in "${INTACT_KNOWN_DEFAULT_PASSWORDS[@]}"; do
        if [[ "$v" == "$d" ]]; then echo "it is a publicly known default"; return 1; fi
    done
    if (( ${#v} < 12 )); then echo "it is shorter than 12 characters"; return 1; fi
    if ! [[ "$v" =~ [A-Z] && "$v" =~ [a-z] && "$v" =~ [0-9] ]]; then
        echo "it needs an uppercase letter, a lowercase letter and a digit"; return 1
    fi
    if [[ "$mode" != existing && "$v" != *[!A-Za-z0-9]* ]]; then
        echo "it needs a symbol (such as ! @ # % ^ & * + = ? ~)"; return 1
    fi
    return 0
}

# secret_is_known_default <value> -- 0 when the value is one of the public ones.
secret_is_known_default() {
    local d
    for d in "${INTACT_KNOWN_DEFAULT_PASSWORDS[@]}"; do [[ "$1" == "$d" ]] && return 0; done
    return 1
}

secret_dir()  { printf '%s/modules/%s/secrets' "${SCRIPT_DIR}" "$1"; }
secret_file() { printf '%s/creds.env' "$(secret_dir "$1")"; }

# secret_get <module> <KEY> -- the stored value, or nothing (exit 1) if absent.
secret_get() {
    local f; f="$(secret_file "$1")"
    [[ -r "$f" ]] || return 1
    local v; v="$(sed -n "s/^${2}=//p" "$f" | tail -1)"
    [[ -n "$v" ]] || return 1
    printf '%s' "$v"
}

# secret_set <module> <KEY> <value> -- store privately. Refuses an empty value:
# writing an empty password is how a box gets "None"/blank passwords that the
# tool then rejects. The file and dir are created private, never chmod-ed later.
secret_set() {
    local m="$1" k="$2" v="$3"
    [[ "$k" =~ ^[A-Z][A-Z0-9_]*$ ]] || { log_error "secret_set: bad key name '${k}'"; return 1; }
    [[ -n "$v" ]] || { log_error "secret_set: refusing an empty value for ${m} ${k}"; return 1; }
    [[ "$v" != *$'\n'* ]] || { log_error "secret_set: value for ${m} ${k} has a newline"; return 1; }
    local d f tmp
    d="$(secret_dir "$m")"; f="$(secret_file "$m")"
    # readlink -m: scripts/clean.sh empties data/, which leaves the registered
    # secrets dirs (lib/state_registry.sh) as symlinks to nothing, and
    # `mkdir -p` on a dangling symlink fails "File exists" -- the re-install
    # then had nowhere to store a password. Create the target instead.
    ( umask 077; mkdir -p "$(readlink -m "$d")" ) || return 1
    chmod 700 "$d" 2>/dev/null || true
    tmp="$(umask 077; mktemp "${d}/.creds.env.XXXXXX")" || return 1
    {
        [[ -f "$f" ]] && grep -v "^${k}=" "$f"
        printf '%s=%s\n' "$k" "$v"
    } > "$tmp" || { rm -f "$tmp"; return 1; }
    chmod 600 "$tmp" || { rm -f "$tmp"; return 1; }
    if [[ -f "$f" ]]; then
        # Write INTO the existing file, never mv over it: state_registry keeps
        # some creds.env files as a hard link with data/state/, and a rename
        # would split the pair -- data/state keeps the old password and the
        # next state migration leaves a stale `.superseded` copy behind.
        cat "$tmp" > "$f" && chmod 600 "$f"
        local rc=$?
        rm -f "$tmp"
        return $rc
    fi
    mv -f "$tmp" "$f"
}

# secret_tool_is_new <spec>... -- 0 when the tool has NO data yet, so a new
# password can safely be generated. Each spec is `vol:<docker volume>` (present
# = not new) or `path:<file or dir>` (exists and non-empty = not new). With any
# doubt (docker unreachable) it answers "not new": keeping an old password is
# recoverable, minting one the tool rejects is not.
secret_tool_is_new() {
    local s
    for s in "$@"; do
        case "$s" in
            vol:*)
                command -v docker >/dev/null 2>&1 || return 1
                docker info >/dev/null 2>&1 || return 1
                docker volume inspect "${s#vol:}" >/dev/null 2>&1 && return 1 ;;
            path:*)
                local p="${s#path:}"
                [[ -f "$p" && -s "$p" ]] && return 1
                [[ -d "$p" && -n "$(ls -A "$p" 2>/dev/null)" ]] && return 1 ;;
            *) log_error "secret_tool_is_new: unknown spec '${s}'"; return 1 ;;
        esac
    done
    return 0
}

# secret_show_once -- reads "label|user|password[|note]" lines on stdin and
# shows them to the operator ONLY, on the terminal. Never to stdout or the
# install log (the migration tees stdout to a log; CI streams it). Without a
# terminal nothing is written anywhere: a file here used to be a second
# plaintext copy of every password, and the stores are already readable with
# scripts/show-credentials.sh. Each line reads `password: <value>` so every
# existing redactor (support bundle, log viewer) still catches a leak.
secret_show_once() {
    local lines; lines="$(cat)"
    [[ -n "$lines" ]] || return 0
    if ! { : > /dev/tty; } 2>/dev/null; then
        log_info "Credentials were set — view them with: sudo scripts/show-credentials.sh"
        return 0
    fi
    {
        echo
        echo "  ---- credentials (shown once; also: sudo scripts/show-credentials.sh) ----"
        printf '%s\n' "$lines" | while IFS='|' read -r label user pw note; do
            printf '  %-22s user: %-16s password: %s%s\n' "$label" "$user" "$pw" "${note:+  ($note)}"
        done
        echo "  ---------------------------------------------------------------------------"
        echo
    } > /dev/tty
}
