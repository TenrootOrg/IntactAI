#!/bin/bash
# Intact.AI — the dashboard's one-time setup token.
#
# WHY. While config.yaml has first_login: true (every fresh install, and every
# password recovery) /api/auth/setup used to accept the FIRST visitor from the
# network. QA: an attacker locks the operator out, waits for them to reopen
# setup, and claims the appliance. Setup now also needs this token. It lives in
# data/state/backend/setup_token -- root-only on the host, read by the backend
# through its /app/data mount (services/auth_service.py:setup_token_path) -- so
# reaching the page is no longer enough. The backend deletes the file when
# setup succeeds; that is how the token is spent.
#
# Callers set SCRIPT_DIR to the Intact.AI root (install.sh, scripts/*.sh do).

setup_token_file() { printf '%s/data/state/backend/setup_token' "${SCRIPT_DIR}"; }

# new_setup_token -- replace any token with a fresh one and print it on stdout.
new_setup_token() {
    local f dir tok
    f="$(setup_token_file)"
    dir="${f%/*}"
    # 43 url-safe chars = 256 bits from the kernel CSPRNG: typed or pasted once,
    # never worth guessing behind a per-client lockout.
    tok="$(LC_ALL=C tr -dc 'A-Za-z0-9_-' </dev/urandom 2>/dev/null | head -c 43)"
    [[ ${#tok} -eq 43 ]] || return 1
    # A directory bind mount, not a single-file one, so a temp+rename is safe
    # here and means the backend never reads a half-written token.
    (
        umask 077
        mkdir -p "$dir" && chmod 700 "$dir" &&
            printf '%s\n' "$tok" >"${f}.tmp" && chmod 600 "${f}.tmp" &&
            mv -f "${f}.tmp" "$f"
    ) || { rm -f "${f}.tmp"; return 1; }
    printf '%s\n' "$tok"
}

# ensure_setup_token -- keep an existing token (a re-run of the install must not
# invalidate the one already shown), else make one; print it either way.
ensure_setup_token() {
    local f tok
    f="$(setup_token_file)"
    if [[ -s "$f" ]]; then
        tok="$(tr -d '[:space:]' <"$f")"
        if [[ -n "$tok" ]]; then
            chmod 600 "$f" 2>/dev/null
            printf '%s\n' "$tok"
            return 0
        fi
    fi
    new_setup_token
}
