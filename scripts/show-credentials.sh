#!/bin/bash
# Print every module login stored on this box: module | user | password (and
# the dashboard setup token while setup is still open).
#
#   sudo bash scripts/show-credentials.sh
#
# The stores (modules/<module>/secrets, see lib/secrets.sh) are the only copy
# of these passwords -- config.yaml is blanked at install -- so this is how an
# operator reads one back after the install's one-time display. Root only: the
# stores are 0600/0700, and a non-root run would print a silently partial table.
# Velociraptor's `api` user and Elasticsearch's kibana_system are machine-only
# and never listed (credential_lines in lib/config.sh).

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/config.yaml"
LOG_FILE=/dev/null

if [[ "${EUID}" -ne 0 ]]; then
    echo "Run as root: sudo bash scripts/show-credentials.sh" >&2
    exit 1
fi

source "${SCRIPT_DIR}/lib/common.sh"
source "${SCRIPT_DIR}/lib/config.sh"

lines="$(credential_lines --ids)"
# The dashboard setup token while setup is still open (the backend deletes the
# file when setup succeeds): an admin who missed the install's one-time
# display can still claim the box.
tok=""
[[ -s "${SCRIPT_DIR}/data/state/backend/setup_token" ]] && \
    tok="$(tr -d '[:space:]' < "${SCRIPT_DIR}/data/state/backend/setup_token")"
if [[ -z "$lines" && -z "$tok" ]]; then
    echo "No stored credentials under ${SCRIPT_DIR}/modules/*/secrets" >&2
    exit 1
fi
printf '%s\n' "module | user | password"
if [[ -n "$lines" ]]; then
    # A 4th field is a note (Portainer "unknown"): printed as a 4th column, so a
    # parser of `module | user | password` lines skips it.
    while IFS='|' read -r module user pw note; do
        printf '%s | %s | %s%s\n' "$module" "$user" "$pw" "${note:+ | $note}"
    done <<< "$lines"
fi
[[ -n "$tok" ]] && printf 'Dashboard setup token | - | %s\n' "$tok"

# The admin has now seen every password, so the backend's "Passwords were
# changed for: ..." banner (the marker's "rotated" list) has done its job.
# "modules" (machine logins still on a default) stays. In place, so the 0600
# mode and inode are kept; gone once both lists are empty.
marker="${SCRIPT_DIR}/data/state/default-passwords.json"
if [[ -n "$lines" && -f "$marker" ]]; then
    python3 - "$marker" <<'PYMARK' || echo "Could not clear the 'rotated' list in ${marker}" >&2
import json, os, sys
path = sys.argv[1]
with open(path, encoding="utf-8") as fh:
    d = json.load(fh)
if d.get("rotated"):
    d["rotated"] = []
    if not d.get("modules"):
        os.unlink(path)
    else:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(d, fh)
            fh.write("\n")
elif not d.get("modules"):
    os.unlink(path)
PYMARK
fi
exit 0
