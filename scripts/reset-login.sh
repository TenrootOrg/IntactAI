#!/bin/bash
# Intact.AI — reopen the dashboard's setup page with a new one-time token.
#
# The recovery for a forgotten dashboard password (or a box with no usable
# login). It used to be "set first_login: true in config.yaml", which opened
# setup to the first visitor from the network (QA: lock the operator out, wait
# for the recovery, claim the box). Now setup also needs a token only root on
# the host can read, so recovery is this script, run as root.
#
# Usage: sudo scripts/reset-login.sh
#
# Order: the token first, then first_login. If the config edit fails, a token
# exists but setup stays closed -- harmless. The reverse would open setup with
# no way to complete it.

set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/config.yaml"
# shellcheck source=../lib/setup_token.sh
source "${SCRIPT_DIR}/lib/setup_token.sh"

# id -u rather than $EUID so tests can stub it.
if [[ "$(id -u)" != "0" ]]; then
    echo "This script must be run as root: sudo scripts/reset-login.sh" >&2
    exit 1
fi
if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "config.yaml not found at ${CONFIG_FILE}" >&2
    exit 1
fi

if ! token="$(new_setup_token)"; then
    echo "Could not write the setup token to $(setup_token_file)" >&2
    exit 1
fi

# In place, inode preserved: config.yaml is bind-mounted into the backend BY
# INODE, so temp+mv would leave the container reading the old first_login
# forever. Same line edit as auth_service.write_first_login: the top-level key
# only, inserted after schema_version when absent, nothing else touched.
if ! python3 - "$CONFIG_FILE" <<'PYRESET'
import re, sys
path = sys.argv[1]
with open(path, "r", encoding="utf-8") as fh:
    lines = fh.read().splitlines(keepends=True)
hits = [i for i, l in enumerate(lines) if re.match(r"first_login\s*:", l)]
if len(hits) > 1:
    sys.exit("config.yaml has more than one top-level first_login line")
if hits:
    nl = "\n" if lines[hits[0]].endswith("\n") else ""
    lines[hits[0]] = "first_login: true" + nl
else:
    at = next((i + 1 for i, l in enumerate(lines) if re.match(r"schema_version\s*:", l)), 0)
    lines.insert(at, "first_login: true\n")
with open(path, "r+", encoding="utf-8") as fh:   # truncate in place
    fh.seek(0)
    fh.write("".join(lines))
    fh.truncate()
PYRESET
then
    echo "Could not set first_login: true in ${CONFIG_FILE}; setup was not reopened." >&2
    exit 1
fi

host="$(sed -n 's/^domain:[[:space:]]*["'\'']\{0,1\}\([^"'\''#[:space:]]*\).*/\1/p' "$CONFIG_FILE" | head -1)"
if [[ -z "$host" || "$host" == "CHANGE-ME" ]]; then
    host="$(hostname -I 2>/dev/null | awk '{print $1}')"
fi

cat <<EOF
Dashboard setup reopened.

  Open:         https://${host:-<appliance-address>}/setup.html
  Setup token:  ${token}

Enter the token there and choose a new username and password. The token works
once. The current login keeps working until setup is completed; after that the
old password stops working and every open session is signed out.
EOF
