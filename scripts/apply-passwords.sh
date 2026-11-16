#!/bin/bash
# Change module passwords on a running box: the admin types them into
# config.yaml, this applies them, then blanks those lines again.
#
#   1. put the new value in config.yaml as modules.<module>.password
#      (elk, timesketch, velociraptor, iris, volweb, portainer)
#   2. sudo bash scripts/apply-passwords.sh
#
# For each module with a value: it must pass Intact's rule (lib/secrets.sh;
# allow_weak_passwords: true relaxes it on a lab box), then creds_apply
# (lib/credentials_apply.sh) sets it INSIDE the tool, stores it, recreates every
# container that reads it, verifies -- and on any failure puts the old one back
# everywhere. Each line is blanked only after its module changed; a refused or
# reverted value stays for the admin to fix. Prints "changed", "reverted:
# <reason>" or "FAILED, not fully put back: <reason>" per module, never a
# value; exits 1 if any was not changed.
#
# WHY A SEPARATE STEP. Installs and upgrades never change a password the backend
# logs in with (ES elastic, the Timesketch user, the VolWeb admin): its hash is
# in the tool's own data, and a half-applied change locks the platform out of
# its evidence. This is the one place that does it, on purpose, with a revert.
# No prompt anywhere: it runs the same from a terminal, cron or ssh -T.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/config.yaml"

if [[ "${EUID}" -ne 0 ]]; then
    echo "Run as root: sudo bash scripts/apply-passwords.sh" >&2
    exit 1
fi

# Beside install_*.log. Compose output lands here; no value ever does.
LOG_FILE="${SCRIPT_DIR}/apply-passwords_$(date +%Y%m%d_%H%M%S).log"
( umask 077; : > "$LOG_FILE" ) 2>/dev/null || LOG_FILE=/dev/null

source "${SCRIPT_DIR}/lib/common.sh"
source "${SCRIPT_DIR}/lib/secrets.sh"
source "${SCRIPT_DIR}/lib/config.sh"
source "${SCRIPT_DIR}/lib/modules/iris.sh"     # enforce_iris_admin_password
source "${SCRIPT_DIR}/lib/modules/volweb.sh"   # seed_volweb_admin
source "${SCRIPT_DIR}/lib/credentials_apply.sh"

any=0 failed=0
# Hangup, Ctrl-C and kill are ignored while a module is mid-change: stopping
# between "the tool has the new password" and "the store and readers have it"
# is the lockout this script exists to prevent. (A cut-off run -- power, kill
# -9 -- is finished by the next run: see _creds_resume.)
trap '' HUP INT TERM
for m in "${INTACT_CRED_MODULES[@]}"; do
    v="$(_config_password_raw "$m" password)"
    [[ -n "$v" ]] || continue
    any=1
    if ! reason="$(secret_check "$v")"; then
        echo "${m}: reverted: the value in config.yaml is not accepted (${reason}); nothing was changed"
        failed=1
        continue
    fi
    # log_* already write to LOG_FILE; stdout here is the per-module summary only.
    if creds_apply "$m" "$v" >/dev/null 2>>"$LOG_FILE"; then
        blank_config_passwords "$m" >>"$LOG_FILE" 2>&1 \
            || echo "${m}: changed, but its config.yaml line could not be blanked — blank it by hand"
        echo "${m}: changed${CREDS_APPLY_NOTE:+ (${CREDS_APPLY_NOTE})}"
    elif (( CREDS_APPLY_PUT_BACK )); then
        echo "${m}: reverted: ${CREDS_APPLY_REASON:-see ${LOG_FILE}}"
        failed=1
    else
        # Not "reverted": saying so would hide a box that is not as it was.
        echo "${m}: FAILED, not fully put back: ${CREDS_APPLY_REASON:-see ${LOG_FILE}}"
        failed=1
    fi
done
trap - HUP INT TERM
unset v

if (( ! any )); then
    echo "No module password is set in config.yaml (modules.<module>.password); nothing to do."
    exit 0
fi
# The marker the dashboard warns from: machine-used values that are no longer
# public drop off it. Values the admin typed are not "rotated" (they know them).
creds_mark_defaults >>"$LOG_FILE" 2>&1
(( failed )) && echo "A reverted module keeps its old password; its value is still in config.yaml — fix or blank that line."
echo "Current passwords: sudo scripts/show-credentials.sh"
exit "$failed"
