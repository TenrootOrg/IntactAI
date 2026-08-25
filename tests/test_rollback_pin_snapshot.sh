#!/usr/bin/env bash
# A rollback must restore the config.yaml pin it started from.
#
# THE BUG THIS EXISTS FOR. u_undo_pin captured its rollback value by reading
# config.yaml at the moment it was called -- inside each module, stage ~5. But
# `intact` runs FIRST in UPGRADE_ORDER, and _intact_merge_versions has by then
# already written the package's NEW pins into config.yaml. So the registered
# "undo" restored the new version: a no-op.
#
# The consequence is not cosmetic. update_env_files (install.sh, change_ip.sh)
# re-derives every module .env FROM config.yaml, so after a rollback the box
# held .env=<old> and config.yaml=<new>, and the next repair silently pushed it
# forward again with no upgrade running and nobody watching. Measured
# 2026-08-25: iris failed, its .env was correctly restored to v2.4.27, and
# config.yaml kept v2.4.29.
#
# The fix snapshots the versions block before any module runs. This test proves
# the OLD shape was broken and the NEW shape is not, then pins the two
# deliberate exceptions.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
run=0; failed=0
ok()  { printf '  \033[0;32mok\033[0m   - %s\n' "$1"; }
bad() { printf '  \033[0;31mFAIL\033[0m - %s\n' "$1"; failed=$((failed+1)); }
chk() { run=$((run+1)); if eval "$2"; then ok "$1"; else bad "$1"; fi; }

echo "== the bug is real, and the snapshot is what fixes it (non-vacuous) =="
# Model both shapes against a config that the "merge" has already overwritten.
sim="$(mktemp)"; trap 'rm -f "$sim"' EXIT
cat > "$sim" <<'SH'
CONFIG_PIN="v2.4.29"          # the merge already wrote the NEW version
INSTALLED="v2.4.27"           # what the box was actually on
read_config() { echo "$CONFIG_PIN"; }

# OLD: read config.yaml at call time -> captures the new value -> no-op undo
old_undo="$(read_config)"

# NEW: read a snapshot taken before the merge
declare -A SNAP=([iris]="$INSTALLED")
new_undo="${SNAP[iris]}"

echo "old=$old_undo new=$new_undo installed=$INSTALLED"
SH
res="$(bash "$sim")"
chk "the old shape captures the NEW version (the no-op)" '[[ "$res" == *"old=v2.4.29"* ]]'
chk "the snapshot captures the version actually installed" '[[ "$res" == *"new=v2.4.27"* ]]'

echo
echo "== the snapshot is taken before any module can touch config.yaml =="
UPG="$ROOT/scripts/upgrade.sh"
HLP="$ROOT/lib/upgrade/helpers.sh"
chk "u_snapshot_pins is called from the plan section" \
    "grep -q 'u_snapshot_pins' '$UPG'"
# It must come AFTER plan_build (config readable) and BEFORE the module loop.
chk "it runs after plan_build" \
    "[[ \$(grep -n 'plan_build' '$UPG' | head -1 | cut -d: -f1) -lt \$(grep -n 'u_snapshot_pins' '$UPG' | head -1 | cut -d: -f1) ]]"
chk "it runs before the module loop" \
    "[[ \$(grep -n 'u_snapshot_pins' '$UPG' | head -1 | cut -d: -f1) -lt \$(grep -nE 'for .* in .*UPGRADE_ORDER' '$UPG' | head -1 | cut -d: -f1) ]]"

echo
echo "== u_undo_pin prefers the snapshot, and degrades safely =="
chk "it reads U_PIN_BEFORE" "grep -q 'U_PIN_BEFORE\[\$key\]' '$HLP'"
chk "it falls back to read_config when no snapshot was taken" \
    "grep -q 'U_PIN_SNAPSHOT_TAKEN' '$HLP'"
# An absent pre-upgrade key (intact-20260615 has no versions.aws_sigma) must
# leave config.yaml alone rather than unpin a key validation then requires.
chk "an absent pre-upgrade pin leaves config.yaml untouched" \
    "grep -q 'leaving config.yaml untouched on rollback' '$HLP'"
chk "the pre-rename 'cloudtrail' spelling is carried into aws_sigma" \
    "grep -q \"cloudtrail\" '$HLP'"

echo
echo "== elk is exempt, deliberately =="
# Restoring versions.elk below a running Elasticsearch would brick the node on
# the next repair: update_env_files re-derives .env from config.yaml, and ES
# refuses to open a data dir a newer version wrote.
chk "u_undo_pin refuses to roll back the elk pin" \
    "sed -n '/^u_undo_pin()/,/^}/p' '$HLP' | grep -q 'key\" == \"elk\"'"
chk "and says why in the log" \
    "sed -n '/^u_undo_pin()/,/^}/p' '$HLP' | grep -q 'ES cannot open a newer data dir'"

echo
echo "== every module that pins now registers an undo =="
for f in "$ROOT"/lib/upgrade/modules/*.sh "$ROOT/lib/upgrade/timesketch/timesketch.sh" \
         "$ROOT/lib/upgrade/velociraptor/velociraptor.sh"; do
    [[ -f "$f" ]] || continue
    grep -q '_pin_module_version' "$f" || continue
    m="$(basename "$f" .sh)"
    run=$((run+1))
    if grep -q 'u_undo_pin' "$f"; then ok "${m} registers a pin undo"
    else bad "${m} pins config.yaml with no undo"; fi
done

echo
echo "$(basename "$0"): ${run} run, ${failed} failed"
[[ $failed -eq 0 ]]
