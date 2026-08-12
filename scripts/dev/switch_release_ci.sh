#!/usr/bin/env bash
# Flip .github/release-ci.conf, which is what decides between the two release
# workflows. Editing that one line by hand does the same thing -- this just
# saves getting the spelling right.
#
#   switch_release_ci.sh new      is_new_CI = TRUE   (per-module assets)
#   switch_release_ci.sh legacy   is_new_CI = FALSE  (single-asset bundle)
#   switch_release_ci.sh          show the current value
#
# Both workflows gate on that file, so exactly one ever runs. Commit and push
# for it to take effect -- GitHub reads the file from the default branch.
set -uo pipefail
CONF="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/.github/release-ci.conf"

_show() {
    local v
    v="$(grep -iE '^[[:space:]]*is_new_CI[[:space:]]*=' "$CONF" | tail -1 | sed 's/.*=[[:space:]]*//')"
    case "${v^^}" in
        FALSE|NO|0) echo "  is_new_CI = ${v}  ->  OLD single-asset bundle" ;;
        *)          echo "  is_new_CI = ${v}  ->  NEW per-module assets" ;;
    esac
}

case "${1:-}" in
    new|per-module|true)  sed -i -E 's/^([[:space:]]*is_new_CI[[:space:]]*=).*/\1 TRUE/I'  "$CONF" ;;
    legacy|old|false)     sed -i -E 's/^([[:space:]]*is_new_CI[[:space:]]*=).*/\1 FALSE/I' "$CONF" ;;
    ""|show|status)       _show; exit 0 ;;
    *) echo "usage: $(basename "$0") [new|legacy]" >&2; exit 2 ;;
esac
_show
echo "  commit + push .github/release-ci.conf for it to take effect"
