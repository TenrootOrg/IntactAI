#!/usr/bin/env bash
# Development pre-releases in `upgrade.sh --list` (2026-10-06: "our system need
# to be able to upgrade to pre-release [it will be out development releases]").
# Listed and flagged, ordered dev1 < dev2 < the stable release of that date,
# and never the suggested "Next" hop. Drives the real upgrade_list_releases on
# a fake GitHub answer.
cd "$(dirname "$0")/.." || exit 1
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
echo intact-20261005 > "$T/VERSION"
cat > "$T/rels.json" <<'EOF'
[{"tag_name":"intact-20261006-dev2","prerelease":true,"assets":[{"name":"a.tar","size":5}]},
 {"tag_name":"intact-20261006-dev1","prerelease":true,"assets":[{"name":"a.tar","size":5}]},
 {"tag_name":"intact-20261006","prerelease":false,"assets":[{"name":"a.tar","size":5}]},
 {"tag_name":"intact-20261005","prerelease":false,"assets":[{"name":"a.tar","size":5}]}]
EOF
list() {
    ( log_info(){ echo "$*"; }; log_error(){ echo "$*"; }
      SCRIPT_DIR="$T"; INTACT_REPO=x/y; INTACT_GH_API_BASE=http://none
      # shellcheck source=/dev/null
      source lib/upgrade/refs.sh
      _gh_curl(){ cat "$T/rels.json"; }
      UPGRADE_JSON="$1" upgrade_list_releases )
}
run=0 failed=0
check() { run=$((run + 1)); if eval "$2"; then :; else failed=$((failed + 1)); echo "  FAIL [$1]"; fi; }

json="$(list 1 | tail -1)"
order="$(python3 -c 'import json,sys; print(" ".join(r["tag"] for r in json.loads(sys.argv[1])["releases"]))' "$json")"
check "ordered by date, dev builds before their stable release" \
    '[[ "$order" == "intact-20261005 intact-20261006-dev1 intact-20261006-dev2 intact-20261006" ]]'
check "the JSON flags each pre-release" \
    'python3 -c "import json,sys; r={x[\"tag\"]: x[\"prerelease\"] for x in json.loads(sys.argv[1])[\"releases\"]}; sys.exit(0 if r[\"intact-20261006-dev1\"] and not r[\"intact-20261006\"] else 1)" "$json"'
human="$(list 0)"
check "the table marks pre-releases" 'grep -q "intact-20261006-dev1.*(pre-release)" <<<"$human"'
check "Next is the stable release, never a dev build" 'grep -q "Next:  sudo bash scripts/upgrade.sh intact-20261006$" <<<"$human"'

echo "test_release_list_prerelease.sh: $run run, $failed failed"
(( failed == 0 ))
