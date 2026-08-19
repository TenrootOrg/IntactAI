#!/bin/bash
# Nothing on the forward path ever carried an `options:` key onto an existing
# box. _intact_merge_versions copies the manifest's `versions:` block and
# nothing else, migrations only reshape what is already there, and a release
# ships no config.yaml at all -- so there has never been a template to seed
# from.
#
# Confirmed on a real 0615 -> 0818 upgrade, 2026-08-19: the box came out the far
# side still holding ['check_module_updates', 'download_forensic_tools'] --
# a key nothing reads -- and never received `download_tools` OR `github_token`.
# The missing token is the sharp end: every api.github.com call then runs
# anonymous against a 60-request/hour per-IP cap, so the Online Upgrade UI
# reports "rate limited" with nowhere in config.yaml to fix it.
#
# Two mechanisms, tested together because that is how they run:
#   * migration 2 -> 3 renames download_forensic_tools -> download_tools,
#     carrying the operator's VALUE (the flag stated an intent 0615 could not
#     honour; the new key is the first thing that can)
#   * _intact_seed_missing_options adds absent keys at their shipped default,
#     never rewriting a value the operator set

set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PASS=0; TOTAL=0
ok()   { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  ok   - $1"; }
fail() { TOTAL=$((TOTAL+1)); echo "  FAIL - $1"; [[ -n "${2:-}" ]] && echo "         $2"; }

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

SH="log_info(){ :; }; log_warn(){ :; }; log_error(){ :; }; log_success(){ :; };
    source '${ROOT}/lib/config.sh' 2>/dev/null || true;
    source '${ROOT}/lib/upgrade/intact/config.sh' 2>/dev/null || true"

run() {  # run <file> <fn...>
    local f="$1"; shift
    bash -c "CONFIG_FILE='$f'; $SH; $*" >/dev/null 2>&1
}
opt() {  # opt <file> <key>
    python3 -c "
import yaml,sys
d=yaml.safe_load(open('$1')) or {}
print((d.get('options') or {}).get('$2','(absent)'))" 2>/dev/null
}

mk0615() {
    cat > "$1" <<'YAML'
domain: 192.168.1.50

options:
  # Download forensic tools during installation
  download_forensic_tools: true
  check_module_updates: true

modules:
  elk:
    enabled: true

versions:
  elk: '9.4.4'
YAML
}

echo "== a 0615 box gets the rename, with its value =="
mk0615 "$TMP/a.yaml"
run "$TMP/a.yaml" '_intact_config_migrations; _intact_seed_missing_options'
[[ "$(opt "$TMP/a.yaml" download_tools)" == "True" ]] \
    && ok "download_forensic_tools: true -> download_tools: true (value carried)" \
    || fail "the operator's value did not survive the rename" "got '$(opt "$TMP/a.yaml" download_tools)'"
[[ "$(opt "$TMP/a.yaml" download_forensic_tools)" == "(absent)" ]] \
    && ok "the dead key is gone, not left alongside the live one" \
    || fail "the dead key is still there"
grep -q "# Download forensic tools during installation" "$TMP/a.yaml" \
    && ok "the operator's comment above the key survives" \
    || fail "the rename ate the comment above the key"

echo "== github_token arrives, which is what a rate-limited box was missing =="
[[ "$(opt "$TMP/a.yaml" github_token)" == "" ]] \
    && ok "github_token seeded empty, ready for the operator to fill in" \
    || fail "github_token absent after upgrade" "an upgraded box stays anonymous at 60 req/hr"
grep -q "5,000 req/hr" "$TMP/a.yaml" \
    && ok "seeded with a line saying what it is for" \
    || fail "github_token seeded with no explanation"

echo "== keys the operator already set are never rewritten =="
mk0615 "$TMP/b.yaml"
python3 - "$TMP/b.yaml" <<'PY'
import sys
p=sys.argv[1]; s=open(p).read()
open(p,"w").write(s.replace("  check_module_updates: true",
                            "  check_module_updates: true\n  github_token: 'ghp_operators_own'"))
PY
run "$TMP/b.yaml" '_intact_config_migrations; _intact_seed_missing_options'
[[ "$(opt "$TMP/b.yaml" github_token)" == "ghp_operators_own" ]] \
    && ok "an existing github_token is left exactly as the operator set it" \
    || fail "seeding overwrote an operator value" "got '$(opt "$TMP/b.yaml" github_token)'"

echo "== running it twice changes nothing the second time =="
cp "$TMP/a.yaml" "$TMP/a.once"
run "$TMP/a.yaml" '_intact_config_migrations; _intact_seed_missing_options'
diff -q "$TMP/a.once" "$TMP/a.yaml" >/dev/null \
    && ok "idempotent -- a re-run is a byte-for-byte no-op" \
    || fail "a second run churned config.yaml" "$(diff "$TMP/a.once" "$TMP/a.yaml" | head -4)"

echo "== a modern box is untouched apart from the schema stamp =="
cp "${ROOT}/config.yaml" "$TMP/m.yaml"
python3 - "$TMP/m.yaml" <<'PY'
import sys
p=sys.argv[1]; l=open(p).readlines(); l.insert(0,"schema_version: 2\n"); open(p,'w').writelines(l)
PY
cp "$TMP/m.yaml" "$TMP/m.orig"
run "$TMP/m.yaml" '_intact_config_migrations; _intact_seed_missing_options'
if diff <(tail -n +2 "$TMP/m.orig") <(tail -n +2 "$TMP/m.yaml") >/dev/null; then
    ok "nothing but schema_version changes on a current config.yaml"
else
    fail "a current config.yaml was rewritten" "$(diff "$TMP/m.orig" "$TMP/m.yaml" | head -6)"
fi

echo "== both names present: warn and carry on, never fail the upgrade =="
printf 'options:\n  download_forensic_tools: true\n  download_tools: false\n' > "$TMP/c.yaml"
if run "$TMP/c.yaml" '_intact_config_migrations'; then
    ok "an ambiguous config.yaml does not fail the intact module"
else
    fail "the migration failed the module over an untidy but working config" \
         "this rolls the whole upgrade back"
fi
[[ "$(opt "$TMP/c.yaml" download_tools)" == "False" ]] \
    && ok "the live key wins and is left alone" \
    || fail "the live key was disturbed"

echo "== no options block at all: one is created, and it parses =="
printf 'domain: 10.0.0.5\nversions:\n  elk: 9.4.4\n' > "$TMP/d.yaml"
run "$TMP/d.yaml" '_intact_seed_missing_options'
if python3 -c "
import yaml,sys
d=yaml.safe_load(open('$TMP/d.yaml'))
sys.exit(0 if set(d['options'])=={'download_tools','github_token'} and d['versions']['elk']=='9.4.4' else 1)" 2>/dev/null; then
    ok "an options: block is created without disturbing the rest of the file"
else
    fail "creating the options block produced something unexpected" "$(cat "$TMP/d.yaml")"
fi

echo
echo "  $PASS/$TOTAL passed"
[[ "$PASS" == "$TOTAL" ]]
