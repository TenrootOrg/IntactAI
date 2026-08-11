#!/bin/bash
# A release page carries three kinds of .tar and only one of them is a module
# asset. Point --package at a folder holding all of them and the other two must
# be left alone.
#
#   <tag>-<module>.tar[.gz]   a module asset            -> collect
#   <tag>-system-bundle.tar   Docker/apt .deb files     -> skip
#   <tag>-bootstrap.tar       install.sh + lib + scripts -> skip
#
# system-bundle was skipped from the start. bootstrap was NOT, until
# 2026-08-11. Its tarball has its own top-level directory -- the bare tag,
# where a module asset uses intact-upgrade-<tag> -- so collecting it gives the
# merged extraction tree a SECOND root that the manifest describes neither of.
#
# CI could not catch this: its dry-run-apply job collects only from the
# per-module build artifacts (`all/asset-*/`), and bootstrap and system-bundle
# upload as separate artifacts, so the three never share a directory there.
# They do share one on the release page, which is exactly what an air-gap
# operator downloads.

set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PASS=0; TOTAL=0
ok()   { TOTAL=$((TOTAL+1)); PASS=$((PASS+1)); echo "  ok   - $1"; }
fail() { TOTAL=$((TOTAL+1)); echo "  FAIL - $1"; [[ -n "${2:-}" ]] && echo "         $2"; }
check() { if [[ "$2" == "$3" ]]; then ok "$1"; else fail "$1" "expected '$3', got '$2'"; fi; }

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
TAG=intact-20260821
touch "$TMP/${TAG}-portainer.tar.gz" \
      "$TMP/${TAG}-elk.tar" \
      "$TMP/${TAG}-system-bundle.tar" \
      "$TMP/${TAG}-bootstrap.tar" \
      "$TMP/${TAG}.index.json" \
      "$TMP/${TAG}.manifest.json" \
      "$TMP/${TAG}-bootstrap.tar.sha256"

echo "== a whole release page in one folder =="
collected() {
    find "$TMP" -maxdepth 1 \( -name '*.tar.gz' -o -name '*.tar' \) \
         ! -name '*-system-bundle.tar' \
         ! -name '*-bootstrap.tar' -printf '%f\n' | sort | tr '\n' ' '
}
check "only the module assets are collected" \
      "$(collected)" "${TAG}-elk.tar ${TAG}-portainer.tar.gz "

# The failure this guards against, spelled out: without the bootstrap
# exclusion the same folder yields three assets, one of which unpacks a
# different root.
legacy() {
    find "$TMP" -maxdepth 1 \( -name '*.tar.gz' -o -name '*.tar' \) \
         ! -name '*-system-bundle.tar' | wc -l | tr -d ' '
}
check "without the bootstrap rule it would take one too many" "$(legacy)" "3"

echo
echo "== every collection site carries BOTH exclusions =="
# Three places expand a directory into assets. All three must agree, or a
# package behaves differently depending on which entry point read it.
sites=(
    "lib/upgrade/package.sh:upgrade, --package <dir>"
    "lib/args.sh:install.sh, --package <dir>"
)
for entry in "${sites[@]}"; do
    f="${ROOT}/${entry%%:*}"; what="${entry#*:}"
    if grep -q -- "! -name '\*-system-bundle.tar'" "$f" \
       && grep -q -- "! -name '\*-bootstrap.tar'" "$f"; then
        ok "${what}"
    else
        fail "${what}" "one of the two exclusions is missing in ${entry%%:*}"
    fi
done
# The wrapper branch (a prepare_package.sh tarball, not a directory) is a
# separate loop in the same file and was equally affected.
if grep -q '\*-system-bundle.tar|\*-bootstrap.tar) continue' "${ROOT}/lib/upgrade/package.sh"; then
    ok "upgrade, unwrapped prepare_package.sh tarball"
else
    fail "upgrade, unwrapped prepare_package.sh tarball" "the wrapper branch still only skips system-bundle"
fi

echo
echo "== the local builder can produce these assets at all =="
B="${ROOT}/scripts/dev/build_local_release_assets.sh"
for flag in --bootstrap --system-bundle --all-assets; do
    if grep -q -- "        ${flag})" "$B" || grep -q -- "${flag})  *BOOTSTRAP=1" "$B" \
       || grep -qE "^\s+${flag}\)" "$B"; then
        ok "builder accepts ${flag}"
    else
        fail "builder accepts ${flag}"
    fi
done
# Faithfulness to the two CI jobs, in the details that are easy to get wrong.
if grep -q "tar -C \"\$_bs_parent\" -cf" "$B"; then
    ok "bootstrap is a PLAIN tar (CI uses tar -cf, not -czf)"
else
    fail "bootstrap is a plain tar"
fi
if grep -q "rm -rf \"\$_bs_parent/\$TAG/scripts/ci\" \"\$_bs_parent/\$TAG/scripts/dev\"" "$B"; then
    ok "bootstrap drops scripts/ci and scripts/dev"
else
    fail "bootstrap drops scripts/ci and scripts/dev" "scripts/dev fabricates packages from a live tree — it must not ship"
fi
# The two sidecars genuinely disagree in CI: bootstrap is the bare hash,
# system-bundle is the full sha256sum line. Copying that disagreement is
# deliberate, so assert both rather than "normalising" them.
if grep -q "awk '{print \$1}' \\\\" "$B"; then
    ok "bootstrap .sha256 is the bare hash"
else
    fail "bootstrap .sha256 is the bare hash"
fi
if grep -q 'sha256sum "${TAG}-system-bundle.tar" > "${TAG}-system-bundle.tar.sha256"' "$B"; then
    ok "system-bundle .sha256 is the full sha256sum line"
else
    fail "system-bundle .sha256 is the full sha256sum line"
fi
if grep -q 'apt-get purge -y -qq curl gnupg lsb-release' "$B"; then
    ok "system bundle purges its bootstrap tools before capturing"
else
    fail "system bundle purges its bootstrap tools before capturing" \
         "apt would consider them satisfied and never download them"
fi

echo
echo "${PASS}/${TOTAL} passed"
[[ "$PASS" == "$TOTAL" ]] || exit 1
