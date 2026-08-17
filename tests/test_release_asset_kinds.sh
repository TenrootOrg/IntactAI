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
         ! -name '*-bootstrap.tar' \
         ! -name '*-engine.tar.gz' -printf '%f\n' | sort | tr '\n' ' '
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
echo "== every collection site carries ALL THREE exclusions =="
# Three places expand a directory into assets. All three must agree, or a
# package behaves differently depending on which entry point read it.
# *-engine.tar.gz joined the set with the bootstrap handover: stage 1's
# payload, flat lib/+scripts/ under its own roots — merging it in is the
# 'found 3: scripts lib intact-upgrade-<tag>' refusal that killed the first
# real Import of a prepared wrapper.
sites=(
    "lib/upgrade/package.sh:upgrade, --package <dir>"
    "lib/args.sh:install.sh, --package <dir>"
)
for entry in "${sites[@]}"; do
    f="${ROOT}/${entry%%:*}"; what="${entry#*:}"
    if grep -q -- "! -name '\*-system-bundle.tar'" "$f" \
       && grep -q -- "! -name '\*-bootstrap.tar'" "$f" \
       && grep -q -- "! -name '\*-engine.tar.gz'" "$f"; then
        ok "${what}"
    else
        fail "${what}" "one of the three exclusions is missing in ${entry%%:*}"
    fi
done
# The wrapper branch (a prepare_package.sh tarball, not a directory) is a
# separate loop in the same file and was equally affected.
if grep -q '\*-system-bundle.tar|\*-bootstrap.tar|\*-engine.tar.gz) continue' "${ROOT}/lib/upgrade/package.sh"; then
    ok "upgrade, unwrapped prepare_package.sh tarball"
else
    fail "upgrade, unwrapped prepare_package.sh tarball" "the wrapper branch must skip system-bundle, bootstrap AND engine"
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
echo "== host-dependency drift is reported, never applied =="
# scripts/upgrade.sh sources common/config/docker/health/package/release/
# permissions -- NOT deps -- so an upgrade has never touched Docker or the
# host's apt packages. A box installed with Docker 24 stayed on Docker 24
# through any number of upgrades. It now says so; applying is a separate,
# operator-run script, because installing docker-ce restarts the daemon and
# would kill the helper container the engine runs inside.
_up() { local v="${1#*:}"; printf '%s' "${v%%-*}"; }
check "epoch and revision are stripped" \
      "$(_up '5:29.7.2-1~ubuntu.24.04~noble')" "29.7.2"
check "a version with no epoch still parses" \
      "$(_up '2.3.3-1~ubuntu.24.04~noble')" "2.3.3"

# The behind/ahead/equal decision, in the same shape hostdeps.sh uses.
_cmp() {
    local have="$1" want="$2"
    [[ "$have" == "$want" ]] && { echo same; return; }
    [[ "$(printf '%s\n%s\n' "$have" "$want" | sort -V | head -1)" == "$have" ]] \
        && echo behind || echo ahead
}
check "older host is BEHIND"        "$(_cmp 24.0.7 29.7.2)" "behind"
check "matching host is same"       "$(_cmp 29.7.2 29.7.2)" "same"
check "newer host is ahead"         "$(_cmp 30.1.0 29.7.2)" "ahead"
# sort -V, not string compare: 29.7.2 vs 29.10.0 is the case a lexical
# comparison gets backwards.
check "double-digit minors compare numerically" "$(_cmp 29.7.2 29.10.0)" "behind"

U="${ROOT}/scripts/upgrade.sh"
if grep -q 'hostdeps_report' "$U"; then
    ok "the upgrade runs the report"
else
    fail "the upgrade runs the report"
fi
# The load-bearing negative: sourcing deps.sh is what would make an upgrade
# able to apply host packages, and it must not.
# Assert the PROPERTY, not the exact list. This matched the source line
# verbatim and broke the moment 526c1d8 legitimately added state_registry to
# it -- a test that fails on a correct change teaches people to ignore it.
if grep -qE '^for _lib in .*\bdeps\b' "$U"; then
    fail "the upgrade still does not source lib/deps.sh" \
         "an upgrade must never be able to apt-get the host"
else
    ok "the upgrade still does NOT source lib/deps.sh"
fi

H="${ROOT}/scripts/update_host_deps.sh"
if [[ -f "$H" ]]; then
    ok "scripts/update_host_deps.sh exists"
else
    fail "scripts/update_host_deps.sh exists"
fi
if grep -q 'EUID != 0' "$H"; then
    ok "it refuses to run without root"
else
    fail "it refuses to run without root"
fi
# Named packages, not _missing_host_deps(): that helper fills gaps on a fresh
# box and skips anything already installed -- and an out-of-date Docker IS
# installed, so deriving the list would silently do nothing.
if grep -q '_apt_install_from_bundle "$BUNDLE_DIR" \\' "$H" \
   && grep -q 'docker-ce docker-ce-cli containerd.io docker-compose-plugin' "$H"; then
    ok "it names the packages so apt upgrades them"
else
    fail "it names the packages so apt upgrades them" \
         "deriving from _missing_host_deps would skip an already-installed old Docker"
fi
if grep -q "daemon will restart" "$H"; then
    ok "it warns that Docker restarts"
else
    fail "it warns that Docker restarts"
fi

echo "== the secret scan works on an ASSET, not just the repo =="
# verify-assets extracts each asset and scans it, so every path is
# <tag>/source/intact/... -- a repo-root-anchored allowlist can never match
# there. The whole carefully-built allowlist was silently inert for asset
# scans until 2026-08-12, which is why a release failed on three findings the
# repo had already decided were noise.
G="${ROOT}/.gitleaks.toml"
if grep -qF "'''^modules/" "$G"; then
    fail "allowlist paths match inside an extracted asset" \
         "^modules/... never matches <tag>/source/intact/modules/..."
else
    ok "allowlist paths match inside an extracted asset"
fi
if grep -qF "(^|/)modules/timesketch/config/timesketch_legacy" "$G"; then
    ok "the un-anchored form is used"
else
    fail "the un-anchored form is used"
fi
# The generated manifest pairs filenames containing security words
# (auth_service.py, secret_store.py, WinSCP__Passwords.yaml) with a 64-char
# sha256 -- precisely what generic-api-key looks for. 74 of 77 findings.
if grep -qF "manifests/" "$G"; then
    ok "the generated release manifest is allowlisted"
else
    fail "the generated release manifest is allowlisted" \
         "its sha256 map reads as 37 leaked API keys per copy"
fi

echo
echo "== a package never carries per-box key material =="
# The packager's comment promised this list defended against a source_dir
# wired to a live install. It named none of it, and the dev builder stages
# exactly that -- so a locally built package shipped the build box's rendered
# timesketch_legacy.conf, with a real SECRET_KEY and postgres password.
K="${ROOT}/scripts/ci/packager/package.py"
for pat in "'secrets'" "'certificates'" "'ssl'" "'*.pem'" "'*.key'" "'timesketch_legacy.conf'"; do
    if grep -qF -- "$pat" "$K"; then
        ok "packager excludes ${pat}"
    else
        fail "packager excludes ${pat}" "per-box key material would ship in source/intact/"
    fi
done
if grep -qF -- "'timesketch.conf.template'" "$K"; then
    fail "the tracked .template is kept" "excluding it leaves the box nothing to render from"
else
    ok "the tracked .template is kept"
fi

echo
echo "== CI can act on its own failures =="
W="${ROOT}/.github/workflows/build-release-assets.yml"
# The packager fetches the target release's config.yaml to pin sidecar
# versions; this repo is private, so without a token that 404s and the build
# silently falls back to the build machine's pins. The index job then refuses
# the release, ~45 minutes after the mistake.
if grep -qF 'GITHUB_TOKEN="$GITHUB_TOKEN"' "$W"; then
    ok "the packager container receives GITHUB_TOKEN"
else
    fail "the packager container receives GITHUB_TOKEN" \
         "anonymous raw fetch 404s on a private repo -> pins_source=local-fallback"
fi
# gitleaks without -v logs a COUNT and no findings.
if grep -qF -- '--redact -v' "$W"; then
    ok "a gitleaks failure names its findings"
else
    fail "a gitleaks failure names its findings" \
         "'leaks found: 70' with no file list is not actionable"
fi

echo
echo "${PASS}/${TOTAL} passed"
[[ "$PASS" == "$TOTAL" ]] || exit 1
