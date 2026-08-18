#!/bin/bash
# Build <tag>-engine.tar.gz -- the small, format-frozen asset that
# scripts/bootstrap_upgrade.sh fetches, verifies and execs.
#
# ONE BUILDER, THREE CALLERS. The release workflow, prepare_package.sh and the
# dev/test tooling all produce this asset, and if they each rolled their own
# `tar` line the layout would drift -- at which point an installed bootstrap,
# which is frozen and cannot be fixed, stops finding scripts/upgrade.sh. The
# layout is the contract; the contract lives here.
#
# See the header of scripts/bootstrap_upgrade.sh for what is frozen and why.
#
# Usage: build_engine_asset.sh <tag> <source-tree> <out-dir>

set -o pipefail

TAG="${1:-}"
SRC="${2:-}"
OUT="${3:-}"

[[ -n "$TAG" && -n "$SRC" && -n "$OUT" ]] || {
    echo "usage: build_engine_asset.sh <tag> <source-tree> <out-dir>" >&2; exit 2; }
[[ -d "$SRC" ]] || { echo "no source tree at ${SRC}" >&2; exit 2; }

# The engine is useless without these; failing here beats shipping an asset
# that every box will download and then refuse.
for _need in scripts/upgrade.sh lib/common.sh install.sh; do
    [[ -e "${SRC}/${_need}" ]] || { echo "source tree has no ${_need}" >&2; exit 2; }
done

mkdir -p "$OUT" || exit 2
STAGE="$(mktemp -d)" || exit 2
trap 'rm -rf "$STAGE"' EXIT

# FLAT, no leading directory: the bootstrap extracts straight into a scratch
# dir and execs <dir>/scripts/upgrade.sh. A wrapping directory would put the
# entry point one level deeper than every installed bootstrap looks.
#
# What goes in: the whole engine and everything it sources. lib/ carries
# lib/upgrade/*, lib/modules/* and the installer libraries that the upgrade
# path deliberately re-uses (deploy_* for a module being installed for the
# first time), so it is copied whole rather than cherry-picked -- a missing
# lib is a run that dies mid-module.
#
# What stays out: modules/ (that is the multi-GB payload, and the entire point
# of this split is that the bootstrap never touches it), data/, .git/, tests/,
# qa/. Keeping this asset small is what makes it safe to fetch before anything
# else has been decided.
# scripts/ci and scripts/dev are EXCLUDED, and that is not tidiness.
# scripts/dev/make_test_package.sh fabricates packages from a live tree and
# carries a secret-leak class that must not travel to a customer box; scripts/ci
# needs a full backend image to import services.image_map and is meaningless off
# a runner. The existing bootstrap-asset job strips both for exactly this
# reason -- this asset ships to the same places, so it strips them too.
tar -C "$SRC" -cf - \
    --exclude='__pycache__' --exclude='*.pyc' \
    --exclude='scripts/ci' --exclude='scripts/dev' \
    lib scripts install.sh 2>/dev/null | tar -C "$STAGE" -xf - || {
    echo "could not stage the engine tree" >&2; exit 1; }
rm -rf "${STAGE}/scripts/ci" "${STAGE}/scripts/dev"

# The bootstrap's escape hatch. A release that genuinely cannot be driven by
# the current handover contract bumps this, and every older bootstrap refuses
# cleanly and names the release to land on first, instead of misparsing.
# Bumping it strands every box below the bump -- it is a last resort, not a
# version number that tracks the release.
echo "1" > "${STAGE}/BOOTSTRAP_PROTOCOL"

# Identifies the engine on a support bundle -- and it is $TAG, ALWAYS, never
# the VERSION file sitting in $SRC.
#
# This asset is built FOR $TAG and ships inside $TAG's release, so claiming any
# other version is simply wrong. Copying $SRC/VERSION also made the build depend
# on repo state that is written AFTER the build: the release workflow stamps
# VERSION back onto the source branch in its `publish` job, but `bootstrap-asset`
# runs early (needs: resolve) and asserts
# `test "$(cat "$probe/VERSION")" = "$TAG"`. So on the FIRST build of any new tag
# the checkout still held the PREVIOUS release's VERSION, the assertion failed,
# publish never ran, and therefore VERSION was never stamped -- a release could
# only ever succeed on a tag that had already been released once. That is
# exactly how intact-20260818 failed: the tree said intact-20260813.
printf '%s\n' "$TAG" > "${STAGE}/VERSION"

NAME="${TAG}-engine.tar.gz"

# Reproducible: fixed mtime, fixed owner, sorted names. Two builds of the same
# ref then produce byte-identical assets, which is what lets CI assert an asset
# was not rebuilt from a different tree.
tar -C "$STAGE" \
    --sort=name --owner=0 --group=0 --numeric-owner --mtime='UTC 2020-01-01' \
    -czf "${OUT}/${NAME}" . 2>/dev/null \
  || tar -C "$STAGE" -czf "${OUT}/${NAME}" . || {
    echo "could not write ${OUT}/${NAME}" >&2; exit 1; }

# sha256sum's own format, so the bootstrap can `sha256sum -c` it or read
# column 1 -- and so can an operator, with no tooling.
( cd "$OUT" && sha256sum "$NAME" > "${NAME}.sha256" ) || {
    echo "could not write ${NAME}.sha256" >&2; exit 1; }

_size="$(du -h "${OUT}/${NAME}" | cut -f1)"
echo "built ${NAME} (${_size})"
echo "  sha256 $(awk '{print $1}' "${OUT}/${NAME}.sha256")"

# Prove the thing we just built is actually usable, here, rather than on a
# customer's box. Cheap, and it is the only check that covers the layout
# contract itself.
_probe="$(mktemp -d)" || exit 0
if tar -xzf "${OUT}/${NAME}" -C "$_probe" 2>/dev/null; then
    for _need in scripts/upgrade.sh lib/common.sh BOOTSTRAP_PROTOCOL; do
        [[ -e "${_probe}/${_need}" ]] || {
            echo "  BUILT ASSET IS BROKEN: no ${_need} at its top level" >&2
            rm -rf "$_probe"; exit 1; }
    done
    bash -n "${_probe}/scripts/upgrade.sh" 2>/dev/null || {
        echo "  BUILT ASSET IS BROKEN: scripts/upgrade.sh does not parse" >&2
        rm -rf "$_probe"; exit 1; }
    echo "  layout verified (scripts/upgrade.sh parses, protocol $(cat "${_probe}/BOOTSTRAP_PROTOCOL"))"
fi
rm -rf "$_probe"
