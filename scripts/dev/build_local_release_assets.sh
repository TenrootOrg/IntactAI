#!/usr/bin/env bash
# DEV-ONLY TOOL. Not shipped, not run by CI, not run by install.sh or upgrade.
#
# Builds a COMPLETE release locally, in both published shapes, with no GitHub
# and no CI:
#
#   shape 2 (per-module)  <tag>-<module>.tar  x N
#                         <tag>.index.json
#                         <tag>.manifest.json
#   shape 1 (legacy)      intact-upgrade-<tag>.tar[.gz]   (with --bundle)
#
# WHY. .github/workflows/build-release-assets.yml is the only thing that has
# ever produced a shape-2 release, it needs a GitHub runner, and the repo is
# private so nobody without a token can even download what it publishes. That
# left the per-module path -- the one every future upgrade takes -- completely
# unexercised. This runs the SAME scripts/ci/build_release_package.py the
# workflow runs, then reproduces the workflow's `index` job step for step, so
# what comes out is a faithful stand-in rather than an approximation.
#
# The index reproduction below is deliberately a close copy of that job's
# python block (build-release-assets.yml, the `index` job) INCLUDING its
# coherence, collision and completeness checks. Paraphrasing it would defeat
# the point: the value here is that a local release fails for the same reasons
# a real one would.
#
# Usage:
#   scripts/dev/build_local_release_assets.sh <tag> [out_dir] [modules_csv]
#
#   --bundle   additionally build the legacy single-bundle asset (slow: it
#              re-saves every image a second time)
#
# Output lands in <out_dir>/<tag>/, which is exactly the layout
# scripts/dev/serve_local_release.sh expects.
set -euo pipefail

BUNDLE=0
BUNDLE_ONLY=0
BOOTSTRAP=0
SYSBUNDLE=0
ARGS=()
for a in "$@"; do
    case "$a" in
        --bundle) BUNDLE=1 ;;
        # Shape 1 alone. What a 0726-era box needs: those appliances have no
        # scripts/upgrade.sh and no lib/upgrade/, so the engine has to arrive
        # inside the package for the stage-0 hop to fire, and they predate the
        # per-module index entirely. There is no point spending an hour on nine
        # module assets to get it.
        --bundle-only) BUNDLE=1; BUNDLE_ONLY=1 ;;
        # The two NEW-shape assets that are not module assets. Off by default:
        # neither is read by an upgrade (the engine skips both), so the common
        # case -- building a package to test an upgrade -- should not pay for
        # them. --system-bundle in particular runs a ubuntu:24.04 container and
        # downloads ~1 GB of .deb files.
        --bootstrap)      BOOTSTRAP=1 ;;
        --system-bundle)  SYSBUNDLE=1 ;;
        --all-assets)     BOOTSTRAP=1; SYSBUNDLE=1 ;;
        *) ARGS+=("$a") ;;
    esac
done
set -- "${ARGS[@]:-}"

TAG="${1:?usage: build_local_release_assets.sh [--bundle|--bundle-only] [--bootstrap] [--system-bundle|--all-assets] <tag> [out_dir] [modules_csv]}"
OUT_ROOT="${2:-$HOME/intact-local-releases}"
MODULES_CSV="${3:-}"

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
STAGE_ROOT="${INTACT_LOCAL_BUILD_ROOT:-$HOME/.cache/intact-local-build}"
STAGE="$STAGE_ROOT/$TAG/src"
WORK="$STAGE_ROOT/$TAG/work"
OUT="$OUT_ROOT/$TAG"

log() { printf '[local-build] %s\n' "$1"; }
err() { printf '[local-build][ERROR] %s\n' "$1" >&2; }

# ── the image that carries the toolchain ──────────────────────────────────
# build_release_package.py imports `services.image_map` from the backend
# package and shells out to docker; the backend image already has both, plus
# python3-yaml and grpc. Running it there rather than on the host is the same
# trick scripts/dev/build_local_release.sh uses -- the host has no grpc, so a
# host run dies on `import services`.
BUILD_IMAGE="${INTACT_BUILD_IMAGE:-}"
if [ -z "$BUILD_IMAGE" ]; then
    BUILD_IMAGE="$(docker image ls --format '{{.Repository}}:{{.Tag}}' \
        | grep '^intact-backend:' | head -1 || true)"
fi
if [ -z "$BUILD_IMAGE" ]; then
    err "no intact-backend image found locally, and none given via"
    err "INTACT_BUILD_IMAGE. The packager needs the backend's python deps"
    err "(services.image_map, grpc), which the host does not have."
    exit 1
fi
log "toolchain image: $BUILD_IMAGE"

# ── the SIGMA rule pack aws_sigma bundles ─────────────────────────────────
# CI clones SigmaHQ/sigma to /opt/sigma-rules and mounts it read-only into the
# builder (build-release-assets.yml, the `sigma` step). Without it the
# aws_sigma build warns, packages nothing, and package.py reports "No modules
# were packaged successfully. Check your internet connection and try again." --
# a message that sends you looking at the network when the real cause is a
# missing rule pack. Check for it up front and say the actual thing.
if ! find /opt/sigma-rules/rules/cloud/aws -name '*.yml' >/dev/null 2>&1 \
   || [ -z "$(find /opt/sigma-rules/rules/cloud/aws -name '*.yml' 2>/dev/null | head -1)" ]; then
    err "no SIGMA AWS rules under /opt/sigma-rules/rules/cloud/aws"
    err "the aws_sigma asset cannot be built without them. Clone them as CI does:"
    err "  sudo mkdir -p /opt/sigma-rules && sudo chown \"\$(id -un)\" /opt/sigma-rules"
    err "  git clone --depth 1 https://github.com/SigmaHQ/sigma /opt/sigma-rules"
    err "or pass a module list that excludes aws_sigma."
    exit 1
fi

# ── stage the source ──────────────────────────────────────────────────────
# NEVER build from the live checkout: build_release_package.py's
# _stamp_backend_pin() REWRITES config.yaml to pin the backend image to the
# tag being built. On this box config.yaml is the operator's live file holding
# real secrets and the running pins, and it is untracked-by-policy -- letting a
# build edit it is how a dev tool silently changes what the appliance runs.
#
# sudo, and then chown back: containers on this box write into the checkout as
# root (modules/iris/config/certificates/*.pem, modules/velociraptor/
# bundled_artifacts/*), and a plain rsync stops dead on the first one with
# "Permission denied" -- exit 23, having copied only part of the tree. A
# partial stage would build a package quietly missing files rather than fail.
log "staging $REPO_DIR -> $STAGE"
# WORK deliberately survives. Building the full set is ~25 GB of `docker save`
# and takes the best part of an hour, so a failure in the ninth module must not
# throw away the eight that already succeeded -- re-running skips whatever is
# already on disk (below). STAGE is always rebuilt: it is cheap, and it is the
# thing that must reflect the current checkout.
sudo rm -rf "$STAGE"
mkdir -p "$STAGE" "$WORK" "$OUT"
sudo rsync -a --exclude='.git' --exclude='data/' --exclude='backups/' \
      "$REPO_DIR/" "$STAGE/"
# ...except data/yara-seed, which is a BUILD INPUT rather than runtime state:
# the packager bundles it so an air-gapped install can seed VolWeb's rule
# corpus. Excluding all of data/ meant locally built packages shipped without
# it, and install.sh reported "No bundled YARA rule sets in this package —
# VolWeb starts with an empty rule corpus", which is a real difference from
# what CI produces rather than a quirk of the dev tool.
if [ -d "$REPO_DIR/data/yara-seed" ]; then
    sudo mkdir -p "$STAGE/data"
    sudo rsync -a "$REPO_DIR/data/yara-seed" "$STAGE/data/"
fi
sudo chown -R "$(id -u):$(id -g)" "$STAGE"

# A THIN BUNDLE: --bundle-only with a module list.
#
# The legacy bundle's contents come from RELEASE_MODULES, not from --module, so
# the only way to build a smaller one is to narrow that set. Doing it in the
# STAGED copy keeps the committed file at the full nine, which is what a real
# release must ship -- trimming the tracked file and forgetting to restore it
# is precisely how a backend-only package gets published by accident.
#
# ~1 GB and a few minutes instead of ~6.4 GB and most of an hour, which is what
# makes "build it, scp it, import it" a usable loop.
if (( BUNDLE_ONLY )) && [ -n "$MODULES_CSV" ]; then
    log "thin bundle: narrowing RELEASE_MODULES to '$MODULES_CSV' in the staged copy"
    MODULES_CSV="$MODULES_CSV" python3 - "$STAGE/scripts/ci/build_release_package.py" <<'PY'
import os, re, sys
path = sys.argv[1]
keep = {m.strip() for m in os.environ["MODULES_CSV"].split(",") if m.strip()}
src = open(path).read()
block = re.search(r"RELEASE_MODULES = \{.*?\n\}", src, re.S)
if not block:
    sys.exit("could not find RELEASE_MODULES in the staged packager")
new = "RELEASE_MODULES = {\n" + "".join(f'    "{m}",\n' for m in sorted(keep)) + "}"
open(path, "w").write(src[:block.start()] + new + src[block.end():])
print(f"[local-build] staged RELEASE_MODULES = {sorted(keep)}")
PY
fi

# The staged tree is mounted into the container AT THE SAME PATH it has on the
# host. packager/proc.py takes HOST_PATH from INTACT_HOST_PATH (defaulting to
# INTACT_PATH), and any `-v` it builds is interpreted by the host daemon -- so
# the two must agree or a bind mount silently points at nothing. The real CI
# workflow does the same thing by mounting $GITHUB_WORKSPACE at itself.
run_packager() {
    docker run --rm \
        -v /var/run/docker.sock:/var/run/docker.sock \
        -v "$STAGE:$STAGE" \
        -v "$WORK:$WORK" \
        -v /opt/sigma-rules:/opt/sigma-rules:ro \
        -e INTACT_PATH="$STAGE" \
        -e INTACT_HOST_PATH="$STAGE" \
        -e PYTHONPATH=/app \
        --entrypoint python3 \
        "$BUILD_IMAGE" \
        "$STAGE/scripts/ci/build_release_package.py" "$@"
}

# ── resolve the module set the same way CI's `resolve` job does ───────────
if [ -n "$MODULES_CSV" ]; then
    MODULES="$(tr ',' ' ' <<< "$MODULES_CSV")"
else
    MODULES="$(run_packager --tag "$TAG" --emit-matrix \
        | python3 -c 'import json,sys; print(" ".join(json.load(sys.stdin)))')"
fi
log "modules: $MODULES"

COMMIT="$(git -C "$REPO_DIR" rev-parse HEAD)"
log "source commit: $COMMIT"

# Resume must not mix trees.
#
# Every asset records the commit it was built from, and the index step asserts
# they all agree -- the same check CI runs, and it exists because a tag re-cut
# mid-build once produced two sets of assets nothing downstream could tell
# apart. Locally the equivalent is resuming a build after committing something:
# the staged tree is re-copied from the CURRENT checkout each run, so the
# modules rebuilt on the second pass genuinely come from a different tree than
# the ones kept from the first. Left alone it fails at the very END, after
# rebuilding everything, with "built from X, expected Y".
#
# So notice at the start instead, and rebuild from scratch rather than
# pretending the halves match.
STAMP="$WORK/.build-commit"
_stale=""
if [ -f "$STAMP" ]; then
    [ "$(cat "$STAMP")" != "$COMMIT" ] && _stale="built at $(cat "$STAMP")"
elif find "$WORK" -maxdepth 1 -name '*.meta.json' | grep -q .; then
    # Assets with no stamp predate this check, so their provenance is simply
    # unknown -- which for this purpose is the same as wrong. Discard rather
    # than assume they match and fail in the index step.
    _stale="built before this check existed, provenance unknown"
fi
if [ -n "$_stale" ]; then
    log "discarding the existing assets: $_stale, now at $COMMIT"
    log "  assets from two different trees cannot ship as one release -- the"
    log "  index step asserts they agree, exactly as CI does."
    sudo rm -rf "$WORK"
    mkdir -p "$WORK"
fi
printf '%s' "$COMMIT" > "$STAMP"

# ── build one asset per module ────────────────────────────────────────────
# --work-dir's BASENAME becomes the tarball's top-level directory, and every
# asset must use the SAME one (intact-upgrade-<tag>) or the N assets extract as
# siblings instead of merging into one package dir. This is the single most
# important argument here.
if (( BUNDLE_ONLY )); then
    log "--bundle-only: skipping the per-module assets"
    MODULES=""
fi

for m in $MODULES; do
    # Resume. The .meta.json sidecar, not the tarball, is the completion
    # marker: the tarball appears before the builder has written the sidecar
    # the index job needs, so keying off the tar would happily "skip" a module
    # that never finished and then fail in the index step with a confusing
    # "no manifest sidecar" instead of just rebuilding it.
    if find "$WORK" -maxdepth 1 -name "$TAG-$m.tar*.meta.json" \
            | grep -q .; then
        log "skipping $m (already built -- delete $WORK to force a rebuild)"
        continue
    fi
    log "building module asset: $m"
    run_packager --tag "$TAG" --module "$m" \
        --out "$WORK" \
        --work-dir "$WORK/intact-upgrade-$TAG" \
        --commit "$COMMIT"
done

if (( BUNDLE )); then
    log "building the legacy single-bundle asset (shape 1)"
    run_packager --tag "$TAG" \
        --out "$WORK" \
        --work-dir "$WORK/intact-upgrade-$TAG-bundle" \
        --commit "$COMMIT"
fi

if (( BUNDLE_ONLY )); then
    # No index and no merged manifest: shape 1 carries its manifest.json INSIDE
    # the tarball, and publishing an index beside it would make upgrade.sh take
    # the per-module branch for a release that has no per-module assets.
    find "$WORK" -maxdepth 1 \( -name "intact-upgrade-$TAG.tar" \
         -o -name "intact-upgrade-$TAG.tar.gz" \
         -o -name "intact-upgrade-$TAG.tar.gz.part-*" \) \
         -exec sh -c 'ln -f "$1" "$2/$(basename "$1")" 2>/dev/null || cp -f "$1" "$2/"' _ {} "$OUT" \;
    log "legacy bundle built -> $OUT"
    ls -la "$OUT"
    exit 0
fi

# ── reproduce the CI `index` job ──────────────────────────────────────────
log "assembling $TAG.index.json and $TAG.manifest.json"
TAG="$TAG" COMMIT="$COMMIT" EXPECTED_MODULES="$(python3 -c '
import json,sys; print(json.dumps(sys.argv[1].split()))' "$MODULES")" \
WORK="$WORK" OUT="$OUT" python3 <<'PY'
import datetime, glob, json, os, sys

tag, commit = os.environ["TAG"], os.environ["COMMIT"]
expected = set(json.loads(os.environ["EXPECTED_MODULES"]))
work, out = os.environ["WORK"], os.environ["OUT"]

metas = sorted(glob.glob(os.path.join(work, "**", "*.meta.json"), recursive=True))
if not metas:
    sys.exit("no .meta.json sidecars -- nothing was built")

entries, images, shas, transitive, problems = {}, {}, {}, {}, []
pins_source = "target-release"
for mp in metas:
    m = json.load(open(mp))
    mod = m.get("module")
    if not mod:
        continue

    if m.get("source_commit") != commit:
        problems.append("%s: built from %s, expected %s"
                        % (mod, m.get("source_commit"), commit))
    if m.get("release_tag") != tag:
        problems.append("%s: claims release %s, expected %s"
                        % (mod, m.get("release_tag"), tag))

    base = m["asset"]
    entries[mod] = {"asset": base, "version": (m.get("modules") or {}).get(mod),
                    "size": m.get("size"), "sha256": m.get("sha256"),
                    "parts": m.get("parts") or []}

    man = os.path.join(os.path.dirname(mp), base + ".manifest.json")
    if not os.path.exists(man):
        problems.append("%s: no manifest sidecar -- collisions with other "
                        "assets cannot be checked" % mod)
        continue
    c = (json.load(open(man)).get("contents") or {})
    for img in (c.get("images") or []):
        if img in images and images[img] != mod:
            problems.append("image %s claimed by both %s and %s"
                            % (img, images[img], mod))
        images[img] = mod
    for k, v in (c.get("sha256") or {}).items():
        if k in shas and shas[k] != v:
            problems.append("file %s differs between assets -- one would "
                            "overwrite the other" % k)
        shas[k] = v
    for tmod, deps in (c.get("transitive_versions") or {}).items():
        transitive.setdefault(tmod, {}).update(deps)
    if c.get("pins_source") == "local-fallback":
        pins_source = "local-fallback"

missing = sorted(expected - set(entries))
if missing:
    problems.append("expected asset(s) never appeared in the index: %s"
                    % ", ".join(missing))
extra = sorted(set(entries) - expected)
if extra:
    problems.append("asset(s) built for module(s) outside the release matrix: %s"
                    % ", ".join(extra))

# Deliberately NOT fatal here, unlike CI. On a dev box config.yaml IS the only
# source of pins -- there is no target release to fetch them from -- so
# local-fallback is the normal case rather than the "GitHub died mid-build"
# emergency it signals in CI. Say so loudly instead of failing.
if pins_source == "local-fallback":
    print("NOTE: pins_source=local-fallback -- sidecar pins came from this "
          "box's config.yaml. Expected for a local build; in CI this is a "
          "hard failure.")

if problems:
    for p in problems:
        print("ERROR: %s" % p)
    sys.exit(1)

index = {"release_tag": tag, "source_commit": commit, "assets": entries}
json.dump(index, open(os.path.join(out, "%s.index.json" % tag), "w"), indent=2)
print("indexed %d module(s): %s" % (len(entries), ", ".join(sorted(entries))))

manifest = {
    "package_version": "1.0",
    "created": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "created_by": "scripts/dev/build_local_release_assets.sh",
    "versions": {mod: e["version"] for mod, e in entries.items() if e.get("version")},
    "contents": {
        "release_tag": tag,
        "pins_source": pins_source,
        "transitive_versions": transitive,
        "sha256": shas,
    },
}
json.dump(manifest, open(os.path.join(out, "%s.manifest.json" % tag), "w"), indent=2)
print("manifest: %d pin(s), %d sidecar pin(s), %d checksummed file(s)"
      % (len(manifest["versions"]),
         sum(len(v) for v in transitive.values()), len(shas)))
PY

# ── bootstrap asset (--bootstrap) ─────────────────────────────────────────
# Mirrors the `bootstrap-asset` job. install.sh + lib/ + scripts/ in one plain
# tar, for bringing up a box that has no checkout yet.
#
# Built from the STAGED copy, not the live checkout, for the same reason
# everything else here is: the live tree carries the operator's secrets and
# root-owned container droppings.
#
# PLAIN tar, and the sha256 sidecar is the bare hash with no filename -- both
# match the job exactly (`tar -cf`, `sha256sum | awk '{print $1}'`). The
# system-bundle sidecar below is deliberately the FULL sha256sum line instead;
# they disagree in CI and copying that disagreement is the point of this
# script.
if (( BOOTSTRAP )); then
    log "building the bootstrap asset"
    _bs_parent="$WORK/bootstrap-stage"
    rm -rf "$_bs_parent"
    mkdir -p "$_bs_parent/$TAG"
    cp -a "$STAGE/install.sh" "$STAGE/lib" "$STAGE/scripts" "$_bs_parent/$TAG/"
    # Neither belongs on a customer box: scripts/ci needs a full backend image
    # to import services.image_map, and scripts/dev fabricates packages FROM a
    # live tree -- shipping it is how make_test_package.sh's own secret-leak
    # class would travel to a customer instead of just this repo.
    rm -rf "$_bs_parent/$TAG/scripts/ci" "$_bs_parent/$TAG/scripts/dev"
    if ! bash -n "$_bs_parent/$TAG/scripts/upgrade.sh"; then
        err "the staged scripts/upgrade.sh does not parse -- refusing to ship it"
        exit 1
    fi
    tar -C "$_bs_parent" -cf "$WORK/${TAG}-bootstrap.tar" "$TAG"
    sha256sum "$WORK/${TAG}-bootstrap.tar" | awk '{print $1}' \
        > "$WORK/${TAG}-bootstrap.tar.sha256"
    rm -rf "$_bs_parent"
    log "  $(du -h "$WORK/${TAG}-bootstrap.tar" | cut -f1) -> ${TAG}-bootstrap.tar"
fi

# ── system bundle (--system-bundle) ───────────────────────────────────────
# Mirrors the `system-bundle` job: Docker + host dependencies as .deb files
# with an apt Packages index, so install.sh can satisfy host deps on a machine
# with no internet.
#
# SLOW AND NETWORKED: pulls ubuntu:24.04 and downloads ~1 GB of packages. It is
# also the one asset no upgrade ever reads -- lib/upgrade/package.sh skips it
# by name -- so it is off unless asked for.
#
# The build script is the job's, verbatim in shape, including the purge of the
# bootstrap tools before the real capture: curl/gnupg/lsb-release are installed
# only to ADD Docker's apt repo, and leaving them installed makes apt consider
# them already satisfied, so they never get downloaded and the bundle silently
# lacks them on a target that has none.
if (( SYSBUNDLE )); then
    log "building the system bundle (ubuntu:24.04, ~1 GB of .deb downloads)"
    _sb_out="$WORK/system-bundle-out"
    rm -rf "$_sb_out"; mkdir -p "$_sb_out"
    cat > "$WORK/build_bundle.sh" <<'BUILDEOF'
#!/bin/bash
set -euo pipefail
apt-get update -qq
apt-get install -y -qq curl gnupg ca-certificates lsb-release

install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" \
  | tee /etc/apt/sources.list.d/docker.list > /dev/null
apt-get update -qq

apt-get purge -y -qq curl gnupg lsb-release
apt-get autoremove -y -qq --purge

mkdir -p /bundle
rm -f /var/cache/apt/archives/*.deb
apt-get install -y -qq --download-only --reinstall \
  docker-ce docker-ce-cli containerd.io docker-compose-plugin \
  curl wget git python3 python3-pip python3-yaml openssl jq dnsutils lsb-release ca-certificates gnupg
cp /var/cache/apt/archives/*.deb /bundle/

apt-get install -y -qq dpkg-dev
cd /bundle
dpkg-scanpackages . /dev/null > Packages 2>/dev/null
gzip -kf Packages

. /etc/os-release
echo "$VERSION_ID" > /bundle/ubuntu-version
echo "== bundle built: $(ls /bundle | wc -l) files =="
du -sh /bundle
BUILDEOF
    docker run --rm \
        -v "$WORK/build_bundle.sh:/build_bundle.sh:ro" \
        -v "${_sb_out}:/bundle" \
        ubuntu:24.04 bash /build_bundle.sh
    # Root-owned inside the container; the tar and everything after runs as us.
    sudo chown -R "$(id -u):$(id -g)" "$_sb_out"
    tar -C "$_sb_out" -cf "$WORK/${TAG}-system-bundle.tar" .
    # FULL sha256sum line here, unlike bootstrap above -- that is what the job
    # writes, and lib/release.sh reads it back expecting that shape.
    ( cd "$WORK" && sha256sum "${TAG}-system-bundle.tar" > "${TAG}-system-bundle.tar.sha256" )
    rm -rf "$_sb_out" "$WORK/build_bundle.sh"
    log "  $(du -h "$WORK/${TAG}-system-bundle.tar" | cut -f1) -> ${TAG}-system-bundle.tar"
fi

# ── publish the assets next to the index ──────────────────────────────────
# Only what a real release page carries. The .meta.json and per-asset
# <asset>.manifest.json sidecars are BUILD artifacts the index job consumes and
# the release deliberately does not publish -- copying them would make the
# local release a shape no box will ever actually see, and in particular would
# hand upkg_expand_args a second loose manifest to choose between.
#
# Overwrite, never skip. The index is regenerated from WORK on every run, so an
# asset left behind in OUT from an earlier build would be advertised with the
# NEW asset's sha256 and fail its digest check on download -- as a corrupt-file
# error, which is the most misleading way for a stale copy to announce itself.
# Hard-linked because both trees are on the same filesystem and the set is
# ~5 GB; `cp` fallback for when they are not.
# The two .sha256 sidecars ARE published (the release page carries them, and
# lib/release.sh reads the system-bundle one back), unlike the .meta.json and
# per-asset manifests above which are build-only.
find "$WORK" -maxdepth 1 \( -name "$TAG-*.tar" -o -name "$TAG-*.tar.gz" \
     -o -name "$TAG-bootstrap.tar.sha256" -o -name "$TAG-system-bundle.tar.sha256" \
     -o -name "intact-upgrade-$TAG.tar" -o -name "intact-upgrade-$TAG.tar.gz" \
     -o -name "intact-upgrade-$TAG.tar.gz.part-*" \) \
     -exec sh -c 'ln -f "$1" "$2/$(basename "$1")" 2>/dev/null || cp -f "$1" "$2/"' _ {} "$OUT" \;

log "release built -> $OUT"
ls -la "$OUT"
log "serve it with: scripts/dev/serve_local_release.sh $OUT_ROOT"
