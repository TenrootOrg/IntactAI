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
ARGS=()
for a in "$@"; do
    case "$a" in
        --bundle) BUNDLE=1 ;;
        *) ARGS+=("$a") ;;
    esac
done
set -- "${ARGS[@]:-}"

TAG="${1:?usage: build_local_release_assets.sh [--bundle] <tag> [out_dir] [modules_csv]}"
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
sudo rm -rf "$STAGE" "$WORK"
mkdir -p "$STAGE" "$WORK" "$OUT"
sudo rsync -a --exclude='.git' --exclude='data/' --exclude='backups/' \
      "$REPO_DIR/" "$STAGE/"
sudo chown -R "$(id -u):$(id -g)" "$STAGE"

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

# ── build one asset per module ────────────────────────────────────────────
# --work-dir's BASENAME becomes the tarball's top-level directory, and every
# asset must use the SAME one (intact-upgrade-<tag>) or the N assets extract as
# siblings instead of merging into one package dir. This is the single most
# important argument here.
for m in $MODULES; do
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

# ── publish the assets next to the index ──────────────────────────────────
# Only what a real release page carries. The .meta.json and per-asset
# <asset>.manifest.json sidecars are BUILD artifacts the index job consumes and
# the release deliberately does not publish -- copying them would make the
# local release a shape no box will ever actually see, and in particular would
# hand upkg_expand_args a second loose manifest to choose between.
find "$WORK" -maxdepth 1 \( -name "$TAG-*.tar" -o -name "$TAG-*.tar.gz" \
     -o -name "intact-upgrade-$TAG.tar" -o -name "intact-upgrade-$TAG.tar.gz" \
     -o -name "intact-upgrade-$TAG.tar.gz.part-*" \) -exec cp -n {} "$OUT/" \;

log "release built -> $OUT"
ls -la "$OUT"
log "serve it with: scripts/dev/serve_local_release.sh $OUT_ROOT"
