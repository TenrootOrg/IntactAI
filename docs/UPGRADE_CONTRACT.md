# The upgrade contract

> **STALE — pending rewrite.** This document describes the in-container Python
> upgrade engine (`modules/backend/services/upgrade/`, the Phase 1 / Phase 2
> handover) that was **deleted** in favour of a shell engine driven from the
> target release's own code. The sections below are kept for historical
> reference only and no longer describe how an upgrade runs.
>
> The current architecture:
> - **`scripts/bootstrap_upgrade.sh`** — frozen stage 1: fetch the target
>   release's `<tag>-engine.tar.gz`, verify its sha256, exec it. This is the
>   one documented upgrade command.
> - **`scripts/upgrade.sh` + `lib/upgrade/*.sh`** — the engine the bootstrap
>   hands over to; it applies the package module by module.
> - **`scripts/build_engine_asset.sh`** — builds the frozen engine asset.
> - The three dashboard flows (online upgrade, prepare package, import
>   package) all route through the bootstrap; see
>   `modules/backend/routes/upgrade_routes.py` and
>   `modules/backend/services/upgrade_launcher.py`.

Read this before changing anything under `scripts/upgrade.sh`,
`lib/upgrade/`, `scripts/bootstrap_upgrade.sh`, or
`scripts/ci/build_release_package.py`.

## How an upgrade actually works

The backend runs code **baked into `intact-backend:<release>`** — never from
host bind-mounts. An upgrade is therefore an image swap, not a file copy:

1. **Phase 1** runs on the box's CURRENT (old) code. It loads
   `images/intact-backend-<target>.tar` from the package, mirrors the source
   tree, persists resume state, and hands off to a **detached helper container**
   (spawned from the OLD image, so it survives its own parent being stopped)
   which recreates `intact_backend` onto the new image.
2. **Phase 2** resumes inside the NEW container, driven by the NEW release's
   code, and upgrades the remaining modules.

The consequence — and the whole point — is that **an old box never executes new
code**. It only loads an image and recreates. So a new release may freely change
backend code, pip dependencies, the base image, the frontend, and module logic:
whatever it does, Phase 2 runs under the new release's own rules.

## The three things you must not break casually

Phase 1 executes on the OLD release. Everything it touches is therefore a
backward-compatibility surface — and it is deliberately tiny. Changing any of
these requires a **stepping-stone release**: ship the mechanism in release N,
flip the behaviour in N+1, never both at once.

### 1. Package layout
- The backend image is bundled as `images/intact-backend-<release-tag>.tar`.
- `manifest.json` carries `versions.intact = <release-tag>` and lists every
  bundled image under `contents.images`.

The name must match what the target resolves, or the shipped image is invisible
and the box silently rebuilds from source. That exact bug shipped in
intact-20260721 (baked as `intact-backend:development`). `_verify_package_usable()`
in `scripts/ci/build_release_package.py` now fails the CI build if it recurs.

### 2. Recreate mechanics
- Container names `intact_backend` / `intact_tusd`; compose project resolved
  from the running container's `com.docker.compose.project` label.
- `BACKEND_VERSION` in `modules/backend/.env` selects the image, and the compose
  declares it **required** (`:?`, no default) so a box can never silently boot a
  stale install-day image.
- `INTACT_HOST_PATH` must also be in `.env`. It used to be only a shell export
  from `install.sh`; `docker restart` preserved mounts so it never surfaced, but
  a **recreate** resolves the compose default and silently breaks any
  non-default install path.

### 3. State lives outside the container
Everything that must survive a recreate is on a host bind or a named volume:
`data/` (intact.db, upgrade_state), `config.yaml`, module `.env` files,
velociraptor/timesketch config, and the named volumes for uploads, memory dumps,
report downloads and upgrade packages.

## Rules that follow

- **Never reintroduce a `./services:/app/services` bind-mount** to the backend
  compose. That sentinel is exactly how `backend_full_mode()` decides Full vs
  legacy; a target carrying it is now REJECTED before anything is touched
  (`upgrade_intact_offline`, "LEGACY TARGET REJECTED").
- **`versions.backend` must track the release tag.** `backend_target_tag()`
  resolves `config.yaml versions.backend` → `VERSION` → `'development'`. Both of
  the first two must be the release tag, or convergence looks for an image the
  package never shipped.
- **A failed `docker compose build` does not prove the image is missing.** It
  can succeed and still hang without exiting (observed 2026-07-22). Re-inspect
  the image store before declaring failure.
- **Do not delete `self_heal_backend_swap` or the boot `recreate-failed-*.json`
  marker check.** They are crash recovery, not legacy support, and the marker
  check must stay BEFORE the pending-upgrade read — otherwise a rolled-back boot
  resumes Phase 2 on old code against new-release state.

## Verifying a release before shipping it

```bash
# 1. CI must pass its own self-check (it fails the build otherwise):
#    "self-check: intact-backend-<tag>.tar bundled — the target will load it, not rebuild."

# 2. Confirm the published asset really carries the image:
#    manifest.json -> contents.images must contain intact-backend-<tag>.tar,
#    NOT intact-backend-development.tar

# 3. On a real upgrade the log must show, in this order:
#    "Full-mode release detected — backend runs from image intact-backend:<tag> (swap + recreate)"
#    "PHASE 1 COMPLETE - Intact.AI upgraded (Full-mode image swap)"
#    and must NOT show "Baking ... from the live source tree" (that is the slow fallback).
```
