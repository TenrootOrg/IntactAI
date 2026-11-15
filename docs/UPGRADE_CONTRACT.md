# The upgrade contract

Read this before changing anything under `scripts/upgrade.sh`,
`scripts/bootstrap_upgrade.sh`, `lib/upgrade/`, `scripts/build_engine_asset.sh`,
`scripts/prepare_package.sh`, `scripts/ci/build_release_package.py`, or the
dashboard side in `modules/backend/services/upgrade_launcher.py` and
`modules/backend/routes/upgrade_routes.py`.

> Rewritten 2026-11 for the bash engine. The previous version described the
> in-container Python engine (`modules/backend/services/upgrade/`, a Phase 1 /
> Phase 2 handover, `upgrade_intact_offline`, `self_heal_backend_swap`,
> `recreate-failed-*.json`, "PHASE 1 COMPLETE"). All of that was deleted; none
> of those symbols or log lines exist any more. Only the legacy resume below
> still knows about the old `upgrade_state` table.

## The one idea

**An upgrade runs the TARGET release's code against the live tree.** The
release being installed decides how its own package is applied. The code
already on the box does as little as possible: fetch the target's engine,
verify it, and `exec` it.

Everything that the old (installed) release runs before that `exec` is a
backward-compatibility surface, because it is already deployed and cannot be
changed. Keep it tiny. Change it only through a stepping-stone release: ship
the new mechanism in N, depend on it in N+1.

## How a run flows

```
operator / dashboard
  └─ scripts/bootstrap_upgrade.sh          OLD release's copy (frozen)
       fetch <tag>-engine.tar.gz (+ .sha256)  or take it from the package
       verify sha256 → extract to /var/lib/intact/engine/engine-<digest16>/
       check BOOTSTRAP_PROTOCOL → bash -n → write data/tmp/upgrade-handoff-<pid>.json
       export INTACT_UPGRADE_REEXEC=1
       exec <engine>/scripts/upgrade.sh --root <appliance> --handoff <json> <args…>
  └─ scripts/upgrade.sh + lib/upgrade/*.sh  TARGET release's code
       lock → acquire package → plan → prechecks → module loop
       → post-upgrade gate → report → single exit code
```

- **CLI.** `sudo bash scripts/upgrade.sh <tag>` (or `--package <file>`) starts
  in the installed `upgrade.sh`. It takes the lock, sweeps stale scratch, and
  hands straight to the installed `bootstrap_upgrade.sh` before touching any
  payload. If there is no bootstrap beside it, it warns and runs itself. That
  is the manual path for a checkout that *is* the target release.
- **Dashboard.** The route checks the lock (`_upgrade_gate`, 409 if held),
  creates the run row, and `upgrade_launcher.launch()` starts a sibling helper
  container `intact-upgrade-runner-<run_id>` from the current backend image
  (`--network host`, docker.sock, and the appliance at its host path). The
  helper runs `data/tmp/upgrade-launch-<run_id>.sh`, which calls the appliance's
  `scripts/bootstrap_upgrade.sh` (or the image's `/app/host-engine` copy on a
  box that has none) with `--log data/tmp/upgrade-<run_id>.log`. The helper
  is a sibling, not a child, because the first module recreates
  `intact_backend` itself.
- **Read-only modes.** `--list` and `--plan <tag>` stop before the lock.
  `--dry-run` acquires, verifies and plans, then stops. The dashboard's package
  preview and preflight run `bootstrap_upgrade.sh --package <p> --dry-run`
  synchronously.
- **`--prepare`.** `bootstrap_upgrade.sh <tag> --prepare [dir]` execs the
  target's own `scripts/prepare_package.sh` to build an air-gap package.

## Frozen surfaces (old code runs these)

### 1. The bootstrap contract (`scripts/bootstrap_upgrade.sh` header)
- Asset `<tag>-engine.tar.gz` plus `.sha256`, at the release download URL and
  at the top level of a `prepare_package.sh` wrapper.
- Flat layout: `BOOTSTRAP_PROTOCOL` (currently `1`), `VERSION`, `install.sh`,
  `lib/`, `scripts/`. Built by `scripts/build_engine_asset.sh`.
- Entry point `scripts/upgrade.sh`, called as
  `--root <appliance> --handoff <json> [--log <path>] <forwarded args>`.
  Unknown flags pass through. `--engine`, `--root`, `--handoff` and `--prepare`
  are stripped and re-emitted.
- The sha256 check is mandatory (`--no-verify` was removed). The engine is
  extracted root-only, `--no-same-owner --no-same-permissions`. Group- or
  world-writable `.sh` files are refused.
- A release that cannot be driven by this contract ships a higher
  `BOOTSTRAP_PROTOCOL`, and old bootstraps refuse it cleanly.

Do not add features to the bootstrap. Add them to `scripts/upgrade.sh`, which
ships with each release.

### 2. The dashboard launcher (old backend runs this)
The installed backend's `upgrade_launcher.py` launches the run, and after
`intact` recreates the backend the NEW backend's copy reattaches
(`reconcile_on_boot`). Both versions must agree on:
- `data/tmp/upgrade-<run_id>.log`: the engine's `--log`, tailed by line
  offset (`details.tail_offset`).
- `data/tmp/upgrade-<run_id>.done.json`: `{"rc": N}`, written by the launch
  script once the engine exits (written to `.tmp`, then renamed).
- `data/tmp/upgrade-<run_id>.cancel`: Stop writes it. The engine polls for it
  (`${LOG_FILE%.log}.cancel`) at every `u_do` and every second inside timed
  steps, and removes it on exit.
- Run `details`: `helper_container`, `log_path`, `done_path`, `tail_offset`.
- Exit code → status: `0`/`3` completed, `130`/`143` cancelled, anything
  else failed.

### 3. The backend image swap (`lib/upgrade/intact/`)
- The package carries `images/intact-backend-<tag>.tar` (or `.tar.gz`), and
  `manifest.json` carries `versions.intact = <tag>`. The image is in no
  registry, so a missing tar is a hard failure (`_intact_ensure_image`).
  `_verify_package_usable()` in `scripts/ci/build_release_package.py` fails the
  CI build when the name is wrong. That exact bug shipped in intact-20260721,
  baked as `intact-backend:development`.
- `BACKEND_VERSION` in `modules/backend/.env` selects the image, and the
  compose requires it (`${BACKEND_VERSION:?…}`, no default).
- `INTACT_HOST_PATH` must also be in `.env` (`_intact_stamp`), because a
  recreate resolves the compose default and silently breaks a non-default
  install path.
- `config.yaml versions.backend` must equal the release tag. The next
  install or upgrade regenerates `.env` from it, and CI checks it.
- Container names `intact_backend` / `intact_tusd`. The swap is
  `docker compose up -d --no-build --pull never backend` from
  `modules/backend` (`_intact_bring_up`). A container left under another
  compose project by the 0726 engine is removed and recreated.
- **Never add a `./services:/app/services` bind mount** to the backend
  compose. `scripts/ci/packager/backend_mode.py:backend_full_mode()` uses its
  absence to decide that the backend runs from the image and that the image
  must be bundled.

### 4. State lives outside the container
`data/` (intact.db, `data/state/` secrets and certs via
`lib/state_registry.sh`), `config.yaml`, the module `.env` files, and the
named volumes. Nothing that must survive a recreate may live in the
container's writable layer.

## Engine rules (target code; change freely, but keep these true)

- **Error model.** `set -o pipefail`, no `set -e`. A failing step aborts its
  own module and the loop moves on. There is one exit decision, at the bottom
  of `main()` (`upgrade_exit_code`, `lib/upgrade/report.sh`):
  - `0`: clean, or nothing to do.
  - `1`: a module rolled back or needs manual repair.
  - `2`: refused before anything was touched (lock held, not root, bad
    package, downgrade, disk).
  - `3`: everything applied, but something is degraded, or the
    post-upgrade gate (`u_post_upgrade_gate`) found a problem.
  - `130`: interrupted.
- **Transactions** (`lib/upgrade/core.sh`). Each module is
  `u_begin` … `u_do` steps with `u_undo` registrations … `u_end <policy>`.
  After the first failure every later `u_do` is a no-op, and `u_undo` stops
  registering. `u_end` is the only thing that adds to `UPGRADE_OK`, and it
  never does so on a timeout or an unreachable probe. `intact.sh` may move
  `intact` from OK to DEGRADED when its sidecars cannot move.
- **Order** (`UPGRADE_ORDER`, `lib/upgrade/plan.sh`). `intact` runs first,
  so a dashboard run loses its backend within the first minutes.
- **Lock.** `data/tmp/upgrade.lock`, `flock` on fd 9, held until the process
  exits. The fd survives the `exec` hops. Every run except a hopped
  `--dry-run` takes it, including the hopped side
  (`INTACT_UPGRADE_REEXEC=1`). An inherited fd 9 that already is the lock is
  re-locked, which is a no-op and cannot deadlock, and anything else is opened
  fresh. The dashboard's `_upgrade_gate`, `_upgrade_in_flight`,
  `ensure_host_engine` and the maintenance purge all probe this same file.
  So do not rename it, and do not delete it while it is held: a new file is a
  new inode and a new lock.
- **Cancel.** Polled, not signalled, because bash ignores SIGTERM while it waits
  on a foreground step. The loop skips every module after a Stop
  ("cancelled before it started"), and only the module in flight unwinds.
- **Scratch.** Extraction goes under `data/tmp/upgrade-pkg-*`.
  `upkg_cleanup` runs from the EXIT trap. A failed image load sets the
  keep-for-retry marker (`data/tmp/.upgrade-keep-scratch`), which keeps the
  tree for `--package-dir`. The marker and the freed-tars tally are per-run
  state, cleared at the start and exit of each locked run (an unlocked
  hopped `--dry-run` leaves them alone).
  `upkg_sweep_stale_scratch` reclaims anything older than 48h.
- **Pins.** `u_snapshot_pins` captures config.yaml pins before `intact`
  merges the package's pins, so a rollback restores the old pin as well as the
  `.env`. `config.yaml` is written in place (it is bind-mounted by inode).
  Never write a temp file and `mv` it over the original.
- **Downgrades are refused** (`plan_reject_downgrades`). Rolling ELK back to
  an older `ELASTIC_VERSION` leaves Elasticsearch unable to start. The
  Velociraptor CA (`data/velociraptor/`, `lib/upgrade/velociraptor/snapshot.sh`)
  and the search-engine volumes are the known data traps.
- **Engine refresh.** On every backend start, `ensure_host_engine()` rewrites
  the appliance's `lib/` and `scripts/` from the image's `/app/host-engine`,
  unless an upgrade holds the lock. Rebuild the image after engine edits.

## Legacy paths still supported

- **intact-20260726 (Python engine) boxes.** Its Import UI swaps in the new
  image and then hands to a Phase 2 that no longer exists.
  `resume_legacy_two_phase()` reads the old `upgrade_state` row
  (`awaiting_restart`) and finishes the remaining modules with the bash engine.
  `_intact_clear_legacy_upgrade_state` drops the table once `intact` succeeds.
- **Packages with the old `source/{backend,frontend}` layout** are still
  mirrored by the `intact` module.

## Verifying a release before shipping it

```bash
# 1. CI's own self-check must print:
#    "[ci-package] self-check: intact-backend-<tag>.tar bundled — the target will load it, not rebuild."
# 2. The release must carry <tag>-engine.tar.gz and its .sha256, and a prepared
#    package must carry both at its top level.
# 3. A real upgrade's log must show, in order:
#    "engine verified (sha256 …)"
#    "handing over to the <tag> release's own upgrade engine"
#    "[1/N] INTACT: <from> -> <tag>"
#    "loading intact-backend:<tag> from intact-backend-<tag>.tar"   (unless already present)
#    "ok: recreate the backend"
#    "intact: upgraded to <tag>"
#    and the run must exit 0. Exit 3 means look at the report and ATTENTION block.
```
