# Upgrading Intact.AI

Upgrades run from the shell on the appliance, as root. There is no upgrade
button in the dashboard.

```bash
sudo bash scripts/upgrade.sh --list                    # what can I upgrade to?
sudo bash scripts/upgrade.sh intact-20260810           # online
sudo bash scripts/upgrade.sh --package /media/usb/pkg.tar   # air-gapped
```

## It does not need the platform to be working

This is the point of running it from the shell. `upgrade.sh` talks to docker
and to this checkout — never to the backend, the dashboard or any API. So it
works when the platform is broken, which is when you most need it:

- the backend is stopped, crash-looping, or was never installed
- nginx is down and the dashboard does not load
- you are on SSH with no browser

Upgrading the backend while the backend is *down* is a supported path and is
tested: the run loads the new image, checks it compiles, starts the container
and brings nginx back with it.

Run it however you like — from any directory, by relative or absolute path,
with `bash` or `sh`, or through a symlink:

```bash
sudo ln -s /home/tenroot/intact/scripts/upgrade.sh /usr/local/bin/intact-upgrade
sudo intact-upgrade --list
```

`--list` and `--help` do not need root. Everything else does, and says so with
the exact command to re-run.

The one thing that will not work is copying `upgrade.sh` somewhere on its own
— it reads `lib/`, `modules/` and `config.yaml` from the checkout. It tells
you that, and prints the path it looked in, rather than failing on a missing
library later.

## Before you start

- Upgrade **one release at a time**. Only N→N+1 is ever QA'd, and the module
  upgraders assume they are moving one release, not four. `--list` tells you
  the next one.
- Nothing needs stopping first. `scripts/upgrade.sh` stops and starts what it needs.
- The run takes 5–20 minutes depending on how many modules moved and whether
  images have to be downloaded.

## What it does

```
verify the package   sha256, gzip integrity, unsafe-path refusal,
                     per-file checksums, format gate
plan                 what is installed vs what the package carries,
                     downgrade refusal, disk check
upgrade each module  intact first, then elk, timesketch, plaso, iris,
                     velociraptor, aws_sigma, o365rc, volweb, portainer
refresh              Velociraptor artifacts/tools/downloads
report               what upgraded, what was skipped, what rolled back
```

Each module is a transaction. If a step fails, that module is rolled back to
the version it was on and the run continues to the next one — a single broken
module never leaves the other nine half-upgraded.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Everything upgraded cleanly, or there was nothing to do |
| `1` | At least one module was rolled back, or needs manual repair |
| `2` | Refused before touching anything (bad package, downgrade, no disk) |
| `3` | Everything applied, but at least one module is degraded |

`3` is worth reading rather than ignoring: the platform is running and the
upgrade did apply, but something is not fully right — a sidecar that did not
come back, a cluster that went from green to yellow.

## Useful flags

```
--dry-run              verify the package and print the plan, change nothing
--only elk,iris        upgrade just these
--skip velociraptor    upgrade everything except these
--expect-sha256 <hex>  refuse the package unless the archive matches
--velo-refresh         re-run only the Velociraptor refresh step
--yes                  never prompt
```

`--dry-run` is the safe way to see what a package would do. It runs every
verification and prints the full version table, then stops.

## Reading the report

```
Upgraded (3):
  ✔ elk 9.4.2 -> 9.4.4
Skipped (2):
  · volweb — already at 3.16.0
Applied but degraded (1):
  ! portainer — degraded: agent is not running
Rolled back (1) — these are back on their previous version:
  ↩ iris — health gate (rc=1); restored to v2.4.26
NEEDS MANUAL REPAIR (1):
  ✘ timesketch — pg_dump failed (rc=1) AND ROLLBACK FAILED
```

The last two are different situations and are deliberately not merged.
**Rolled back** means the module is back on its old version and working —
nothing to do beyond finding out why it failed. **Needs manual repair** means
the rollback itself also failed; that module needs a human.

## What protects your data

Upgrades are not supposed to be able to lose evidence, and the mechanisms
below exist to make that true rather than hoped-for.

| Module | Protection |
|---|---|
| Timesketch | `pg_dump` before anything, kept afterwards under `backups/timesketch/`. Row and OpenSearch document counts compared across the upgrade; a drop fails the module. A Postgres major-version change requires wiping the data volume, and that is **refused outright** if the dump failed. |
| IRIS | `pg_dump` before the swap, kept under `backups/iris/`. |
| VolWeb | `pg_dump` before the swap, kept under `backups/volweb/`. |
| Velociraptor | The CA fingerprint is captured before and verified after. A changed CA fails the upgrade and restores the original config. |
| Elasticsearch | Downgrades refused. Credentials are never rotated. |
| All | `.env` snapshotted and restored on failure. Named volumes are never removed except by Timesketch's Postgres-major path, which requires a dump. |

Two limits worth knowing:

- **OpenSearch is not backed up.** Timesketch's `pg_dump` covers sketches,
  timelines, users and ACLs — the *metadata*. The timeline **events** live in
  OpenSearch. A lost index is detected (the document count drops) but cannot
  be restored from anything the upgrade takes.
- **There is no whole-platform undo.** Rollback is per module and forward-only.

## Downgrades are refused

There is no `--force`. This is not caution, it is that a downgrade does not
work: Elasticsearch will not open a data directory written by a newer version,
and Postgres and OpenSearch forward-migrate their volumes on first boot with
no way back. Attempting one does not restore the old state, it destroys the
current one. Genuinely reverting a module means wiping its volume and
restoring from a backup — a deliberate operation, not an upgrade.

## If something goes wrong

The full log is `upgrade_<timestamp>.log` in the repo root, and its path is
printed at the end of every run.

- **A module rolled back.** It is on its old version and running. The log
  names the step that failed and the last few lines it produced.
- **A module needs manual repair.** Its snapshot is kept and its path is in
  the log — `data/tmp/intact-rollback-*` for the platform,
  `data/tmp/velo-upgrade-*` for Velociraptor, `modules/*/.env.upgrade-bak-*`
  for the rest. Database dumps are under `backups/<module>/`.
- **The Velociraptor refresh failed.** Velociraptor itself is fine; artifacts
  or tools may be stale. Re-run just that step:
  `sudo bash scripts/upgrade.sh --velo-refresh --package <dir>`.
- **Re-running is safe.** Modules already at the target version are skipped.

## Air-gapped upgrades

Build the package on a machine with internet access:

```bash
bash scripts/prepare_package.sh intact-20260810 /media/usb
```

Carry it across and point `--package` at the file or the directory:

```bash
sudo bash scripts/upgrade.sh --package /media/usb/intact-upgrade-intact-20260810.tar
```

Everything comes from the package; nothing is fetched. If the package is
missing something a module needs, that module fails loudly rather than
quietly reaching for a registry.

## Why this runs on the host

The upgrade engine used to live inside the backend container, which meant it
had to replace the container it was running in. That needed a two-phase
handoff, a state table that survived the restart, a helper container spawned
from the outgoing image, a watchdog, a boot-time self-heal and resume
counters — thousands of lines whose only job was surviving their own suicide,
and a dashboard session that dropped mid-upgrade every time.

From the host, the backend is just another container.
