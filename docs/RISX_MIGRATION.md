# Migrating a risx-mssp box to Intact.AI (Velociraptor preserved)

`scripts/migrate/migrate_from_risx.sh` converts a legacy risx-mssp install
into a fresh intact install **on the same machine**, preserving exactly one
thing: the Velociraptor deployment. Every already-enrolled endpoint keeps
connecting — same `client_id`, no reinstall, no touch — and all historical
collections/hunts survive.

Everything else (Timesketch, IRIS, ELK, MISP, …) is removed and starts fresh
in intact.

## Why the clients keep working

A deployed Velociraptor client pins three things from the config embedded in
its installer, and the migration preserves all three:

| pinned by the client | preserved how |
|---|---|
| the **CA certificate** | the legacy CA cert + private key are transplanted into intact's `server.config.yaml` |
| the **nonce** (`Client.nonce`) | transplanted verbatim |
| **`server_urls`** (`https://<host>:8000/`) | same machine + intact publishes the same 8000/8001/8889 ports; intact's `domain` is pre-set to the legacy host |

The client's identity (its keypair → `client_id`) lives in the client's own
writeback file, so once trust + endpoint match, every client reconnects as
itself. Historical data survives because the legacy datastore is copied into
intact's `velociraptor_velociraptor_datastore` volume; Velociraptor 0.77.x
reads and forward-migrates the old datastore in place (upstream-supported).

intact's own machinery does the finishing work: the velociraptor container
entrypoint generates a server config **only if absent** (so the seeded
transplant wins) and re-derives `client.config.yaml` + `api.config.yaml`
from it on every boot — which automatically re-issues the backend's gRPC API
cert from the transplanted CA.

## Usage

```bash
# on the risx-mssp box, as the platform user (not root):
export GITHUB_TOKEN=...   # repo read access to TenrootOrg/IntactAI
bash scripts/migrate/migrate_from_risx.sh
```

Phases (interactive checkpoints in **bold**):

0. **Preflight** — finds the risx install, prints legacy version, CA
   fingerprint, client count + agent-version histogram, disk math, and a
   tiered compatibility verdict. Aborts on missing identity material.
1. **Backup** — stops the legacy `velociraptor` **gracefully** (see the
   client_info note below) and copies its entire data dir to
   `~/velo-migration-backup-<ts>/`. This backup is the
   seed source AND the rollback artifact; the script never mutates it and
   never deletes it — you do, by hand, when satisfied.
2. **Remove risx-mssp** — shows what will be destroyed and requires typing
   `REMOVE`. Re-verifies the backup immediately before `rm -rf`.
3. **Download intact** — latest GitHub release (or `--release TAG` /
   `--from-dir DIR` for air-gap).
4. **Configure** — pre-sets `domain:` to the host your clients dial, then
   opens `config.yaml` in `$EDITOR` for modules/IP. An accidental editor
   exit loops back to a summary + proceed/edit/abort prompt. Changing
   `domain` away from the legacy host triggers a hard warning (it would
   strand every deployed client).
5. **Transplant + install** — transforms the legacy `server.config.yaml`
   into intact's shape (`scripts/migrate/transform_config.py`), seeds it and
   the datastore volume, then runs `install.sh`.
6. **Verify** — CA fingerprint unchanged, api.config.yaml signed by the
   transplanted CA, client.config.yaml carries the legacy nonce/endpoint,
   client-record count matches, backend gRPC round-trip, and (informational)
   waits up to 5 min for a real endpoint to reconnect.
7. **Fleet upgrade guidance** — how to push the 0.77.x client binary through
   the new server (`Admin.Client.Upgrade`), canary-first.

Options: `--force` (pass the orange compat gate), `--datastore-mode bind`
(huge datastores: the volume binds the backup dir — 1× disk instead of 2×,
but the backup then IS live data), `--skip-remove` (leave risx stopped on
disk; needs 3× disk), `--backup-dir` (reuse a previous run's backup after a
failure — re-runs are cheap).

## Client compatibility (lab-verified 2026-07-26)

Old clients vs a **0.77.1** server, real processes, loopback lab:

| client version | connects/TLS | enrolls + interrogates | `Generic.Client.Info` collection |
|---|---|---|---|
| 0.6.9  | ✓ | ✓ (version detected) | ✓ FINISHED, 20 rows |
| 0.7.0  | ✓ | ✓ | ✓ FINISHED, 21 rows |
| 0.7.1  | ✓ | ✓ | ✓ FINISHED, 21 rows |
| 0.72.4 | ✓ | ✓ | ✓ FINISHED, 21 rows |
| 0.75.8 | ✓ | ✓ | ✓ FINISHED, 22 rows |

So every fleet generation seen in the field (0.6.9 → 0.75) talks to intact's
server directly; the preflight gates hard only below 0.6.9.

**The one incompatibility found:** binaries ≤0.72 refuse to *parse a config
file* containing fields introduced later (`Client.version`,
`Client.server_version`, `level2_writeback_suffix`). Deployed clients are
unaffected — they keep their original embedded config forever. But never
hand a **newly generated** `client.config.yaml` to an old binary (e.g. when
re-imaging a machine, use the new installer from `client_installers/`, which
pairs the new binary with the new config).

Newer-server caveats that still apply (upstream "best effort"): artifacts
using post-0.6.9 VQL features won't run on old clients until the fleet
upgrade — run phase 7 soon after migrating.

### Stepping-stone path (fleets older than 0.6.9)

Untested territory. Before migrating, upgrade the OLD platform's
Velociraptor one bracket using risx-mssp's own tooling
(`Risx-MSSP/edit_versions/velociraptor.sh` bumps `VELOCIRAPTOR_VERSION`; the
image rebuilds from the GitHub release), let clients reconnect, push a
client upgrade through the old server to ≥0.72, then run this migration.

## Why the legacy server must be stopped *gracefully*

Velociraptor holds the fleet records — hostname, OS, agent version, last seen —
in an in-memory cache flushed to `<datastore>/client_info/snapshot.json`
periodically and on a clean shutdown. The risx entrypoint starts the server as
a **child** of its shell script (no `exec`), so `docker stop` delivers SIGTERM
to the shell and the server gets SIGKILLed when the grace period expires — the
snapshot is never written.

Consequence if that happens: every collection, hunt and client key still
migrates, and clients still reconnect with their original `client_id` — but
the intact fleet list comes up **empty**, and a client only reappears when its
process restarts (which re-enrolls it). On a box with thousands of endpoints
that looks like total data loss even though nothing was lost.

Phase 1 therefore signals the server process itself inside the container,
waits for `client_info/snapshot.json` to land, and only then stops the
container. If the snapshot still doesn't appear the script warns loudly and
continues — the migration is safe, the fleet list just refills gradually.

## Operational notes

- **Never** run risx's `cleanup.sh --app velociraptor` or
  `docker compose down --volumes` in the legacy velo dir — both destroy the
  datastore. The script only ever uses `docker stop`.
- The legacy data dir mixes datastore records and repacked client binaries
  under one `clients/` directory; the datastore copy excludes
  `clients/{linux,mac,windows}` (binaries) but keeps `clients/C.*` (records).
- Legacy GUI users/passwords ride along in the datastore. intact's
  entrypoint adds its own admin + `api` users only if absent.
- `intact scripts/clean.sh --all|--volumes` deletes volumes prefixed
  `velociraptor_` — that includes the transplanted datastore. Use
  `--containers` if you must clean.
- If an intact **upgrade** ever runs in the same breath as a transplant, set
  `INTACT_ALLOW_VELO_CA_CHANGE=1` (the upgrade's CA-drift guard would
  otherwise abort on the deliberately-changed CA).
- The legacy `api.config.yaml` may have been downloaded off-box by analysts
  (risx "Download Api" button). It remains valid against the new server
  (same CA). If that's a concern, rotate keys after migrating — at the cost
  of redeploying clients, i.e. usually not.
