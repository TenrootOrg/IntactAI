# Plan: Settings → Velociraptor — upgrade the Velociraptor clients

Branch `dev-velociraptor-client-upgrade` (from main 5268f189). Planned 2026-10-11.

**Status 2026-10-12:** steps 1-3 done and live-tested for Windows AND Linux (4a5f2a3a, 91a27762, 47034514);
the critical cases (mixed results, retry, force, Linux rollback, offline, Stop, one run at a time, restart
resume) all run live. **Left: step 4** (banner after a server upgrade + prepare from velo_refresh), docs,
the risx_lib artifact names. The scope grew to Linux on request: Intact.Client.Upgrade.Linux (backend
config/) swaps the running binary; legacy, musl-only Linux and macOS are known gaps (commit 91a27762).
The fleet stage is followed 24 h and checked once an hour; the pilot every 20 s for 15 min.

## Decided with the user
1. **Rollout:** pilot first, then the rest. Upgrade the picked client(s) (1 by default), wait until they
   report the new version, then a second click upgrades the rest.
2. **OS scope:** Windows first. Linux is shown as "manual" until verified: our Linux installer is a
   repacked binary, while `Admin.Client.Upgrade.Debian/RedHat` expect a deb/rpm-installed
   `velociraptor_client` service. macOS: Velociraptor 0.77.2 has no upgrade artifact.
3. **After a server upgrade:** notify + prepare, the operator clicks. The packages are rebuilt
   automatically and the tab shows a banner; nothing is pushed without a human ("we notify, never
   auto-act").
4. **Live test:** downgrade the lab VM's client (DESKTOP-2175T02, `C.51628cbbd6a2ae90`) to 0.77.1 over
   SSH, confirm it reports 0.77.1, then run the real upgrade from the new tab. SSH is the recovery path
   (reinstall). Nothing may touch the VM's network (see attack-simulation-campaign.md safety rules).

## Facts (verified 2026-10-11)
- Server 0.77.2 (`config.yaml` versions.velociraptor; `modules/velociraptor/.env` is stamped from it on
  install/upgrade; image `velociraptor-server:0.77.2`, built locally). Legacy 0.7.1 builds for Win7/2008R2.
- Server upgrade = `lib/upgrade/velociraptor/velociraptor.sh:upgrade_module_velociraptor` (CA kept and
  verified by fingerprint, datastore volume untouched), then `lib/upgrade/velo_refresh.sh:velo_refresh`
  (policy "report": artifacts, tools, downloads, `scripts/generate_clients.sh`). **The new package step
  hooks in here.**
- Built into 0.77.2: `Admin.Client.Upgrade.Windows` (tool **`WindowsMSI`**, msiexec
  `/i REINSTALL=ALL REINSTALLMODE=A`, param `SleepDuration` = 600 s stagger; the flow never "completes":
  the client dies and comes back), `.Debian` (tool `VelociraptorDebian`), `.RedHat` (`VelociraptorRedHat`),
  `Server.Utils.CreateMSI`, `Server.Utils.CreateLinuxPackages`, `Generic.Client.Info`.
- **TRAP on the box:** the `WindowsMSI` tool is EMPTY, and `VelociraptorWindowsMSI` points at the plain
  upstream v0.77.2 MSI **with no client config**. Pushing that would install clients that cannot
  reach the server, and the whole fleet would disconnect. Only a repacked MSI verified to carry our config
  may ever be registered as `WindowsMSI`.
- An MSI built with `Server.Utils.CreateMSI` already exists in the backend:
  `services/msi_generator_service.py:generate_msi_via_artifact` (+ `copy_msi_from_collection`). The
  config-embedded check exists in `modules/velociraptor/entrypoint.sh:157-205`
  (README_MSI_BROKEN). Reuse both.
- Client versions: nothing reads `agent_information.version` today. `services/velociraptor_service.py:
  get_clients_from_snapshot` (VQL `clients()`) needs the field added. Live: 10 clients, only
  DESKTOP-2175T02 reports a version (0.77.2); 9 were never interrogated, so run `Generic.Client.Info` to fill them.
- Hunts: `velociraptor_service.py:create_velociraptor_hunt` and `routes/velociraptor_routes.py:
  _create_single_velo_hunt` (supports `include_labels`). Pilot = hunt limited to the chosen client(s)
  (label the pilot, or `hunt(... spec ...)` with a client condition).
- Tools: `inventory_add(tool=, serve_locally=TRUE, file=)` as in `velo_refresh.sh:_velo_refresh_tools` /
  `tools_download_service.py:configure_inventory`.
- Long jobs → Settings → Actions: `workflow_service.create_automation_run` / `add_log_to_run` /
  `update_run_status`, type added to `SYSTEM_TYPES` (example: `routes/support_bundle_routes.py:26-81`).
  UI hand-off `window.ActiveCase.gotoSystemWorkflows()`.
- Settings tabs: `partials/settings.html` local `settingsTab`, buttons lines 19-38, gate with
  `$store.services.has('velociraptor')`; store `js/stores/settings.js`. Bump the cache chain
  (index → partial-loader → partials).
- Wrong names to fix: `scripts/migrate/risx_lib.sh:645-646` tells operators to hunt
  `Admin.Client.Upgrade` / `Admin.Client.Upgrade.Linux`, which do not exist in 0.77.2.

## Steps (one commit each; targeted tests once before each commit; deploy + live check)
1. **Tab + status (read-only).** `GET /api/velociraptor/clients/versions`: server version, clients
   grouped as current / behind / unknown / offline (add `agent_information.version` to the clients VQL).
   "Refresh client info" = `Generic.Client.Info` hunt (System action). The new Velociraptor tab in Settings.
2. **Packages.** `POST /api/velociraptor/client-packages`: `Server.Utils.CreateMSI` for the server
   version → verify that the config is embedded and the version matches → register as `WindowsMSI` (keep the previous one
   for the record). Refuse to register anything unverified. Also called from `velo_refresh` after a
   server upgrade (prepare only).
3. **Upgrade.** `POST /api/velociraptor/clients/upgrade {stage: pilot|rest, client_ids?}`: preflight
   (verified `WindowsMSI` matches the server version; never downgrade; skip clients already current),
   `Admin.Client.Upgrade.Windows` hunt to the pilot (SleepDuration small for a pilot), System action that
   polls `clients()` until each target reports the server version: upgraded / pending / offline (the hunt
   stays open so it upgrades when the client is back) / failed (timeout). "Upgrade the rest" is enabled only after
   the pilot succeeds.
4. **After a server upgrade + docs.** Banner "Server X — N clients behind → Upgrade clients"; docs; fix
   the risx_lib names.

## Live test (step 3)
Check for in-flight runs. Read-only queries first. Install the 0.77.1 MSI on the VM via SSH (as the VM's
current install is MSI-based; confirm), wait for it to report 0.77.1 → pilot upgrade from the tab →
expect the same client ID back on 0.77.2 within minutes; the Actions run shows "upgraded". Recovery:
reinstall the 0.77.2 repacked MSI over SSH.
