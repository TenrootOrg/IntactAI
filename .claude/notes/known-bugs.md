# Known bugs — triage later

## Velociraptor: legacy version disabled after upgrade/offline-install

**Symptom**
After running an upgrade (or offline install) of the Velociraptor
module, the LEGACY Velociraptor binary support gets disabled —
clients running older Win7 / Server 2008 R2 OSes can no longer be
generated as offline collectors or repacked from the live-client
path.

**Where to start looking**
- `lib/modules.sh:download_legacy_velociraptor_binaries`
  (the install.sh path that fetches velociraptor_legacy=0.7.1 binaries)
- `modules/backend/services/upgrade/velociraptor.py`
  (upgrade_velociraptor_offline + install_velociraptor_offline —
  probably overwrites the staged-binaries directory and wipes the
  legacy binaries put there by install.sh)
- `modules/nginx/html/downloads/velociraptor-v0.7.1-*` paths
  (where install.sh stages the legacy binaries for the
  offline-collector + live-client repack flows)
- `config.yaml: versions.velociraptor_legacy` (currently `'0.7.1'`)

**Likely root cause hypothesis**
upgrade_velociraptor_offline bumps the VELOCIRAPTOR_VERSION and
recreates the container, but the LEGACY binaries (separate pin,
separate filenames like `velociraptor-v0.7.1-linux-amd64`) live in
the same nginx/downloads directory that the upgrade may clean up
or fail to repopulate. install.sh has a dedicated
`download_legacy_velociraptor_binaries` step; the upgrade path
probably doesn't run an equivalent.

**Reported by user** 2026-06-09 session — alongside the
fresh-install Timesketch fixes (see commits 7c27d2a, a093f20, the
in-flight timesketch user-creation patch).
