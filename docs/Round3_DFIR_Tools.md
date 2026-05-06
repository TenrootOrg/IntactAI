# Round 3 — DFIR tooling: manual install steps

This round adds two free, mature, Azure-specific DFIR tools to the
pipeline. Both are integrated as **manual prerequisites** for now —
`install.sh` does not auto-pull or auto-clone them. The pipeline detects
when the prereq is missing and logs a clear "what to run" message; once
you run the steps below, the next scan picks them up.

| Tool | Stars | License | Adds |
|---|---|---|---|
| [Microsoft Azure-Sentinel](https://github.com/Azure/Azure-Sentinel) | ~4.6K | MIT | ~50–200 high-value detection rules (point-event / aggregate / baseline) |
| [ROADtools](https://github.com/dirkjanm/ROADtools) | ~3.6K | MIT | Entra attack-graph for blast-radius enrichment |

Neither overlaps with DFIR-O365RC. Sentinel adds *detection rules*
(different layer); ROADtools adds *configuration / relationships*
(different category — graph, not events).

---

## 1) Azure-Sentinel detection rules

### One-time install

Run as the `tenroot` user on the Intact VM:

```bash
# Pick the Sigma-format rule directories — KQL-only rules are skipped in
# this first cut and tracked as a follow-up.
TMP=$(mktemp -d)
git clone --depth 1 https://github.com/Azure/Azure-Sentinel "$TMP/Azure-Sentinel"

mkdir -p /home/tenroot/intact/data/sentinel-rules

# AAD identity / sign-in / OAuth / app-registration rules (the categories
# our Graph collector covers). Add other directories as needed.
rsync -a --include='*/' --include='*.yml' --include='*.yaml' --exclude='*' \
  "$TMP/Azure-Sentinel/Detections/AuditLogs/" \
  /home/tenroot/intact/data/sentinel-rules/AuditLogs/

rsync -a --include='*/' --include='*.yml' --include='*.yaml' --exclude='*' \
  "$TMP/Azure-Sentinel/Detections/SigninLogs/" \
  /home/tenroot/intact/data/sentinel-rules/SigninLogs/

rsync -a --include='*/' --include='*.yml' --include='*.yaml' --exclude='*' \
  "$TMP/Azure-Sentinel/Detections/IdentityInfo/" \
  /home/tenroot/intact/data/sentinel-rules/IdentityInfo/ 2>/dev/null || true

rm -rf "$TMP"
ls /home/tenroot/intact/data/sentinel-rules/ | head
```

The data directory is bind-mounted into the backend container at
`/app/data/sentinel-rules`. No backend restart required — the rules are
re-loaded at the start of every scan.

### Refresh (Microsoft pushes daily; refresh whenever)

```bash
TMP=$(mktemp -d)
git clone --depth 1 https://github.com/Azure/Azure-Sentinel "$TMP/Azure-Sentinel"
rsync -a --delete --include='*/' --include='*.yml' --include='*.yaml' --exclude='*' \
  "$TMP/Azure-Sentinel/Detections/AuditLogs/" \
  /home/tenroot/intact/data/sentinel-rules/AuditLogs/
# (repeat for SigninLogs / IdentityInfo as above)
rm -rf "$TMP"
```

### What changes per scan

- Workflow log: `[SENTINEL] Loaded N rules from /app/data/sentinel-rules
  (X point_event, Y aggregate, Z baseline; ...)`
- In **targeted** mode: `[SIGMA] Skipping K aggregate/baseline rules in
  targeted scope (rerun with scope_mode=tenant_wide to include them)`
- `sigma_rule_tally` may now contain Microsoft-authored rule names that
  weren't in the SigmaHQ corpus.

### Removing it

Delete the directory and the loader silently no-ops on the next scan:

```bash
rm -rf /home/tenroot/intact/data/sentinel-rules
```

---

## 2) ROADtools (planned in this round, implementation arrives in a
   follow-up commit)

### One-time install

```bash
docker pull dirkjanm/roadtools:latest
mkdir -p /home/tenroot/intact/data/roadtools-cache
```

Cache directory persists per-tenant graphs across scans (24h TTL).

### Verify the image is on the box

```bash
docker image inspect dirkjanm/roadtools:latest > /dev/null && echo OK
```

When this returns OK and the new code is shipped, scans automatically
gather the tenant graph and enrich findings with blast-radius facts.
Until then, the pipeline runs as today (no behaviour change if you skip
this step).

### Removing it

```bash
docker rmi dirkjanm/roadtools:latest
rm -rf /home/tenroot/intact/data/roadtools-cache
```

---

## Verification (after both prereqs are in place)

1. Restart backend so it picks up the new modules:

   ```bash
   docker compose -f /home/tenroot/intact/modules/backend/docker-compose.yaml restart backend
   ```

2. Run an Azure scan with `scope_mode=targeted` and your usual sim user.
3. Check the workflow log for the `[SENTINEL] Loaded N rules` line near
   the start of phase 4 (detection).
4. Compare `sigma_rule_tally` on the run before vs. after — Sentinel
   rules should show new entries (Microsoft-authored rule names).
5. (After ROADtools follow-up ships) — check the report for a `BLAST
   RADIUS` section under each finding.

If `[SENTINEL] Rules directory not found` appears in the log, the manual
install hasn't been run yet — either run it, or ignore the message if
you don't want Sentinel rules.
