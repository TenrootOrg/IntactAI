"""CVE Scan pipeline — orchestrates the NVD lookup against operator-
provided CSVs (or Velociraptor flow results) and produces the
customer-facing deliverables: per-input CSVs, the consolidated
`combined_cves.csv`, a structured `findings.json`, and a short
markdown summary saved via the same `save_report` accessor the
Engagement Report builder consumes.

Public API:
  run_cve_scan(run_id, input_csv_paths, name=...)
  pull_from_velociraptor(run_id, flow_id, dest_dir)
"""
from __future__ import annotations

import csv
import json
import os
import time
from pathlib import Path
from typing import Dict, List, Optional

from services.workflow_service import update_run_status, add_log_to_run
from services.storage.report_store import save_report

from . import nvd as _nvd


def _collapse_validated_rows(rows):
    """Collapse near-duplicate findings that share `(host, status,
    cve_link)` — e.g. Microsoft Office Click-to-Run's Extensibility /
    Licensing / Localization sub-components all flagged against the
    same CVE on the same host, or the same product appearing with
    minor punctuation differences from overlapping inputs
    (system_programs.csv vs detectraptor_applications.csv).

    The remediation for both cases is identical ("patch CVE-X on host
    Y" or "this CVE is patched on host Y"), so showing them as N
    separate rows just inflates the CSV without adding actionable
    signal. The display product becomes the longest common prefix of
    the merged rows' product strings + a `(+N variants)` annotation.

    Status is part of the key so a host with one patched and one
    vulnerable sub-component on the same CVE doesn't get merged — we
    want to preserve that distinction."""
    if not rows:
        return rows
    groups: Dict[tuple, list] = {}
    order: list = []
    for r in rows:
        host, product, version, status, level, link = r
        key = (host, status, link)
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(r)

    out = []
    for key in order:
        group = groups[key]
        if len(group) == 1:
            out.append(group[0])
            continue
        # Pick the highest-CVSS row as representative for the CVE
        # level / link metadata (they're nearly always identical
        # inside a group since the CVE itself drives those fields).
        def _score(r):
            try:
                return float((r[4] or '').split(None, 1)[0])
            except Exception:
                return 0.0
        rep = max(group, key=_score)
        products = [r[1] or '' for r in group]
        prefix = products[0]
        for p in products[1:]:
            i = 0
            limit = min(len(prefix), len(p))
            while i < limit and prefix[i] == p[i]:
                i += 1
            prefix = prefix[:i]
        display_prod = prefix.rstrip(" -–—_/.,:").strip()
        if len(display_prod) < 4:
            display_prod = min(products, key=len)
        extras = len(group) - 1
        merged_product = f"{display_prod} (+{extras} variant{'' if extras == 1 else 's'})"
        versions = sorted({(r[2] or '') for r in group})
        merged_version = versions[0] if len(versions) == 1 else f"{versions[0]} (+{len(versions) - 1} more)"
        host, _, _, status, level, link = rep
        out.append((host, merged_product, merged_version, status, level, link))
    return out


# Per the README — these are the four artifact CSV exports the scan
# expects. Filenames are how the side-project's main() identifies
# inputs by content; we accept either the historical filename or any
# upload alias that maps to the right artifact.
EXPECTED_CSVS = (
    'system_programs.csv',
    'detectraptor_applications.csv',
    'detectraptor_lolrm.csv',
    'windows versions.csv',
)


def _log(run_id):
    """Closure that turns (msg, level) into a workflow log entry."""
    def _f(msg, level='info'):
        try:
            add_log_to_run(run_id, msg, level)
        except Exception:
            print(msg, flush=True)
    return _f


def run_cve_scan(run_id: str, input_csv_paths: List[Path], name: Optional[str] = None,
                 mode: str = "vulnerable_only") -> Dict:
    """Background-thread worker for /api/cve/scan/upload and
    /api/cve/scan/from-flow. Mutates the workflow row's status +
    progress + logs throughout.

    `input_csv_paths`: list of CSV files (any subset of the four
    expected artifacts — the underlying script tolerates missing
    inputs). Caller is responsible for placing them on disk first
    (upload route writes them via the existing upload service; from-
    flow route writes them via `pull_from_velociraptor`).

    `mode`: 'vulnerable_only' (default) emits one row per host ×
    product × CVE. 'full' additionally emits one row per host ×
    product even when nothing matched, with a Status column =
    Vulnerable / Unknown / Patched. Rows are ordered vulnerable
    → unknown → patched in 'full' mode.

    Returns the result dict (mostly for tests / future inspection).
    """
    if mode not in ("vulnerable_only", "full"):
        mode = "vulnerable_only"
    log = _log(run_id)
    result = {'has_report': False}

    try:
        update_run_status(run_id, 'running', progress=5)

        # Tell the rate limiter whether we have an API key (50/30s)
        # or not (5/30s).
        have_key = bool(_nvd._api_key())
        _nvd.set_rate_limit(have_key)

        # NVD needs internet (and ideally a key). When either is missing we do
        # NOT error — we fall back to the bundled local CVE database (cves.db)
        # and say so. Offline => skip NVD REST entirely (no 90s/page stalls).
        from services.connectivity import has_internet
        from . import local_db as _local_db
        online = has_internet()
        try:
            local_ready = _local_db.is_populated()
        except Exception:
            local_ready = False

        _nvd.set_local_only(False)
        if not online:
            if local_ready:
                _nvd.set_local_only(True)
                log("[CVE] No internet connection — using the bundled local CVE "
                    "database (cves.db). No error; results come from the offline "
                    "dictionary.", "info")
            else:
                log("[CVE] No internet connection and the local CVE database "
                    "(cves.db) is not populated — CVE matching will be limited. "
                    "Seed cves.db via an install/upgrade that bundles it.", "warning")
        elif not have_key:
            if local_ready:
                log("[CVE] No NVD API key — using the local CVE database (cves.db) "
                    "as the primary source; anonymous NVD (5 req/30s) fills gaps.",
                    "info")
            else:
                log("[CVE] No NVD API key configured — running at the anonymous "
                    "5 req / 30s rate. Add a key in Settings to speed this up to "
                    "50 req / 30s.", "warning")

        # Filter to only paths that actually exist (side project tolerates missing).
        existing = [Path(p) for p in input_csv_paths if Path(p).exists()]
        if not existing:
            raise RuntimeError("No usable input CSVs — every supplied path was missing or empty.")
        log(f"[CVE] Scanning {len(existing)} input CSV(s): " +
            ", ".join(p.name for p in existing), "info")

        # Output dir lives under /data/downloads/<run_id>/ like every
        # other pipeline. Persists across container restarts.
        out_dir = Path(f"/data/downloads/{run_id}")
        out_dir.mkdir(parents=True, exist_ok=True)

        # Step 1: collect every unique (product, version) pair across
        # all inputs. Also harvest a name→Publisher map so the lookup
        # layer can fall back to vendor-scoped CPE search for products
        # whose install string doesn't carry the vendor token (e.g.
        # "Advanced IP Scanner" has no "radmin" in the name but the
        # Publisher column says "Famatech").
        pairs = sorted(_nvd.collect_unique_pairs(existing))
        publisher_map = _nvd.collect_name_publisher_map(existing)
        log(f"[CVE] {len(pairs)} unique (product, version) pairs to look up "
            f"({len(publisher_map)} with Publisher hints)", "info")
        update_run_status(run_id, 'running', progress=15)

        if not pairs:
            log("[CVE] No (product, version) pairs found in any input. Check the CSV headers — "
                "the inputs should be Velociraptor exports of "
                "Windows.Sys.Programs / DetectRaptor.Windows.Detection.Applications / "
                "DetectRaptor.Windows.Detection.LolRMM / Generic.Client.Info.",
                "warning")
            # Still finish (empty result) rather than crash — operator gets
            # an empty CSV they can use to debug their input.

        # Step 2: parallel NVD lookup (12 workers, rate-limited).
        # The lookup phase dominates on big inventories — 946 pairs at
        # the 50 req/30s rate can take ~10 minutes. Pump live progress
        # into the workflow row so the operator sees movement instead
        # of a static 15%.
        cache_path = Path("/app/data/cve_cache/nvd_cache.json")
        cache = _nvd.load_cache(cache_path)
        started = time.time()

        def _lookup_progress(done, total):
            # Map 0..total → 15..60% so the rest of the pipeline still
            # has room to advance the bar.
            pct = 15 + int(45 * done / max(total, 1))
            update_run_status(run_id, 'running', progress=min(pct, 60))

        lookup = _nvd.fetch_all_pairs(pairs, cache, cache_path, log=log,
                                       publisher_map=publisher_map,
                                       progress_cb=_lookup_progress)
        elapsed = time.time() - started
        log(f"[CVE] Fetched {len(pairs)} products from NVD in {elapsed:.1f}s", "success")
        update_run_status(run_id, 'running', progress=60)

        # Step 3: write the per-input *_with_cves.csv files.
        log("[CVE] Writing per-input CSVs with CVE columns…", "info")
        for src in existing:
            # Sanitize the filename so 'windows versions.csv' becomes
            # 'windows_versions.csv' on the output side (consistent
            # naming for downloads).
            stem = src.stem.replace(' ', '_')
            dst = out_dir / f"{stem}_with_cves.csv"
            try:
                cve_count = _nvd.write_per_input_output(src, dst, lookup)
                log(f"[CVE]   {src.name} → {dst.name}: {cve_count} rows tagged with a CVE", "info")
            except Exception as e:
                log(f"[CVE]   {src.name} write failed: {e}", "warning")
        update_run_status(run_id, 'running', progress=75)

        # Step 4: build the combined cross-host table.
        log(f"[CVE] Assembling combined table (mode={mode})…", "info")
        combined_rows = _nvd.build_combined_rows(existing, lookup, mode=mode)
        log(f"[CVE] Combined table: {len(combined_rows)} rows pre-validation", "info")
        update_run_status(run_id, 'running', progress=85)

        # Step 5: independent CVE-detail validation pass — drops rows
        # whose CVE-by-id payload doesn't actually have a CPE in
        # range. Non-vulnerable rows pass through untouched.
        log("[CVE] Independent CVE-detail validation pass…", "info")
        validated = _nvd.validate_combined(combined_rows, log=log)
        # Collapse sub-component / near-duplicate rows that share
        # (host, status, CVE) — single source of truth for both CSV and
        # findings.json so the operator's deliverables don't repeat
        # Office Click-to-Run's three sub-components for every CVE
        # match, etc.
        raw_count = len(validated)
        validated = _collapse_validated_rows(validated)
        collapsed_delta = raw_count - len(validated)
        if collapsed_delta:
            log(f"[CVE] Collapsed {collapsed_delta} sub-component / near-duplicate row(s) by (host, status, CVE)", "info")
        vuln_count = sum(1 for r in validated if r[3] == "vulnerable")
        patched_count = sum(1 for r in validated if r[3] == "patched")
        unknown_count = sum(1 for r in validated if r[3] == "unknown")
        log(f"[CVE] {vuln_count} vulnerable / {patched_count} patched / {unknown_count} unknown rows after validation", "success")
        update_run_status(run_id, 'running', progress=92)

        # Step 6: write combined_cves.csv. Schema changes per mode so
        # the vulnerable-only output stays identical to the original
        # side-project deliverable; full mode adds a Status column.
        combined_csv = out_dir / "combined_cves.csv"
        with combined_csv.open("w", encoding="utf-8", newline="") as fout:
            w = csv.writer(fout)
            if mode == "full":
                w.writerow(["HostName", "Product", "ProductVersion", "Status", "CVELevel", "LinkToCVE"])
                for r in validated:
                    host, product, version, status, level, link = r
                    w.writerow([host, product, version, status.title(), level, link])
            else:
                w.writerow(["HostName", "Product", "ProductVersion", "CVELevel", "LinkToCVE"])
                for r in validated:
                    host, product, version, status, level, link = r
                    # vulnerable_only already filtered by build_combined_rows,
                    # but double-check so we never leak a non-vulnerable
                    # row into the legacy schema.
                    if status != "vulnerable":
                        continue
                    w.writerow([host, product, version, level, link])
        log(f"[CVE] Wrote combined_cves.csv: {len(validated)} rows", "success")

        # Step 7: write findings.json (forward-compat for the
        # Engagement Report integration). Always carries the Status
        # field so downstream consumers can choose whether to show
        # patched/unknown lines.
        findings_json = out_dir / "findings.json"
        findings = []
        for r in validated:
            host, product, version, status, level, link = r
            score = 0.0
            severity = ''
            try:
                parts = level.split(None, 1)
                score = float(parts[0])
                severity = parts[1] if len(parts) > 1 else ''
            except Exception:
                pass
            cve_id = link.rsplit('/', 1)[-1] if '/' in link else ''
            findings.append({
                'hostname': host,
                'product': product,
                'version': version,
                'status': status,
                'cve_id': cve_id,
                'cve_link': link,
                'cvss_score': score,
                'severity_bucket': severity,
            })
        findings_json.write_text(json.dumps(findings, indent=2), encoding='utf-8')

        # Step 8: write a short markdown summary via save_report so
        # the engagement-report builder's get_X_report_content shape
        # works for cve_scan runs. The engagement chat assistant can
        # then talk about CVE findings without a custom accessor.
        md_summary = _build_markdown_summary(name or 'CVE Scan', existing, validated, len(pairs))
        save_report(run_id, json.dumps({'technical': md_summary}))

        # Step 9: stash on the workflow row so the download endpoint
        # can serve combined_cves.csv without re-deriving paths.
        try:
            from services.file_storage_service import get_workflow, save_workflow
            wf = get_workflow(run_id)
            if wf is not None:
                wd = wf.get('details') or {}
                wd['has_report'] = True
                wd['llm_enabled'] = False  # no LLM ran; for Engagement-Report eligibility
                wd['combined_csv'] = str(combined_csv)
                wd['findings_count'] = vuln_count
                wd['patched_count'] = patched_count
                wd['unknown_count'] = unknown_count
                wd['mode'] = mode
                wd['inputs_processed'] = [p.name for p in existing]
                wd['unique_pairs'] = len(pairs)
                wf['details'] = wd
                save_workflow(wf)
        except Exception as e:
            print(f"[CVE] Failed to stash run details: {e}", flush=True)

        update_run_status(run_id, 'completed', progress=100, force=True)
        if mode == "full":
            log(f"[CVE] Done. {vuln_count} vulnerable + {unknown_count} unknown + {patched_count} patched rows across {len(existing)} input CSVs.", "success")
        else:
            log(f"[CVE] Done. {vuln_count} validated CVE rows across {len(existing)} input CSVs.", "success")
        result['has_report'] = True
        result['findings_count'] = vuln_count
        return result

    except Exception as e:
        import traceback as _tb
        _tb.print_exc()
        log(f"[CVE] Scan failed: {e}", "error")
        update_run_status(run_id, 'failed', error=str(e))
        raise


def _build_markdown_summary(name, inputs, validated_rows, pairs_total) -> str:
    """Compact markdown summary of the scan — used as the report
    body that get_X_report_content (when ported) will return. This
    is also what the engagement chat assistant sees when discussing
    CVE findings. Reads the 6-tuple row shape
    (host, product, version, status, level, link)."""
    vuln_rows = [r for r in validated_rows if r[3] == "vulnerable"]
    if not vuln_rows:
        return (
            f"# CVE Scan — {name}\n\n"
            f"**Inputs:** {', '.join(p.name for p in inputs)}\n"
            f"**Unique (product, version) pairs scanned:** {pairs_total}\n"
            f"**Findings:** none. Either no installed products in the inputs match a known CVE, "
            f"or the version ranges in NVD don't cover the installed builds.\n"
        )

    # Bucket counts (vulnerable rows only — patched/unknown don't
    # carry a severity).
    buckets = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Other': 0}
    for r in vuln_rows:
        level = r[4]
        sev = (level.split(None, 1)[1] if len(level.split(None, 1)) > 1 else 'Other').title()
        buckets[sev if sev in buckets else 'Other'] += 1

    def _score(r):
        try:
            return float(r[4].split()[0])
        except Exception:
            return 0.0
    top = sorted(vuln_rows, key=_score, reverse=True)[:10]

    md_lines = [
        f"# CVE Scan — {name}",
        "",
        f"**Inputs:** {', '.join(p.name for p in inputs)}",
        f"**Unique (product, version) pairs scanned:** {pairs_total}",
        f"**Validated vulnerable findings:** {len(vuln_rows)}",
        "",
        "## Severity breakdown",
        "",
        f"- Critical: {buckets['Critical']}",
        f"- High: {buckets['High']}",
        f"- Medium: {buckets['Medium']}",
        f"- Low: {buckets['Low']}",
        f"- Other: {buckets['Other']}",
        "",
        "## Top 10 findings",
        "",
        "| Host | Product | Version | Severity | CVE |",
        "|---|---|---|---|---|",
    ]
    pipe_escape = "\\|"
    for host, product, version, _status, level, link in top:
        cve_id = link.rsplit('/', 1)[-1] if '/' in link else '?'
        product_safe = product.replace('|', pipe_escape)
        md_lines.append(
            f"| {host} | {product_safe} | {version} | {level} | "
            f"[{cve_id}]({link}) |"
        )
    md_lines.append("")
    md_lines.append(
        "*See `combined_cves.csv` (downloadable from the workflow row) for "
        "the full per-host vulnerability inventory.*"
    )
    return "\n".join(md_lines)


def pull_from_velociraptor(run_id: str, flow_id: Optional[str], hunt_id: Optional[str], dest_dir: Path) -> List[Path]:
    """Fetch the four required artifact result CSVs out of an existing
    Velociraptor flow or hunt and write them to `dest_dir` with the
    historical filenames the scan expects.

    Accepts EITHER `flow_id` (single-host collection) OR `hunt_id`
    (multi-host hunt — `H.xxx` or hunt-derived `F.xxx.H`).

    Reuses
    [services.agentic.collectors.get_existing_collection_results](modules/backend/services/agentic/collectors.py#L1050)
    so we don't reinvent the gRPC + VQL plumbing that the agentic
    pipeline already uses. That helper enumerates flows in a hunt,
    fetches rows per artifact, tags each row with `_client_id` and
    `_hostname` for cross-host attribution.

    Returns the list of CSV paths actually written (subset of the
    four; missing artifacts are silently skipped — the scan
    tolerates partial input).
    """
    log = _log(run_id)
    dest_dir.mkdir(parents=True, exist_ok=True)

    # Artifact → output filename map (the names the scan recognises).
    targets = {
        'Windows.Sys.Programs':                              'system_programs.csv',
        'DetectRaptor.Windows.Detection.Applications':       'detectraptor_applications.csv',
        'DetectRaptor.Windows.Detection.LolRMM':             'detectraptor_lolrm.csv',
        'Generic.Client.Info':                               'windows versions.csv',
    }

    src_label = flow_id or hunt_id or '(no source)'
    log(f"[CVE] Pulling artifact rows from Velociraptor {src_label}…", "info")

    # Lazy import — keeps the cve_scan service importable on installs
    # without the agentic module enabled.
    try:
        from services.agentic.collectors import get_existing_collection_results
    except Exception as e:
        raise RuntimeError(f"Agentic collectors helper not available: {e}")

    all_results, artifacts_found, client_info = get_existing_collection_results(
        run_id=run_id,
        flow_id=flow_id,
        hunt_id=hunt_id,
        time_filter=None,
        client_ids=None,
    )

    log(f"[CVE]   Velociraptor returned {len(artifacts_found)} artifact(s) "
        f"across {len(client_info)} client(s)", "info")

    written: List[Path] = []
    for artifact, fname in targets.items():
        # Velociraptor sometimes returns artifact rows under either
        # the base artifact name or a `<artifact>/<source>` form
        # (when the artifact has multiple sources). Accept any key
        # that starts with the artifact name.
        rows = []
        for key, key_rows in all_results.items():
            if key == artifact or key.startswith(artifact + '/'):
                rows.extend(key_rows or [])
        if not rows:
            log(f"[CVE]   {artifact}: no rows (artifact not in this flow / hunt)", "info")
            continue
        # Compute header from union of row keys, preserving order.
        keys = []
        seen = set()
        for r in rows:
            if not isinstance(r, dict):
                continue
            for k in r.keys():
                if k not in seen:
                    seen.add(k)
                    keys.append(k)
        # Make sure Hostname / Fqdn / Platform / etc. are present —
        # the scan's _row_host looks for these. _hostname is the
        # collectors helper's tag; expose it as Hostname for the
        # scan to pick up.
        if '_hostname' in keys and 'Hostname' not in keys:
            keys.append('Hostname')
            for r in rows:
                if isinstance(r, dict) and '_hostname' in r:
                    r.setdefault('Hostname', r.get('_hostname') or '')
        out_path = dest_dir / fname
        with out_path.open('w', encoding='utf-8', newline='') as f:
            w = csv.writer(f)
            w.writerow(keys)
            for r in rows:
                if not isinstance(r, dict):
                    continue
                w.writerow([r.get(k, '') for k in keys])
        log(f"[CVE]   {artifact} → {fname}: {len(rows)} rows", "info")
        written.append(out_path)

    if not written:
        raise RuntimeError(
            f"Velociraptor {src_label} produced no rows for any of the four "
            f"required artifacts ({', '.join(targets.keys())}). Re-run a "
            f"Velociraptor hunt with those artifacts and try again."
        )
    return written
