"""Memory-forensics pipeline orchestrator.

The single public entry point :func:`run_memory_pipeline` is called
from :mod:`routes.memory_routes` (and the scheduler, eventually). It
walks the workflow through six phases:

  1. **Pre-flight** — disk pressure check, client liveness, config sanity.
  2. **Acquire** — Velociraptor ``Windows.Memory.Acquisition`` +
     ``fs:`` accessor extract → host .raw.
  3. **Upload** — chunked upload to VolWeb → ``evidence_id``.
  4. **Extract + yarascan** — one ``selective-extraction`` call with
     the curated 12-plugin set, plus yarascan against all seeded
     rulesets. Both poll concurrently.
  5. **Analyze** — selected mode (yara / plugin / layered) → markdown.
  6. **Cleanup** — auto-purge .raw across the three places it lives.

Every phase boundary checks the cancel event registered at workflow
start, so the Stop button kills the run promptly no matter where it
is. The cleanup hook runs on success AND failure so a half-baked
acquisition never leaks a multi-GB dump on disk.

Token-usage + LLM cost telemetry is inherited from
``services.agentic.analyzers.call_llm`` — the analyzer module's
single ``call_llm`` invocation records to the workflow row's
``llm_metrics`` dict for free.
"""

from __future__ import annotations

import os
import shutil
import time
import traceback
from typing import Any, Callable

from services.workflow_service import (
    add_log_to_run,
    is_cancelled,
    mutate_run_details,
    register_cancel_event,
    register_cleanup,
    unregister_cancel,
    update_run_status,
)
from .acquire import acquire_memory_dump, AcquisitionError
from .cleanup import cleanup_after_run
from .defaults import (
    ACQUISITION_DEFAULTS,
    CURATED_PLUGINS,
    DISK_PREFLIGHT_MULTIPLIER,
    YARA_CATEGORY_KEYWORDS,
)
from .volweb_client import VolWebClient, VolWebError


def _resolve_plugin_set(blueprint: dict | None, client: "VolWebClient",
                        evidence_id: int, log) -> tuple[str, ...]:
    """Pick the Vol3 plugin list to extract for this run.

    Resolution order:
      1. Blueprint's `settings.plugin_set` if non-empty and not the
         all-plugins marker.
      2. Marker ``['*']`` → query VolWeb for every plugin row it
         registered for this evidence (one row per plugin VolWeb knows
         how to run against this dump's profile). Used by the
         `memory_all_plugins` blueprint so the set stays correct as
         VolWeb adds/removes plugins, without us hardcoding 60+ class
         paths in the YAML.
      3. Fallback to ``CURATED_PLUGINS`` (the 12-plugin sweet-spot
         set from the PoC).
    """
    raw = (blueprint.get("settings") or {}).get("plugin_set") if blueprint else None
    raw = list(raw or [])

    if raw == ['*']:
        try:
            rows = client.list_plugins(evidence_id) or []
        except Exception as e:
            log(f"'*' resolution failed ({e!s}) — falling back to curated set", "warning")
            return CURATED_PLUGINS
        names = tuple(r['name'] for r in rows if r.get('name'))
        if not names:
            log("'*' resolved to empty list — falling back to curated set", "warning")
            return CURATED_PLUGINS
        log(f"'*' resolved to {len(names)} plugins available for evidence {evidence_id}", "info")
        return names

    return tuple(raw) if raw else CURATED_PLUGINS


def _extract_phase_label(run_plugins: bool, run_yara: bool) -> str:
    """One-line description of what the extract phase is about to do."""
    if run_plugins and run_yara:
        return "selective-extraction + yarascan"
    if run_plugins:
        return "selective-extraction (plugins only, no yara)"
    if run_yara:
        return "yarascan only (no plugins)"
    return "nothing to extract"


def _extract_queued_label(plugins_to_run, run_plugins: bool, run_yara: bool) -> str:
    """Post-trigger summary line: what actually got queued on VolWeb."""
    parts = []
    if run_plugins:
        parts.append(f"{len(plugins_to_run)} plugins queued")
    if run_yara:
        parts.append("yarascan queued")
    return " + ".join(parts) if parts else "nothing queued"


def _resolve_yara_scan_targets(
    blueprint: dict | None, client: "VolWebClient", log
) -> tuple[list[int] | None, list[int] | None]:
    """Pick the YARA scan scope for this run from the blueprint.

    Returns ``(rulesets, rules)`` to hand to :meth:`trigger_yarascan`:
      * ``(None, None)``  → scan the full active corpus (broad-net
        default — every seeded rule).
      * ``(None, [ids])`` → scan only the rules matching the blueprint's
        ``settings.yara_categories`` (a threat-typed subset).

    Resolution: if ``yara_categories`` is non-empty and not the ``['*']``
    marker, expand each category to its keywords
    (``defaults.YARA_CATEGORY_KEYWORDS``), union them, and resolve to
    concrete rule IDs via the backend. A non-empty result scopes the
    scan; anything else falls through to the full corpus.

    Fail-open by design: a memory YARA sweep that silently scans ZERO
    rules is worse than one that scans everything, so unknown categories,
    a resolution error, or a zero-rule match all return ``(None, None)``
    with a warning — never an empty ``rules=[]`` that would scan nothing.
    """
    settings = (blueprint or {}).get("settings") or {}
    cats = [c for c in (settings.get("yara_categories") or []) if c]
    if not cats or cats == ["*"]:
        return None, None

    keywords: list[str] = []
    unknown: list[str] = []
    for c in cats:
        kw = YARA_CATEGORY_KEYWORDS.get(str(c).strip().lower())
        if kw:
            keywords.extend(kw)
        else:
            unknown.append(str(c))
    if unknown:
        log(
            f"yara: ignoring unknown categories {unknown} "
            f"(known: {sorted(YARA_CATEGORY_KEYWORDS)})",
            "warning",
        )
    if not keywords:
        log("yara: no known categories resolved — scanning full corpus", "warning")
        return None, None

    try:
        ids = client.resolve_yara_rule_ids(keywords)
    except Exception as e:
        log(f"yara: category resolution errored ({e!s}) — scanning full corpus", "warning")
        return None, None
    if not ids:
        log(f"yara: categories {cats} matched 0 rules — scanning full corpus", "warning")
        return None, None

    log(f"yara: scoped to categories {cats} → {len(ids)} rules", "info")
    return None, ids


# Phase progress weights (sum to ~95; the final 5 is reserved for
# Cleanup + Reporting). Tuned from the PoC runs — Acquire dominates
# wall-clock on a fresh capture; Analyze is cheap once the data is
# there.
_PHASE_WEIGHTS = {
    "preflight": 2,
    "acquire": 35,
    "upload":   15,
    "extract":  20,   # plugin extraction
    "yarascan": 15,   # parallel with extract; we attribute its slice independently
    "analyze":   8,
    "cleanup":   5,
}

# Volatility's YaraScan plugin scans the whole image against the full
# rule corpus at roughly ~400 s/GB (measured 2026-06-16: a 5 GB dump ×
# 1454 rules took ~1595 s). A FIXED yarascan timeout is therefore wrong
# for some dump size — too low and the wait gives up while the scan is
# still running, reporting hits=0 and (pre-fix) destroying the results.
# These drive a size-aware floor.
_YARASCAN_BASE_OVERHEAD_S = 600     # fixed setup cost (symbol scan, rule compile)
_YARASCAN_SECONDS_PER_GB  = 400     # generous; real rate ~320 s/GB


def _effective_yarascan_timeout(
    base_s: int,
    host_path: str | None,
    operator_set: bool,
    log: Callable[[str, str], None],
) -> int:
    """Return the yarascan wait budget scaled to the dump size.

    - operator did NOT set it → silently raise to the size-aware floor
      so the default just works for any dump size.
    - operator DID set it but it's below the floor → respect their
      value (they asked for a bounded run) but warn loudly; the cleanup
      safety net preserves results if it overruns, only the in-run hit
      count is at risk.
    """
    try:
        size_gb = (
            os.path.getsize(host_path) / (1024 ** 3)
            if host_path and os.path.exists(host_path) else 0.0
        )
    except Exception:
        size_gb = 0.0
    if size_gb <= 0:
        return base_s
    recommended = int(_YARASCAN_BASE_OVERHEAD_S + _YARASCAN_SECONDS_PER_GB * size_gb)
    if base_s >= recommended:
        return base_s
    if operator_set:
        log(
            f"yarascan_timeout_s={base_s}s is below the ~{recommended}s a "
            f"{size_gb:.1f} GB dump usually needs (~{_YARASCAN_SECONDS_PER_GB} s/GB). "
            f"Respecting your value — results survive if the scan overruns "
            f"(dir preserved), but the hit count may not land in THIS run. "
            f"Raise it to ~{recommended}s to capture the count in-run.",
            "warning",
        )
        return base_s
    log(
        f"yarascan: scaling wait {base_s}s → {recommended}s for the "
        f"{size_gb:.1f} GB dump (~{_YARASCAN_SECONDS_PER_GB} s/GB).",
        "info",
    )
    return recommended


def _llm_config_from_runtime() -> dict:
    """Pull the active ``frontend_config`` and return the dict shape
    ``services.agentic.analyzers.call_llm`` expects (``{'agentic': {...}}``).
    """
    from services.storage.config_store import load_frontend_config  # local import
    cfg = load_frontend_config() or {}
    # call_llm reads cfg['agentic'] — memory module reuses agentic's
    # LLM config rather than introducing a parallel one (matches what
    # SECRETS.md documents).
    return {"agentic": cfg.get("agentic", {}) or {}}


def _bump(run_id: str, percent: int, log_msg: str | None = None) -> None:
    update_run_status(run_id, "running", progress=min(percent, 99))
    if log_msg:
        add_log_to_run(run_id, log_msg, "info")


def _persist_cleanup_state(run_id: str, **fields) -> None:
    """Mirror the in-flight acquisition's identifiers (client_id, flow_id,
    host_path, evidence_id/filename) into the workflow row's `details` as
    soon as each becomes known.

    register_cleanup()'s callback closure is IN-MEMORY ONLY — if the
    backend process crashes or restarts mid-run, that closure is lost and
    cleanup_after_run() never fires, leaking the Velociraptor flow (still
    running on the endpoint) and the multi-GB .raw dump on disk. Boot-time
    orphan reaping (app.py's restart reaper) reads this persisted state
    back to run the same cleanup after a crash — see cleanup_orphaned_memory_acquisition().
    """
    try:
        mutate_run_details(run_id, lambda d: d.setdefault("_cleanup_state", {}).update(
            {k: v for k, v in fields.items() if v is not None}
        ))
    except Exception:
        pass


def _disk_preflight(
    run_id: str, dumps_dir: str, mem_bytes_estimate: int | None
) -> None:
    """Refuse to dispatch if there isn't enough headroom for three
    transient copies of the dump.

    ``mem_bytes_estimate`` is best-effort: the Velociraptor client
    record's ``os_info.total_memory_bytes`` (when present) is the
    cleanest signal. Falls back to 8 GiB (a typical Win10 desktop)
    when unknown — preflight is a safety net, not a hard SLA.
    """
    try:
        # Must check dumps_dir's own filesystem, not "/" — dumps_dir is
        # typically a separate bind-mounted data volume, and "/" being
        # roomy tells us nothing about whether the actual destination has
        # room for a multi-GB dump (see acquire.py's _preflight_capacity
        # for the same pattern already done correctly).
        os.makedirs(dumps_dir, exist_ok=True)
        free_bytes = shutil.disk_usage(dumps_dir).free
    except OSError as e:
        add_log_to_run(run_id, f"preflight: disk_usage failed: {e}", "warning")
        return
    # Default 4 GiB if Velociraptor doesn't expose total_memory_bytes.
    # Most observed in-prod dumps run 3-5 GB on Win10/11 clients with
    # 4-8 GB RAM; using 4 GiB as the assumption keeps preflight from
    # rejecting installs with ~10 GB free disk while still catching
    # the dangerous "out of disk while dumping" case. The multiplier
    # in DISK_PREFLIGHT_MULTIPLIER provides the safety margin.
    est = mem_bytes_estimate or (4 * 1024 * 1024 * 1024)
    required = int(est * DISK_PREFLIGHT_MULTIPLIER)
    add_log_to_run(
        run_id,
        f"preflight: free={free_bytes // 1024 // 1024} MB "
        f"required>={required // 1024 // 1024} MB "
        f"(estimate {est // 1024 // 1024} MB × {DISK_PREFLIGHT_MULTIPLIER})",
        "info",
    )
    if free_bytes < required:
        raise RuntimeError(
            f"insufficient disk: need ≥ {required // 1024 // 1024} MB free, "
            f"have {free_bytes // 1024 // 1024} MB"
        )


def _estimate_client_memory_bytes(client_id: str) -> int | None:
    """Look up ``os_info.total_memory_bytes`` for a client via the
    existing snapshot reader. Returns ``None`` if missing."""
    try:
        from services.velociraptor_service import get_clients_from_snapshot
        for c in get_clients_from_snapshot(include_offline=True) or []:
            if c.get("client_id") == client_id:
                info = c.get("os_info") or {}
                v = info.get("total_memory_bytes") or info.get("ram_bytes")
                return int(v) if v else None
    except Exception:
        pass
    return None


def _build_extraction_only_report(
    *,
    evidence_id: int,
    client,
    mode: str,
    case_name: str,
    client_name: str | None,
) -> str:
    """Synthesise the minimal extraction-only markdown report for a memory run.

    Memory is collect-only — the LLM analysis/reporting happens at Case Analysis
    (fusion). Stitches together the raw extraction primitives:
      * plugin row counts per plugin (so the operator sees what
        landed in VolWeb)
      * yarascan match count
      * direct links into the VolWeb UI for hands-on review

    Deliberately stays small (~2 KB). The whole point of LLM-skip
    mode is to avoid the synthesis step; we just provide a clean
    handoff back to a human analyst.
    """
    from datetime import datetime

    parts: list[str] = []
    parts.append(f"# Memory Forensics — Extraction Report")
    parts.append("")
    parts.append(f"**Case:** {case_name}  ")
    parts.append(f"**Host:** {client_name or '(uploaded dump)'}  ")
    parts.append(f"**Mode:** {mode} (extraction only — LLM analysis disabled)  ")
    parts.append(f"**Generated:** {datetime.now().isoformat(timespec='seconds')}  ")
    parts.append(f"**VolWeb evidence ID:** `{evidence_id}`")
    parts.append("")

    parts.append("## Plugin extraction")
    parts.append("")
    try:
        rows = client.list_plugins(evidence_id) or []
    except Exception as e:
        rows = []
        parts.append(f"_Could not list plugins: {e}_")
    if rows:
        parts.append("| Plugin | Status |")
        parts.append("|---|---|")
        for r in rows:
            short = (r.get("name") or "?").rsplit(".", 1)[-1]
            if r.get("results"):
                status = "✓ has results"
            elif r.get("error") or "alert" in (r.get("icon") or "").lower():
                status = f"✗ errored: {str(r.get('error'))[:80]}"
            else:
                status = "… queued / running"
            parts.append(f"| `{short}` | {status} |")
    elif mode == "yara":
        parts.append("_Plugin extraction not run for this collection (yara-only mode)._")
    parts.append("")

    parts.append("## YARA scan")
    parts.append("")
    try:
        hist = client.yarascan_history(evidence_id) or []
        if hist:
            count = (hist[0] or {}).get("count")
            scan_id = (hist[0] or {}).get("scan_id") or "?"
            parts.append(f"- Scan id: `{scan_id}`")
            parts.append(f"- Total matches: **{count}**")
        elif mode == "plugin":
            parts.append("_YARA scan not run for this collection (plugin-only mode)._")
        else:
            parts.append("_No yarascan history found yet — task may still be running._")
    except Exception as e:
        parts.append(f"_Could not fetch yarascan history: {e}_")
    parts.append("")

    parts.append("## Next steps")
    parts.append("")
    parts.append("- Open the VolWeb UI for this evidence to review plugin tables + per-hit context interactively.")
    parts.append("- Re-run with **LLM analysis enabled** to get an engagement-ready findings report.")
    parts.append("- Toggle the **Validate (chat)** button to ask follow-up questions over chat once an LLM run exists.")
    return "\n".join(parts)


def _persist_fusion_payload(run_id, client, evidence_id, log) -> None:
    """Snapshot the memory fusion payload (plugin rows + yara hits) to
    ``/data/downloads/<run_id>/memory_payload.json`` BEFORE cleanup runs.

    Why this exists: cleanup purges the VolWeb evidence dir to reclaim the
    multi-GB image, and the yarascan RESULTS FILE lives under that dir. Fusion
    (``store._memory_contribution``) used to lazily re-fetch plugins + yara
    from VolWeb at fuse time — but by then cleanup has deleted the yara
    results, so ``/yarascan/results/`` 404s and every hit silently vanishes
    from the graph (plugin rows survive in VolWeb's DB; yara does not). We
    fetch both here, while the evidence is still intact, and let fusion read
    this snapshot first. Bonus: no VolWeb round-trip per fuse.
    """
    import json
    import os

    from .analyzers import _build_plugin_payload, _build_yara_payload

    plugins, _pw = _build_plugin_payload(client, evidence_id)
    try:
        hits, _tot = _build_yara_payload(client, evidence_id)
    except Exception as e:  # noqa: BLE001 — yara is optional, never lose plugins
        log(f"persist: yara fetch failed ({e}) — snapshot will omit yara", "warning")
        hits = []
    downloads_dir = f"/data/downloads/{run_id}"
    os.makedirs(downloads_dir, exist_ok=True)
    with open(f"{downloads_dir}/memory_payload.json", "w") as f:
        json.dump({"plugins": plugins, "yara": hits}, f)
    plugin_rows = sum(len(v) for v in plugins.values() if hasattr(v, "__len__"))
    log(
        f"persist: memory fusion payload snapshot saved "
        f"({plugin_rows} plugin rows, {len(hits)} yara hits)",
        "info",
    )


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def run_memory_pipeline(
    *,
    run_id: str,
    client_id: str = "",
    client_name: str | None = None,
    mode: str = "layered",
    case_name: str = "Memory",
    dumps_dir: str = "/data/memory_dumps",
    blueprint: dict | None = None,
    from_upload_path: str | None = None,
    timeouts: dict | None = None,
) -> None:
    # Resolved timeouts in seconds. Operator override (UI textbox)
    # wins over blueprint.settings, which wins over defaults. Defaults
    # are tuned for a typical 4-8 GB Win10/11 client; bigger dumps or
    # slower hardware benefit from bumping these up.
    _to = dict(timeouts or {})
    bp_settings = (blueprint or {}).get("settings") or {}
    def _t(key: str, default: int) -> int:
        try:
            return int(_to.get(key) or bp_settings.get(key) or default)
        except (TypeError, ValueError):
            return default
    acquire_flow_timeout_s = _t("acquire_flow_timeout_s", 5400)   # 90 min
    plugin_timeout_s       = _t("plugin_timeout_s",       1800)   # 30 min
    yarascan_timeout_s     = _t("yarascan_timeout_s",     3600)   # 60 min default (bumped 2026-06-17)
    # Did the operator explicitly set the yarascan timeout (vs default/
    # blueprint)? If so we respect it but warn when it's too low for the
    # dump size; if not, we silently scale it up to a size-aware floor.
    yarascan_timeout_operator_set = "yarascan_timeout_s" in _to
    """Run a memory-forensics pipeline end-to-end.

    Contract: takes a pre-created workflow ``run_id`` (the route
    handler creates it via ``create_automation_run`` so the operator
    sees the row immediately even while we wait for acquisition).
    Updates the row's status + progress + logs throughout. Never
    raises — terminal failures are mapped to ``status='failed'``
    with the error captured in the log timeline.

    Args:
      run_id: workflow id created upstream.
      client_id: Velociraptor client id (per-host — memory acquisition
        is single-target by design).
      client_name: hostname for the log timeline (falls back to
        Velociraptor's reported name post-acquire if not provided).
      mode: ``"yara"`` | ``"plugin"`` | ``"layered"`` (default).
      case_name: VolWeb case to attach the evidence to. Created if
        missing. Cases are how engagement reports group memory runs.
      dumps_dir: host directory for transient .raw files. Created if
        missing.
      blueprint: optional blueprint dict with overrides
        (``plugin_set``, ``yara_rulesets``, ``compression``,
        ``max_bytes``, etc.).
    """
    cancel_event = register_cancel_event(run_id)
    cancel = cancel_event.is_set  # for compactness in cancel checks

    # Per-phase state that cleanup needs, populated as we go.
    flow_id: str | None = None
    host_path: str | None = None
    evidence_id: int | None = None
    evidence_filename: str | None = None
    # Set True when the yarascan wait times out while the scan is still
    # running — tells cleanup to PRESERVE media/<id>/ so in-flight
    # matches aren't destroyed (2026-06-17 incident).
    yarascan_incomplete: bool = False
    client = VolWebClient(
        logger=lambda m, level="info": add_log_to_run(run_id, m, level),
    )

    def log(msg: str, level: str = "info") -> None:
        add_log_to_run(run_id, msg, level)

    # ----------------------------------------------------------------
    # Register a single all-encompassing cleanup callback so Stop
    # triggers cleanup the same way a normal failure path would.
    # ----------------------------------------------------------------
    def _cleanup() -> None:
        cleanup_after_run(
            client_id=client_id,
            flow_id=flow_id,
            host_path=host_path,
            evidence_id=evidence_id,
            evidence_filename=evidence_filename,
            volweb_client=client,
            delete_evidence_row=False,   # operator's report+plugin rows stay
            preserve_evidence_dir=yarascan_incomplete,
            logger=log,
        )

    register_cleanup(run_id, _cleanup)

    started_at = time.time()
    cumulative = 0

    try:
        # ----------------------------------------------------------------
        # Mode validation (fail loud on typo from the route)
        # ----------------------------------------------------------------
        if mode not in ("yara", "plugin", "layered"):
            raise ValueError(f"invalid mode {mode!r}")
        log(f"pipeline: mode={mode} client={client_id} case={case_name!r}")
        _persist_cleanup_state(run_id, client_id=client_id or None)

        # Whether to run the VolWeb yarascan at all. The "Include YARA" checkbox
        # in the UI maps to the analysis mode: plugin = plugins only (NO yara),
        # layered = plugins + yara, yara = yara-focused. The extract phase used
        # to trigger yarascan UNCONDITIONALLY, so a plugin-only run still fired a
        # full 600+-rule scan (operator-reported 2026-07). Gate it on the mode.
        run_yara = mode in ("yara", "layered")
        if not run_yara:
            log("pipeline: yarascan disabled for this run (plugin-only mode)", "info")

        # Whether to run Vol3 plugin extraction at all — the MIRROR of run_yara.
        # A yara-only blueprint ships an EMPTY plugin_set (mode=yara), and the
        # UI maps "no plugins picked" to yara mode. The extract phase used to
        # ALWAYS resolve a plugin set, and _resolve_plugin_set falls back to the
        # 12 CURATED_PLUGINS when the set is empty — so a yara-only run silently
        # ran 12 plugins (operator-reported 2026-07). Gate plugins on the mode:
        # only plugin/layered runs extract plugins; yara mode runs yarascan only.
        run_plugins = mode in ("plugin", "layered")
        if not run_plugins:
            log("pipeline: plugin extraction disabled for this run (yara-only mode)", "info")

        # ----------------------------------------------------------------
        # Phase 1 — Preflight
        # ----------------------------------------------------------------
        if from_upload_path:
            # Offline-upload path: the operator already has a dump
            # (Velociraptor "Prepare Download" export, an offline
            # collector's PhysicalMemory.raw, or any raw memory image).
            # We skip the preflight + acquire phases and feed the file
            # directly into Phase 3.
            import os
            if not os.path.isfile(from_upload_path):
                raise RuntimeError(f"upload file missing: {from_upload_path}")
            size_b = os.path.getsize(from_upload_path)
            host_path = from_upload_path
            flow_id = None   # no Velociraptor flow when uploaded offline
            _persist_cleanup_state(run_id, host_path=host_path)
            log(
                f"pipeline: offline-upload — using {host_path} ({size_b // 1024 // 1024} MB)",
                "info",
            )
            cumulative += _PHASE_WEIGHTS["preflight"] + _PHASE_WEIGHTS["acquire"]
            _bump(run_id, cumulative, "offline-upload: bypassed acquire")
            if cancel():
                raise RuntimeError("cancelled before upload")

            # ------------------------------------------------------------
            # Phase 3 (still runs) — Upload to VolWeb
            # ------------------------------------------------------------
            log(f"pipeline: upload — chunked to VolWeb case={case_name!r}", "info")
            case_id = client.ensure_case(case_name)
            evidence_id = client.upload_evidence(
                host_path,
                case_id=case_id,
                os_name="windows",
                cancel_check=cancel,
                progress_cb=lambda sent, total, mbps: add_log_to_run(
                    run_id,
                    f"upload: {sent//1024//1024}/{total//1024//1024} MB  ({mbps:.1f} MB/s)",
                    "info",
                ),
            )
            evidence_filename = client.get_evidence(evidence_id).get("name")
            _persist_cleanup_state(run_id, evidence_id=evidence_id, evidence_filename=evidence_filename)
            cumulative += _PHASE_WEIGHTS["upload"]
            _bump(run_id, cumulative, f"upload: evidence_id={evidence_id}")
            if cancel():
                raise RuntimeError("cancelled after upload")

            # ------------------------------------------------------------
            # Phase 4 (offline-upload branch) — Extract + yarascan
            # ------------------------------------------------------------
            log("pipeline: extract — " + _extract_phase_label(run_plugins, run_yara), "info")
            client.stage_media_dir(evidence_id)
            plugins_to_run: tuple[str, ...] = ()
            if run_plugins:
                plugins_to_run = _resolve_plugin_set(blueprint, client, evidence_id, log)
            _yara_rulesets, _yara_rules = (None, None)
            if run_yara:
                _yara_rulesets, _yara_rules = _resolve_yara_scan_targets(blueprint, client, log)
            if run_plugins:
                client.trigger_extraction(evidence_id, plugins_to_run)
            if run_yara:
                client.trigger_yarascan(evidence_id, rulesets=_yara_rulesets, rules=_yara_rules)
            log("pipeline: extract — " + _extract_queued_label(plugins_to_run, run_plugins, run_yara), "info")
            if run_plugins:
                ext_started = time.time()
                client.wait_for_plugin_results(
                    evidence_id,
                    plugins_to_run,
                    timeout_s=plugin_timeout_s,
                    cancel_check=cancel,
                    on_progress=lambda done, total: _bump(
                        run_id,
                        cumulative + int(_PHASE_WEIGHTS["extract"] * (done / max(total, 1))),
                    ),
                )
                cumulative += _PHASE_WEIGHTS["extract"]
                log(
                    f"pipeline: extract — plugins complete in {int(time.time() - ext_started)}s",
                    "success",
                )
                if cancel():
                    raise RuntimeError("cancelled after plugin extract")
            else:
                cumulative += _PHASE_WEIGHTS["extract"]   # credit the skipped phase so progress completes
                _bump(run_id, cumulative, "extract: plugins skipped (yara-only mode)")
            if run_yara:
                yara_started = time.time()
                _eff_yara_to = _effective_yarascan_timeout(
                    yarascan_timeout_s, host_path, yarascan_timeout_operator_set, log,
                )
                hit_count, _yara_done = client.wait_for_yarascan(
                    evidence_id,
                    timeout_s=_eff_yara_to,
                    cancel_check=cancel,
                )
                yarascan_incomplete = not _yara_done
                cumulative += _PHASE_WEIGHTS["yarascan"]
                log(
                    f"pipeline: yarascan — complete in {int(time.time() - yara_started)}s  hits={hit_count}",
                    "success",
                )
                _bump(run_id, cumulative, f"extract: ready (yara hits={hit_count})")
            else:
                hit_count = 0
                cumulative += _PHASE_WEIGHTS["yarascan"]   # credit the skipped phase so progress completes
                _bump(run_id, cumulative, "extract: ready (yarascan skipped — plugin-only mode)")
            if cancel():
                raise RuntimeError("cancelled after yarascan")
        else:
            cumulative += _PHASE_WEIGHTS["preflight"]
            _bump(run_id, cumulative, "preflight: disk + client checks")
            mem_estimate = _estimate_client_memory_bytes(client_id)
            _disk_preflight(run_id, dumps_dir, mem_estimate)
            if cancel():
                raise RuntimeError("cancelled during preflight")

            # ------------------------------------------------------------
            # Phase 2 — Acquire
            # ------------------------------------------------------------
            log("pipeline: acquire — dispatching Windows.Memory.Acquisition", "info")
            overrides: dict[str, Any] = {}
            if blueprint:
                bp_settings = (blueprint.get("settings") or {})
                for k in ("max_bytes", "cpu_limit", "compression"):
                    if bp_settings.get(k) is not None:
                        overrides[k] = bp_settings[k]
            acq = acquire_memory_dump(
                client_id,
                dumps_dir=dumps_dir,
                logger=lambda m, level="info": add_log_to_run(run_id, m, level),
                run_id=run_id,
                cancel_check=cancel,
                flow_timeout=acquire_flow_timeout_s,
                poll_max_min=max(5, acquire_flow_timeout_s // 60),
                **overrides,
            )
            flow_id = acq["flow_id"]
            host_path = acq["host_path"]
            client_name = client_name or acq.get("hostname")
            _persist_cleanup_state(run_id, flow_id=flow_id, host_path=host_path)
            cumulative += _PHASE_WEIGHTS["acquire"]
            _bump(
                run_id, cumulative,
                f"acquire: complete — {acq['size_bytes'] // 1024 // 1024} MB at {host_path}",
            )
            if cancel():
                raise RuntimeError("cancelled after acquire")

            # ------------------------------------------------------------
            # Phase 3 — Register / Upload to VolWeb
            #
            # If acquire used the shared-volume fast-path (in-tree
            # Velociraptor + in-tree VolWeb), the .raw is already
            # visible to VolWeb at /home/app/web/media/staging/<name>.
            # We just move it to evidences/ + insert the DB row.
            # Otherwise (PoC VolWeb, no shared volume) fall back to
            # the original chunked HTTP upload.
            # ------------------------------------------------------------
            case_id = client.ensure_case(case_name)
            if acq.get("shared_volume"):
                log("pipeline: register — using shared volume (no HTTP upload)", "info")
                evidence_id = client.register_existing_file(
                    acq["shared_basename"],
                    case_id=case_id,
                    os_name="windows",
                )
                evidence_filename = acq["shared_basename"]
                _persist_cleanup_state(run_id, evidence_id=evidence_id, evidence_filename=evidence_filename)
            else:
                log(f"pipeline: upload — chunked to VolWeb case={case_name!r}", "info")
                evidence_id = client.upload_evidence(
                    host_path,
                    case_id=case_id,
                    os_name="windows",
                    cancel_check=cancel,
                    progress_cb=lambda sent, total, mbps: add_log_to_run(
                        run_id,
                        f"upload: {sent//1024//1024}/{total//1024//1024} MB  ({mbps:.1f} MB/s)",
                        "info",
                    ),
                )
                evidence_filename = client.get_evidence(evidence_id).get("name")
                _persist_cleanup_state(run_id, evidence_id=evidence_id, evidence_filename=evidence_filename)
            cumulative += _PHASE_WEIGHTS["upload"]
            _bump(run_id, cumulative, f"upload: evidence_id={evidence_id}")
            if cancel():
                raise RuntimeError("cancelled after upload")

            # ------------------------------------------------------------
            # Phase 4 — Extraction (plugins + yarascan)
            # ------------------------------------------------------------
            log("pipeline: extract — " + _extract_phase_label(run_plugins, run_yara), "info")

            # Pre-stage media/<id>/ FIRST so the yarascan worker doesn't
            # hit the empty-dir race from the PoC.
            client.stage_media_dir(evidence_id)

            # Determine plugin set (blueprint override or curated default) —
            # only when this mode runs plugins (yara-only mode runs none).
            plugins_to_run: tuple[str, ...] = ()
            if run_plugins:
                plugins_to_run = _resolve_plugin_set(blueprint, client, evidence_id, log)
            # Determine YARA scope (blueprint yara_categories → rule subset,
            # or full corpus). None,None == scan everything.
            _yara_rulesets, _yara_rules = (None, None)
            if run_yara:
                _yara_rulesets, _yara_rules = _resolve_yara_scan_targets(blueprint, client, log)

            # Trigger BOTH tasks before waiting on either — they run on
            # separate Celery queues and execute concurrently.
            if run_plugins:
                client.trigger_extraction(evidence_id, plugins_to_run)
            if run_yara:
                client.trigger_yarascan(evidence_id, rulesets=_yara_rulesets, rules=_yara_rules)

            log("pipeline: extract — " + _extract_queued_label(plugins_to_run, run_plugins, run_yara), "info")

            # Phase 4a — wait for plugins (skipped in yara-only mode).
            if run_plugins:
                ext_started = time.time()
                client.wait_for_plugin_results(
                    evidence_id,
                    plugins_to_run,
                    timeout_s=plugin_timeout_s,
                    cancel_check=cancel,
                    on_progress=lambda done, total: _bump(
                        run_id,
                        cumulative + int(_PHASE_WEIGHTS["extract"] * (done / max(total, 1))),
                    ),
                )
                cumulative += _PHASE_WEIGHTS["extract"]
                log(
                    f"pipeline: extract — plugins complete in {int(time.time() - ext_started)}s",
                    "success",
                )
                if cancel():
                    raise RuntimeError("cancelled after plugin extract")
            else:
                cumulative += _PHASE_WEIGHTS["extract"]   # credit the skipped phase so progress completes
                _bump(run_id, cumulative, "extract: plugins skipped (yara-only mode)")

            # Phase 4b — wait for yarascan history record.
            if run_yara:
                yara_started = time.time()
                _eff_yara_to = _effective_yarascan_timeout(
                    yarascan_timeout_s, host_path, yarascan_timeout_operator_set, log,
                )
                hit_count, _yara_done = client.wait_for_yarascan(
                    evidence_id,
                    timeout_s=_eff_yara_to,
                    cancel_check=cancel,
                )
                yarascan_incomplete = not _yara_done
                cumulative += _PHASE_WEIGHTS["yarascan"]
                log(
                    f"pipeline: yarascan — complete in {int(time.time() - yara_started)}s  hits={hit_count}",
                    "success",
                )
                _bump(run_id, cumulative, f"extract: ready (yara hits={hit_count})")
            else:
                hit_count = 0
                cumulative += _PHASE_WEIGHTS["yarascan"]   # credit the skipped phase so progress completes
                _bump(run_id, cumulative, "extract: ready (yarascan skipped — plugin-only mode)")
            if cancel():
                raise RuntimeError("cancelled after yarascan")

        # ----------------------------------------------------------------
        # Phase 5 — Report (extraction-only). Memory is a COLLECTOR: the LLM
        # analysis + reporting now happen at Case Analysis (fusion). We emit a
        # minimal extraction-only report for the workflow's own download; the
        # fused case is the reporting surface.
        # ----------------------------------------------------------------
        report_md = _build_extraction_only_report(
            evidence_id=evidence_id,
            client=client,
            mode=mode,
            case_name=case_name,
            client_name=client_name,
        )
        cumulative += _PHASE_WEIGHTS["analyze"]
        _bump(run_id, cumulative, f"report: extraction-only ({len(report_md):,} chars)")

        # ----------------------------------------------------------------
        # Persist report into the workflow row's details so the route
        # layer can serve it from /download. Mirrors agentic's pattern.
        # ----------------------------------------------------------------
        update_run_status(
            run_id, "running",
            progress=cumulative,
            details={
                "report_md": report_md,
                "report_warnings": [],
                "mode": mode,
                "evidence_id": evidence_id,
                "evidence_filename": evidence_filename,
                "flow_id": flow_id,
                "host_path": host_path,
                "client_id": client_id,
                "client_name": client_name,
                "case_name": case_name,
            },
        )

        # ----------------------------------------------------------------
        # Snapshot the fusion payload (plugins + yara hits) to a sidecar
        # BEFORE cleanup. Cleanup purges the VolWeb evidence dir, which holds
        # the yarascan RESULTS FILE — so a lazy re-fetch at fuse time 404s and
        # every yara hit vanishes from the graph. See _persist_fusion_payload.
        # ----------------------------------------------------------------
        try:
            _persist_fusion_payload(run_id, client, evidence_id, log)
        except Exception as _pe:  # noqa: BLE001 — never block completion on the snapshot
            log(
                f"persist: fusion-payload snapshot failed ({_pe}) — fusion will fall "
                "back to a live VolWeb fetch (yara may be lost after cleanup)",
                "warning",
            )

        # ----------------------------------------------------------------
        # Phase 6 — Cleanup (post-success: keep DB rows, remove .raw files)
        # ----------------------------------------------------------------
        log("pipeline: cleanup — purging .raw files on host + VolWeb + Velociraptor", "info")
        _cleanup()
        cumulative += _PHASE_WEIGHTS["cleanup"]

        elapsed = time.time() - started_at
        update_run_status(run_id, "completed", progress=100)
        add_log_to_run(
            run_id,
            f"pipeline: complete in {elapsed:.0f}s  mode={mode}  evidence={evidence_id}",
            "success",
        )

    except Exception as exc:  # noqa: BLE001 — final boundary
        # Trace goes to backend stderr; the operator sees a single
        # clean error line in the workflow log.
        traceback.print_exc()
        err_msg = str(exc) or exc.__class__.__name__
        add_log_to_run(run_id, f"pipeline: failed — {err_msg}", "error")
        # Cleanup runs whether or not the failure was during a phase that
        # produced disk artefacts; cleanup_after_run is safe with all
        # arguments None.
        try:
            _cleanup()
        except Exception as cleanup_err:
            add_log_to_run(
                run_id, f"pipeline: cleanup-after-failure error: {cleanup_err}", "warning"
            )
        update_run_status(run_id, "failed", progress=0, error=err_msg)
    finally:
        unregister_cancel(run_id)


__all__ = ["run_memory_pipeline"]
