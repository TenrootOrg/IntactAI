"""Case persistence + fuse orchestration.

A Case is just a workflow row (``automation_type='case'``) whose ``details``
hold the window/severity, member run ids, the fused graph, the report, and
chat. Reuses workflow_service entirely — no new table. Member runs are
fetched, dispatched to their module mapper, assembled into one graph by
``correlate.assemble``, then narrated by ``llm_sim`` (simulated).
"""

from __future__ import annotations

import json
import os

from .schema import FusionGraph
from . import correlate, llm_sim, keys, render, budget
from .mappers import map_memory, map_agentic, map_cve, map_timesketch, map_cloud

CASE_TYPE = "case"
BASELINE_TYPE = "fusion_baseline"
DEFAULT_CASE_NAME = "Default"
SYSTEM_CASE_NAME = "System"

# Per-case storage cap on the fused graph (operator-tunable via the config rail).
DEFAULT_MAX_ENTITIES = 500000       # entity limit default (stored graph; LLM auto-takes a context-safe subset)
MAX_GRAPH_ENTITIES = 1_000_000      # sanity ceiling only (a graph never has this many)

# Fusion modules: which run types each selectable module groups.
#   velociraptor_agentic = runs from Velociraptor *Agentic* blueprints (the
#       curated, bounded forensic collections + offline-collector imports).
#   velociraptor_all     = ALL Velociraptor blueprints, incl. hunts — some hunt
#       artifacts produce huge output, so this is the costly option (disabled).
# `available` modules can be toggled in the UI; `disabled` ones are shown greyed
# (their runs stay tagged but never fuse). Default = velociraptor_agentic only.
FUSION_MODULE_TYPES = {
    "velociraptor_agentic": {"velociraptor_collection", "velociraptor_upload"},
    "velociraptor_all": {"velociraptor_collection", "velociraptor_upload",
                         "velociraptor_hunt"},
    "memory": {"memory"},
    "timesketch": {"timesketch"},
    "cve": {"cve_scan"},
    "aws": {"aws_scan"},
    "azure": {"azure_scan"},
    # legacy alias for cases saved before the agentic/all split (maps to agentic)
    "velociraptor": {"velociraptor_collection", "velociraptor_upload"},
}
# Order + membership of the UI picker (legacy 'velociraptor' alias is not shown).
FUSION_MODULES_UI = ["velociraptor_agentic", "velociraptor_all", "memory",
                     "timesketch", "cve", "aws", "azure"]
# Selectable now: Velociraptor (Agentic) [default-on], Velociraptor (All) + Memory
# [selectable, off]. The rest (TimeSketch/CVE/AWS/Azure) are shown greyed/disabled.
FUSION_MODULES_AVAILABLE = ("velociraptor_agentic", "velociraptor_all", "memory")
FUSION_MODULES_DEFAULT = ["velociraptor_agentic"]
_FUSION_MODULE_LABELS = {
    "velociraptor_agentic": "Velociraptor (Agentic)",
    "velociraptor_all": "Velociraptor (All)",
    "memory": "Memory (VolWeb)",
    "timesketch": "TimeSketch", "cve": "CVE", "aws": "AWS", "azure": "Azure",
}


def normalize_modules(mods):
    """Map legacy module names to current ones + apply the default. Keeps cases
    saved before the agentic/all rename working without a data migration."""
    if not mods:
        return list(FUSION_MODULES_DEFAULT)
    out = ["velociraptor_agentic" if m == "velociraptor" else m for m in mods]
    return out or list(FUSION_MODULES_DEFAULT)


def fusion_modules_catalog():
    """The module picker model for the UI: every selectable fusion module with
    its label, whether it's available right now, and whether it's on by default."""
    return [{"name": m, "label": _FUSION_MODULE_LABELS.get(m, m),
             "available": m in FUSION_MODULES_AVAILABLE,
             "default": m in FUSION_MODULES_DEFAULT}
            for m in FUSION_MODULES_UI]


def _enabled_run_types(d):
    """Run types fusable for this case = the union of its enabled modules' types.
    None/legacy modules fall back to the velociraptor-agentic default."""
    allowed = set()
    for m in normalize_modules(d.get("fusion_modules")):
        allowed |= FUSION_MODULE_TYPES.get(m, set())
    return allowed


_VELOCIRAPTOR_TYPES = {"velociraptor_collection", "velociraptor_upload", "velociraptor_hunt"}


def _is_agentic_run(run) -> bool:
    """True when a Velociraptor run came from an AGENTIC blueprint.

    Every Velociraptor run is fused regardless; this only TAGS it so the Case
    Analysis 'Modules' picker can include 'Velociraptor (Agentic)' (agentic only)
    vs 'Velociraptor (All)' (agentic + general).

    Prefer the explicit details['is_agentic'] flag stamped at run-creation /
    import time. Fall back to the '[Agentic]' marker the agentic blueprints put
    on every hunt/collector description (e.g. '[Agentic] Quick Wins Extended') —
    visible in the run name, blueprint label, or captured hunt description — so
    runs created before tagging existed still classify correctly. (Neither run
    TYPE nor a blueprint_id is reliable: imports carry no blueprint_id and hunts
    store only a name; for imports the description is captured at import time via
    upload_routes._fuse_offline_import -> velociraptor_service.get_hunt_description
    into details['hunt_description'].)"""
    det = run.get("details") or {}
    if det.get("is_agentic") is not None:
        return bool(det.get("is_agentic"))
    hay = " ".join(str(x) for x in (
        run.get("name"), det.get("blueprint"),
        det.get("hunt_description"), det.get("description"),
    ) if x).lower()
    return "agentic" in hay


def _run_passes_gate(run, d) -> bool:
    """Whether `run` belongs to at least one of the case's enabled fusion modules.

    The Velociraptor split is by AGENTIC PROVENANCE (the '[Agentic]' description),
    NOT by run type:
      - velociraptor_agentic -> Velociraptor runs (collection/upload/hunt) whose
        description/name is tagged Agentic.
      - velociraptor_all     -> every Velociraptor run, agentic or not.
    Non-Velociraptor modules (memory/cve/aws/azure/timesketch) gate on type as
    before. Replaces the old pure-type gate (`automation_type in
    _enabled_run_types`) so an agentic HUNT now fuses under 'Velociraptor
    (Agentic)' and a non-agentic collection/import no longer does."""
    atype = run.get("automation_type")
    mods = set(normalize_modules(d.get("fusion_modules")))
    if atype in _VELOCIRAPTOR_TYPES:
        if "velociraptor_all" in mods:
            return True
        if "velociraptor_agentic" in mods or "velociraptor" in mods:
            return _is_agentic_run(run)
        return False
    allowed = set()
    for m in mods:
        if m in ("velociraptor_agentic", "velociraptor_all", "velociraptor"):
            continue
        allowed |= FUSION_MODULE_TYPES.get(m, set())
    return atype in allowed


# Per-entity char allowance used to scale the LLM char budget with the entity
# count, so a bigger 'LLM payload' setting isn't immediately clawed back by the
# distiller's char step-down. ~ REPORT_BUDGET_CHARS / REPORT_MAX_ENTITIES.
_LLM_CHARS_PER_ENTITY = 550
# Safety ceiling on the LLM payload so a large Entity limit can't overflow the
# model context — distilled() trims entities to fit this. ~100k tokens, which
# leaves headroom for output inside a 128k-context model (the common floor).
_LLM_MAX_BUDGET_CHARS = 400_000


def _llm_payload_budget(d):
    """LLM payload size, derived from the case's 'Entity limit' (max_entities) but
    BOUNDED to a context-safe size. The Entity limit can be huge (it sizes the
    stored graph you browse); the LLM only ever receives the top-N entities that
    fit ~_LLM_MAX_BUDGET_CHARS, so a 500k graph cap can't overflow the model
    context. For small graph caps the LLM payload tracks the limit 1:1; above the
    context-safe cap it plateaus. Returns (llm_max_entities, budget_chars)."""
    n = d.get("max_entities")
    try:
        n = int(n)
    except (TypeError, ValueError):
        n = DEFAULT_MAX_ENTITIES
    n = max(20, n)
    safe_cap = _LLM_MAX_BUDGET_CHARS // _LLM_CHARS_PER_ENTITY   # entities that fit the context
    return min(n, safe_cap), _LLM_MAX_BUDGET_CHARS


def _llm_output_cap(d):
    """The case 'Output token cap' — max tokens the model WRITES per LLM call
    (the pricey side of the bill). None = use the model/global default."""
    n = d.get("llm_max_output_tokens")
    try:
        n = int(n)
    except (TypeError, ValueError):
        return None
    return max(256, min(n, 64000)) if n else None


# Rescan-cost model: a rescan makes 2 LLM passes (report + advisory), each gets
# the distilled payload (~fusion_approx tokens) + a small system prompt, and
# writes up to the output cap. All approximate — for a pre-spend sanity number.
_RESCAN_LLM_CALLS = 2
_SYS_PROMPT_TOKENS = 3000
_DEFAULT_OUTPUT_TOKENS = 4000


def _configured_fusion_model():
    """(model, provider, fusion_mode) read from the agentic LLM config — the same
    keys call_llm uses. Returns (None, None, 'simulated') when nothing is set."""
    try:
        from services.storage.config_store import load_frontend_config
        ac = (load_frontend_config() or {}).get("agentic", {}) or {}
    except Exception:
        return None, None, "simulated"
    fusion_mode = str(ac.get("fusion_llm_mode", "simulated")).lower()
    if str(ac.get("llm_mode", "online")).lower() == "offline":
        off = ac.get("offline_llm", {}) or {}
        return off.get("model"), "ollama", fusion_mode
    on = ac.get("online_llm", {}) or {}
    model = on.get("custom_model") if on.get("model") == "custom" else on.get("model")
    return model, on.get("provider", "claude"), fusion_mode


def _model_max_output(model, provider):
    """The configured model's max output tokens (catalog/alias resolved). This is
    the DEFAULT output cap — i.e. let the model write up to its own ceiling unless
    the operator sets a smaller cap. Falls back to _DEFAULT_OUTPUT_TOKENS."""
    try:
        from services.agentic.analyzers._llm import get_model_max_output_tokens
        mx = get_model_max_output_tokens(model or "", provider or "claude")
        if mx:
            return int(mx)
    except Exception:
        pass
    return _DEFAULT_OUTPUT_TOKENS


def estimate_rescan_cost(d):
    """Estimate the USD cost of one Rescan (LLM), priced LIVE from the configured
    model's catalog pricing. Returns BOTH sides of the fusion ontology:

      - before: feeding the RAW rows to the LLM (token_ab.raw_approx)
      - after:  feeding the distilled fusion payload (token_ab.fusion_approx)

    so the operator sees the dollar saving the ontology buys (the $ twin of the
    'token cut'). In simulated mode it's the projected cost IF run live. All values
    0.0 when no model/pricing is resolvable."""
    try:
        from services.agentic.analyzers._llm import _estimate_llm_cost
    except Exception:
        return {}
    ab = d.get("token_ab") or {}
    raw_in = int(ab.get("raw_approx") or 0)
    fused_in = int(ab.get("fusion_approx") or 0)
    model, provider, mode = _configured_fusion_model()
    calls = _RESCAN_LLM_CALLS
    # Output defaults to the MODEL'S MAX (the operator can cap it lower).
    model_max_out = _model_max_output(model, provider)
    out_per_call = _llm_output_cap(d) or model_max_out
    out_tokens = out_per_call * calls

    def _side(in_one):
        in_tokens = (in_one + _SYS_PROMPT_TOKENS) * calls
        return {"input_tokens": in_tokens,
                "usd": round(_estimate_llm_cost(model or "", in_tokens, out_tokens), 4)}

    before, after = _side(raw_in), _side(fused_in)
    return {"model": model, "provider": provider, "mode": mode,
            "output_tokens": out_tokens,
            "model_max_output_tokens": model_max_out,   # UI uses this as the cap default
            "priced": before["usd"] > 0 or after["usd"] > 0,
            "before": before, "after": after,
            "per_rescan_usd": after["usd"],
            "savings_usd": round(before["usd"] - after["usd"], 2)}


def _env_key_from_members(members) -> str | None:
    """Stable environment identity = normalised primary hostname across member runs.
    Baselines are keyed by this so a clean snapshot subtracts from later cases on the
    same box/image."""
    ws = _ws()
    for rid in members or []:
        run = ws.get_automation_run(rid) or {}
        det = run.get("details") or {}
        hostnames = det.get("hostnames")
        host = None
        if isinstance(hostnames, dict) and hostnames:
            host = next(iter(hostnames.values()))
        elif isinstance(hostnames, list) and hostnames:
            host = hostnames[0]
        host = host or det.get("client_name")
        if host:
            return keys.norm_host(str(host))
    return None


def set_disposition(case_id, target, *, verdict="benign", attribution="it_admin",
                    reason="", scope="case", by="operator", watermark=None) -> dict:
    """Record an operator triage on a finding/entity ('that PsExec was IT'), re-fuse so it
    takes effect, and — when scope='environment' — fold it into the env baseline so it
    suppresses across FUTURE cases too. Returns the disposition.

    `watermark` (occurrence snapshot from the timeline) binds a benign verdict to the
    occurrences it covered: when the finding later shows new activity beyond it, the
    suppression is treated as stale and the finding re-opens (correlate._apply_dispositions).
    None = no watermark (e.g. chat entity dispositions), which stay broad as before."""
    ws = _ws()
    d = get_case(case_id)
    disp = {"target": target, "verdict": verdict, "attribution": attribution,
            "reason": reason, "scope": scope, "by": by}
    if watermark:
        disp["watermark"] = watermark
    existing = [x for x in (d.get("dispositions") or []) if x.get("target") != target]
    ws.update_run_status(case_id, "pending", details={"dispositions": existing + [disp]})
    log_case_event(case_id, "Risk · disposition applied", "info",
                   f"{target} → {verdict} ({attribution}, scope={scope}); re-fusing")
    if scope == "environment" and verdict == "benign":
        _promote_disposition_to_baseline(case_id, target)
    fuse_case(case_id)
    return disp


def clear_disposition(case_id, target) -> dict:
    """Reverse an operator triage on a target (un-suppress) and re-fuse so a
    finding marked not-real / known-IT comes back to its real severity. The
    counterpart to set_disposition — makes validation reversible."""
    ws = _ws()
    d = get_case(case_id)
    remaining = [x for x in (d.get("dispositions") or []) if x.get("target") != target]
    ws.update_run_status(case_id, "pending", details={"dispositions": remaining})
    log_case_event(case_id, "Risk · disposition cleared", "info", f"{target}; re-fusing")
    fuse_case(case_id)
    return {"target": target, "cleared": True}


def _promote_disposition_to_baseline(case_id, target) -> None:
    """Fold a dispositioned finding's SIGMA title into the environment baseline fingerprint
    so future cases on the same host subtract it (reuses the baseline mechanism)."""
    g = fuse_case(case_id, _record=False)
    titles = {f.title.split(" on ")[0] for f in g.findings
              if f.id == target or target in (f.entity_ids or [])}
    if not titles:
        return
    members = (get_case(case_id).get("member_run_ids") or [])
    env = _env_key_from_members(members)
    fp = load_baseline(env) or {"sigma_titles": [], "finding_titles": [], "service_paths": []}
    fp["finding_titles"] = sorted(set(fp.get("finding_titles") or []) | titles)
    fp["sigma_titles"] = sorted(set(fp.get("sigma_titles") or [])
                                | {t.replace("SIGMA: ", "") for t in titles})
    ws = _ws()
    rid = ws.create_automation_run(automation_type=BASELINE_TYPE,
                                   name=f"Baseline — {env}",
                                   details={"env_key": env, "source_case": case_id,
                                            "fingerprint": fp, "from_disposition": True})
    ws.update_run_status(rid, "completed", details={"env_key": env, "source_case": case_id,
                                                    "fingerprint": fp, "from_disposition": True})


def load_baseline(env_key) -> dict | None:
    """Most recent baseline fingerprint for an environment, or None."""
    if not env_key:
        return None
    ws = _ws()
    try:
        runs = [r for r in (ws.get_all_automation_runs() or [])
                if r.get("automation_type") == BASELINE_TYPE
                and (r.get("details") or {}).get("env_key") == env_key]
    except Exception:
        return None
    if not runs:
        return None
    runs.sort(key=lambda r: r.get("created_at") or r.get("updated_at") or "", reverse=True)
    return (runs[0].get("details") or {}).get("fingerprint")


def _raw_payload_size(run) -> int:
    """Approx tokens a NORMAL (non-fusion) LLM run would feed for this run — the
    raw module rows. Best-effort; used only for the fusion-vs-raw A/B headline."""
    det = run.get("details") or {}
    blob = (det.get("collected_data") or det.get("plugins") or det.get("events")
            or det.get("timeline_events") or det.get("findings") or det.get("sigma_findings"))
    if not blob and run.get("automation_type") in ("velociraptor_collection", "velociraptor_upload"):
        # Agentic / offline-import runs persist their rows to disk
        # (/data/downloads/<rid>/raw_results.json), not into details — read them
        # back so the raw-vs-fusion token A/B reflects the real input size.
        blob = _agentic_collected_data(run.get("run_id"), det) or None
    return budget.approx_tokens(blob) if blob else 0


def _ws():
    from services import workflow_service as ws
    return ws


def create_case(name, *, time_window=None, initial_access=None,
                min_severity="medium", member_run_ids=None, is_default=False,
                is_system=False) -> str:
    # The case row is itself a workflow row but is NEVER case-scoped — pass
    # case_id=None explicitly so the request's active case doesn't tag it.
    return _ws().create_automation_run(
        automation_type=CASE_TYPE, name=f"Case — {name}", case_id=None,
        details={"name": name, "time_window": time_window or {},
                 "initial_access_estimate": initial_access, "min_severity": min_severity,
                 "member_run_ids": list(member_run_ids or []),
                 "is_default": bool(is_default), "is_system": bool(is_system),
                 "fusion_graph": {}, "report_md": "", "chat_messages": []})


def get_case(case_id) -> dict:
    return (_ws().get_automation_run(case_id) or {}).get("details") or {}


def _members_for_case(case_id, d=None) -> list:
    """A case's members = every analysis run TAGGED to it (the workspace model),
    unioned with any legacy explicit member_run_ids for back-compat."""
    ws = _ws()
    tagged = [r.get("run_id") for r in ws.get_automation_runs_by_case(case_id)
              if r.get("automation_type") in ws.AGENTIC_TYPES]
    if d is None:
        d = get_case(case_id)
    seen = set(tagged)
    legacy = [r for r in (d.get("member_run_ids") or []) if r not in seen]
    return tagged + legacy


def attach_runs(case_id, run_ids) -> list:
    """Legacy explicit attach (kept for back-compat / the API). In the workspace
    model runs auto-belong via their case_id tag; this also stamps the tag so a
    manually-attached run shows up under the case everywhere."""
    from services.file_storage_service import get_workflow
    d = get_case(case_id)
    members = list(dict.fromkeys((d.get("member_run_ids") or []) + list(run_ids)))
    _ws().update_run_status(case_id, "pending", details={"member_run_ids": members})
    for rid in run_ids:                       # tag the run into this workspace too
        run = get_workflow(rid)
        if run and not run.get("case_id"):
            run["case_id"] = case_id
            from services.file_storage_service import save_workflow
            save_workflow(run)
    return members


EXPORT_KIND = "intact_case_export"
EXPORT_SCHEMA = 1


def export_case(case_id) -> dict | None:
    """Build a self-contained, importable bundle for one case (workspace):
    the case record (its details cache the fused graph + report + config +
    dispositions) plus every member run's full record (the fusion inputs). A
    later import recreates the case verbatim and can re-fuse from the runs."""
    ws = _ws()
    case_run = ws.get_automation_run(case_id)
    if not case_run or case_run.get("automation_type") != CASE_TYPE:
        return None
    member_ids = _members_for_case(case_id)
    runs = [r for r in (ws.get_automation_run(rid) for rid in member_ids) if r]
    det = dict(case_run.get("details") or {})
    # The graph now lives in a sidecar — embed it back inline so the bundle stays
    # self-contained (import reads it inline; a later re-fuse moves it to a sidecar).
    fg = _read_graph_sidecar(case_id)
    if fg is not None:
        det["fusion_graph"] = fg
        case_run = {**case_run, "details": det}
    return {
        "kind": EXPORT_KIND,
        "schema": EXPORT_SCHEMA,
        "name": det.get("name") or case_run.get("name") or "case",
        "case": case_run,
        "runs": runs,
    }


def import_case(bundle: dict, *, name: str | None = None) -> dict:
    """Recreate a case from an export bundle. Creates a FRESH case container and
    re-tags the bundled member runs into it (run ids are preserved so the cached
    graph/findings, which reference run ids, stay consistent — intended for
    moving a case to another install). Returns {case_id, name, runs_imported}."""
    if not isinstance(bundle, dict) or bundle.get("kind") != EXPORT_KIND:
        raise ValueError("not an Intact case export bundle")
    src_case = bundle.get("case") or {}
    src_runs = bundle.get("runs") or []
    src_det = src_case.get("details") or {}
    disp_name = (name or src_det.get("name") or src_case.get("name") or "Imported case").strip()

    ws = _ws()
    from services.file_storage_service import save_workflow

    # Fresh case container (never inherits default/system status from the source).
    new_case_id = ws.create_automation_run(
        automation_type=CASE_TYPE, name=f"Case — {disp_name}", case_id=None, details={},
    )

    # Upsert each member run, preserving its id + payload, re-tagged to the new case.
    member_ids = []
    for r in src_runs:
        rid = (r or {}).get("run_id")
        if not rid:
            continue
        rec = dict(r)
        rec["case_id"] = new_case_id
        save_workflow(rec)
        member_ids.append(rid)

    # New case details = the source case's cached state, re-pointed + de-privileged.
    new_det = dict(src_det)
    new_det["name"] = disp_name
    new_det["member_run_ids"] = member_ids
    new_det.pop("is_default", None)
    new_det.pop("is_system", None)
    ws.update_run_status(new_case_id, src_case.get("status") or "completed", details=new_det)

    return {"case_id": new_case_id, "name": disp_name, "runs_imported": len(member_ids)}


def ensure_default_case() -> str:
    """Return the id of the Default workspace, creating it if missing. Idempotent —
    safe to call on every startup."""
    ws = _ws()
    for r in ws.get_all_automation_runs() or []:
        if r.get("automation_type") != CASE_TYPE:
            continue
        det = r.get("details") or {}
        if det.get("is_default") or det.get("name") == DEFAULT_CASE_NAME:
            return r.get("run_id")
    return create_case(DEFAULT_CASE_NAME, is_default=True)


def ensure_system_case() -> str:
    """Return the id of the System workspace (where Settings-page/system runs live),
    creating it if missing. Idempotent — safe to call on every startup."""
    ws = _ws()
    for r in ws.get_all_automation_runs() or []:
        if r.get("automation_type") != CASE_TYPE:
            continue
        det = r.get("details") or {}
        if det.get("is_system") or det.get("name") == SYSTEM_CASE_NAME:
            return r.get("run_id")
    return create_case(SYSTEM_CASE_NAME, is_system=True)


def is_default_case(case_id) -> bool:
    d = get_case(case_id)
    return bool(d.get("is_default") or d.get("name") == DEFAULT_CASE_NAME)


def is_system_case(case_id) -> bool:
    d = get_case(case_id)
    return bool(d.get("is_system") or d.get("name") == SYSTEM_CASE_NAME)


def delete_case(case_id) -> dict:
    """Delete a workspace and EVERYTHING in it: every tagged run, the baseline this
    case captured, and the case row. Refuses to delete the Default/System workspaces."""
    from services.file_storage_service import delete_workflow
    ws = _ws()
    d = get_case(case_id)
    if not d:
        return {"deleted": False, "error": "not found"}
    if d.get("is_default") or d.get("name") == DEFAULT_CASE_NAME:
        return {"deleted": False, "error": "default workspace cannot be deleted"}
    if d.get("is_system") or d.get("name") == SYSTEM_CASE_NAME:
        return {"deleted": False, "error": "system workspace cannot be deleted"}
    run_ids = [r.get("run_id") for r in ws.get_automation_runs_by_case(case_id)]
    for rid in run_ids:
        delete_workflow(rid)
    # baselines this case captured (match by source_case only — never touch a
    # baseline another workspace may rely on)
    removed_baselines = 0
    for r in ws.get_all_automation_runs() or []:
        if r.get("automation_type") != BASELINE_TYPE:
            continue
        if (r.get("details") or {}).get("source_case") == case_id:
            delete_workflow(r.get("run_id"))
            removed_baselines += 1
    delete_workflow(case_id)
    _delete_graph_sidecar(case_id)   # remove the fused-graph sidecar file too
    return {"deleted": True, "runs_deleted": len(run_ids),
            "baselines_deleted": removed_baselines}


def _memory_contribution(rid, det):
    asset = keys.asset_id(det.get("client_id") or rid)
    host = det.get("client_name")
    from services.memory.volweb_client import VolWebClient
    from services.memory.analyzers import _build_plugin_payload, _build_yara_payload
    client = VolWebClient()
    evid = det.get("evidence_id")
    plugins, _w = _build_plugin_payload(client, evid)
    try:                                  # yara is optional — never lose plugins over it
        hits, _t = _build_yara_payload(client, evid)
    except Exception:
        hits = []
    return map_memory({"plugins": plugins, "yara": hits, "host": host},
                      run_id=rid, asset=asset, hostname=host)


def _cve_contribution(rid, det):
    import json
    import os
    for base in (f"/app/data/downloads/{rid}", f"/data/downloads/{rid}",
                 det.get("output_dir") or ""):
        fp = os.path.join(base, "findings.json") if base else ""
        if fp and os.path.exists(fp):
            with open(fp) as f:
                return map_cve(json.load(f), run_id=rid)
    return [], []


def _agentic_collected_data(rid, det):
    """The real agentic pipeline persists rows to /data/downloads/<rid>/raw_results.json
    (not into details, to avoid bloating the SQLite blob). Prefer details.collected_data
    (test/legacy runs), else read the file. This is what makes a REAL agentic run fuseable."""
    cd = det.get("collected_data")
    if cd:
        return cd
    import json
    import os
    for base in (f"/app/data/downloads/{rid}", f"/data/downloads/{rid}",
                 det.get("output_dir") or ""):
        fp = os.path.join(base, "raw_results.json") if base else ""
        if fp and os.path.exists(fp):
            try:
                with open(fp) as f:
                    return json.load(f)
            except Exception:
                return {}
    return {}


def _relabel_source(ents, rels, frm, to):
    """Rewrite a module/source label on a contribution in place. Used so an
    offline-collector import (mapped by map_agentic for code reuse) is attributed
    to "velociraptor", not "agentic" — no agent ran, it's imported artifacts."""
    def fix(seq):
        if seq:
            for i, s in enumerate(seq):
                if s == frm:
                    seq[i] = to
    for e in ents or []:
        fix(getattr(e, "sources", None))
        for ev in (getattr(e, "evidence", None) or []):
            if getattr(ev, "module", None) == frm:
                ev.module = to
    for r in rels or []:
        fix(getattr(r, "sources", None))


def _velo_hunt_contribution(rid, det, log=None):
    """A live Velociraptor HUNT (velociraptor_hunt run). The run stores its hunt_id;
    pull the hunt's rows across every reporting client, persist them once (so the
    token A/B + later views are stable + fast), map via the shared mapper, and label
    the source 'velociraptor' (no agent ran). Empty if the hunt has no rows yet —
    rescan after clients report."""
    hunt_id = det.get("hunt_id")
    if not hunt_id:
        if log:
            log(f"hunt run {rid} has no hunt_id — cannot fuse", "warning")
        return [], []
    # ALWAYS pull live so an in-flight hunt shows its current partial data and each
    # rescan picks up whatever has arrived since — no need to wait for the hunt to
    # finish. A snapshot is persisted only as a fallback for when Velociraptor is
    # unreachable.
    cd = {}
    try:
        from services.agentic.collectors import get_existing_collection_results
        from services.agentic.reports import persist_pipeline_artifacts
        cd, _arts, client_info = get_existing_collection_results(
            rid, flow_id=None, hunt_id=hunt_id, client_ids=None)
        if cd:
            try:
                persist_pipeline_artifacts(rid, {}, cd)      # fallback snapshot
            except Exception:
                pass
            hostnames = {str(c): (i or {}).get("hostname")
                         for c, i in (client_info or {}).items() if c and (i or {}).get("hostname")}
            if hostnames:
                det["hostnames"] = hostnames
    except Exception as e:
        if log:
            log(f"hunt {hunt_id}: live pull failed ({e}); using last snapshot", "warning")
    if not cd:                                            # Velociraptor down -> last snapshot
        cd = _agentic_collected_data(rid, det)
    if not cd:
        return [], []
    ents, rels = map_agentic(cd, run_id=rid, hostnames=det.get("hostnames") or {})
    _relabel_source(ents, rels, "agentic", "velociraptor")
    return ents, rels


def _distill_ts_events(events, *, per_tag=5):
    """Collapse a large tagged-event pull into a small, representative set: keep up
    to `per_tag` highest-anomaly events per distinct tag (one tag = one analyzer /
    SIGMA detection class). A KAPE timeline routinely has thousands of 'logon-event'
    rows that would flood the 2500-entity graph and bury the real signal; this keeps
    every distinct detection (e.g. 'rare-domain') while capping the noisy classes."""
    from .anomaly import score_row
    buckets = {}
    for e in events or []:
        if not isinstance(e, dict):
            continue
        tags = e.get("tag") or ["_untagged"]
        if not isinstance(tags, list):
            tags = [tags]
        try:
            sc = score_row(e)
        except Exception:
            sc = 0
        for t in tags:
            buckets.setdefault(str(t), []).append((sc, e))
    out, seen = [], set()
    for rows in buckets.values():
        rows.sort(key=lambda x: x[0], reverse=True)
        for _sc, e in rows[:per_tag]:
            if id(e) not in seen:
                seen.add(id(e))
                out.append(e)
    return out


def _contribution_for_run(run, log=None):
    atype, rid = run.get("automation_type"), run.get("run_id")
    det = run.get("details") or {}
    try:
        if atype == "memory":
            return _memory_contribution(rid, det)
        # "velociraptor_collection" = a live/collect Velociraptor run; "velociraptor_upload" = an
        # offline-collector import fused into its own upload row (one workflow
        # row, not two). Both persist rows the same way and fuse via the same
        # mapper — but the offline import ran NO agent, so relabel its source
        # "agentic" -> "velociraptor" (the data is just imported Velociraptor
        # artifacts) so the report doesn't read as if an agent had run.
        if atype in ("velociraptor_collection", "velociraptor_upload"):
            ents, rels = map_agentic(_agentic_collected_data(rid, det), run_id=rid,
                                     hostnames=det.get("hostnames") or {})
            if atype == "velociraptor_upload":
                _relabel_source(ents, rels, "agentic", "velociraptor")
            return ents, rels
        if atype == "velociraptor_hunt":
            return _velo_hunt_contribution(rid, det, log=log)
        if atype == "cve_scan":
            return _cve_contribution(rid, det)
        if atype == "timesketch":
            evs = det.get("events") or det.get("timeline_events")
            fetched = False
            if not evs and (det.get("sketch_id") or det.get("sketch_name")):
                # TimeSketch keeps the timeline on its server (the sketch), not in
                # the run row — pull the analyst-relevant subset (tagged SIGMA /
                # analyzer hits + starred) so it actually contributes to the case.
                # The run often stores only sketch_name (sketch_id is None), so
                # resolve the id by name. Best-effort: [] if TS is unreachable, so
                # the fuse never blocks on TimeSketch.
                try:
                    from services.timesketch_service import (
                        fetch_sketch_events, find_sketch_by_name)
                    from config import TIMESKETCH_CONFIG
                    sid = det.get("sketch_id")
                    if not sid and det.get("sketch_name"):
                        sid = find_sketch_by_name(det["sketch_name"], TIMESKETCH_CONFIG, logger=log)
                    if sid:
                        evs = fetch_sketch_events(sid, TIMESKETCH_CONFIG, logger=log)
                        fetched = True
                except Exception as _e:
                    if log:
                        log(f"fuse: timesketch fetch for {rid} skipped: {_e}", "warning")
                    evs = None
            if evs:
                evs = _distill_ts_events(evs, per_tag=5)
                if fetched:
                    # Cache the distilled set on the run so later fuses (dispositions,
                    # timeline validations) don't re-hit TimeSketch every time. A
                    # fresh Refusion after new analyzer tags re-imports the timeline.
                    try:
                        _ws().update_run_status(rid, run.get("status") or "completed",
                                                details={"timeline_events": evs})
                    except Exception:
                        pass
                # Resolve the REAL host so timesketch merges with its velociraptor/
                # memory node instead of spawning a synthetic run-keyed host. The
                # run stores the client under details.clients[]/hostnames, not the
                # top-level client_name/client_id. (Multi-client runs attach to the
                # first host — per-host splitting is a later refinement.)
                client_id = det.get("client_id")
                hostname = det.get("client_name")
                cl = det.get("clients")
                if isinstance(cl, list) and cl and isinstance(cl[0], dict):
                    client_id = client_id or cl[0].get("client_id")
                    hostname = hostname or cl[0].get("client_name")
                if not hostname:
                    hns = det.get("hostnames")
                    if isinstance(hns, list) and hns:
                        hostname = hns[0]
                    elif isinstance(hns, dict) and hns:
                        hostname = next(iter(hns.values()), None)
                asset = keys.asset_id(client_id or hostname or rid)
                return map_timesketch(evs, run_id=rid, asset=asset, hostname=hostname)
        if atype in ("aws_scan", "azure_scan"):
            prov = "aws" if atype == "aws_scan" else "azure"
            finds = det.get("findings") or det.get("sigma_findings")
            if not finds:
                fb = det.get("findings_by_severity")
                if isinstance(fb, dict):
                    finds = [x for v in fb.values() for x in (v or [])]
            if finds:
                return map_cloud(finds, run_id=rid, provider=prov,
                                 account=det.get("account") or det.get("account_id")
                                 or det.get("tenant_id"))
    except Exception as e:  # never let one run break the fuse
        if log:
            log(f"fuse: run {rid} ({atype}) skipped: {e}", "warning")
    return [], []


def fuse_case(case_id, *, contributions_override=None, log=None, _record=True) -> FusionGraph:
    ws = _ws()
    d = get_case(case_id)

    def _plog(msg, status="info", detail=""):   # progress -> case log (recorded fuses only)
        if _record:
            log_case_event(case_id, msg, status, detail)

    members = _members_for_case(case_id, d)
    # include/exclude: scope the fusion to a chosen subset of the case's runs (None = all)
    inc = d.get("included_run_ids")
    if inc is not None:
        members = [m for m in members if m in set(inc)]
    if contributions_override is not None:
        contributions = contributions_override
    else:
        # Module gating: only fuse runs whose module is enabled for this case
        # (default = velociraptor only). Disabled modules' runs stay tagged
        # members but contribute nothing to the graph. Drop the filtered runs
        # from `members` too so run_ids/baseline reflect what was actually fused.
        _plog("Refusion · reading + mapping run data", "info",
              f"{len(members)} member run(s)")
        contributions, kept = [], []
        for rid in members:
            run = ws.get_automation_run(rid)
            if not run:
                continue
            if not _run_passes_gate(run, d):
                continue
            kept.append(rid)
            contributions.append(_contribution_for_run(run, log=log))
        members = kept
    window = d.get("time_window") or None
    min_sev = d.get("min_severity", "informational")
    _plog("Refusion · building case graph", "info",
          f"window {(window or {}).get('start') or 'open'}…{(window or {}).get('end') or 'now'}, "
          f"severity {min_sev}+ · {len(contributions)} contributing run(s)")
    # subtract the environment baseline (if one was captured) so provisioning /
    # automation noise doesn't read as attack signal.
    baseline = None if d.get("is_baseline") else load_baseline(_env_key_from_members(members))
    g = correlate.assemble(case_id, contributions, members, baseline=baseline, window=window,
                           min_severity=min_sev, dispositions=d.get("dispositions") or None)
    _plog("Refusion · graph built", "info",
          f"{len(g.entities):,} entities, {len(g.relationships):,} links, "
          f"{len(g.findings):,} findings")
    if not _record:
        return g
    # cross-case KB: enrich with prior sightings, then index this case (best-effort,
    # degrades silently when ES is down — never a dependency).
    try:
        from . import kb
        kb.enrich(g, current_case_id=case_id)
        kb.index_case_entities(case_id, g)
    except Exception:
        pass
    # masking (customer-facing): anonymize host/user/ip in the report + LLM payload
    mask = None
    mk = d.get("masking") or {}
    if mk.get("enabled"):
        try:
            from services.data_anonymizer import DataAnonymizer
            mask = DataAnonymizer(custom_patterns=mk.get("patterns") or [])
        except Exception:
            mask = None
    # host-exclusion: cut excluded hosts' data from the report/LLM (token saving). The
    # FULL graph `g` is still stored so the picker can list/re-include every host.
    gv = _filter_graph_by_hosts(g, d.get("excluded_hosts"))
    # The report + advisory are the heavy narrative. Generate them ONLY on the FIRST
    # fuse (no report yet); afterwards they stay FROZEN until the operator clicks
    # Rescan (store.regenerate_report). This keeps the per-action re-fuses (timeline
    # validations, dispositions) fast + token-free, and matches the product rule
    # "first scan generates it; afterwards only on rescan".
    if d.get("report_md"):
        report = d.get("report_md")
        analysis = d.get("analysis") or {}
        # Report reused verbatim → it still reflects whatever members it was last
        # written from, NOT the (possibly newer) graph members. Tracking this
        # separately from fused_run_ids lets the deterministic graph auto-refresh
        # on every load while the UI can still tell the operator the narrative is
        # behind ("Save & rescan to refresh the report").
        report_members = d.get("report_run_ids")
        if report_members is None:
            report_members = d.get("fused_run_ids")  # legacy graphs: best-effort
        # Report left frozen while the graph was rebuilt (a triage/disposition
        # re-fuse) → it may now be behind. Surface a "report not up to date" hint.
        report_dirty = True
    else:
        llm_ent, llm_chars = _llm_payload_budget(d)
        llm_out = _llm_output_cap(d)
        report = llm_sim.generate_report(
            gv, window=window, min_severity=min_sev,
            initial_access=d.get("initial_access_estimate"),
            case_name=d.get("name", "Case"), run_id=case_id,
            audience=d.get("audience", "both"), language=d.get("language", "en"),
            master_prompt=d.get("master_prompt"), mask=mask,
            dispositions=d.get("dispositions") or None,
            validations=d.get("timeline_validations") or None,
            prefer_llm=False,   # first scan = fast, free, deterministic; LLM on Rescan
            max_entities=llm_ent, budget_chars=llm_chars, max_output_tokens=llm_out)
        # ADVISORY analyst pass — incident-grouping + grounded hypotheses. Stored
        # SEPARATELY from the deterministic findings; fed prior operator dispositions.
        analysis = llm_sim.analyze(gv, window=window, min_severity=min_sev, run_id=case_id,
                                   dispositions=d.get("dispositions") or None,
                                   max_entities=llm_ent, budget_chars=llm_chars,
                                   max_output_tokens=llm_out)
        report_members = list(members)   # report now reflects exactly these members
        report_dirty = False             # report freshly generated → up to date
    # customer-confirmation checklist — generate once (preserve operator decisions on re-fuse)
    checklist = d.get("disposition_checklist")
    if not checklist:
        try:
            checklist = llm_sim.generate_disposition_checklist(
                gv, window=window, min_severity=min_sev, run_id=case_id)
        except Exception:
            checklist = []

    # Token A/B: raw rows a normal run would feed vs the distilled payload the LLM
    # actually sees. raw_approx is necessarily an estimate (we never send raw), so
    # it's labelled _approx; real model tokens land on llm_metrics via call_llm.
    try:
        raw_approx = 0
        for rid in members:
            run = ws.get_automation_run(rid)
            if run:
                raw_approx += _raw_payload_size(run)
        _le, _lc = _llm_payload_budget(d)
        distilled = render.distilled(g, window=window, min_severity=min_sev,
                                     max_entities=_le, budget_chars=_lc)
        fusion_approx = budget.approx_tokens(json.dumps(distilled))
        token_ab = {"raw_approx": raw_approx, "fusion_approx": fusion_approx,
                    "reduction_ratio": round(raw_approx / max(fusion_approx, 1), 1)}
    except Exception:
        token_ab = {}

    # Persist the graph to its sidecar (NOT inline in the case row) + precompute the
    # stat-bar counts, so metadata/report/config/log reads never deserialize the
    # graph. `fusion_graph: {}` clears any legacy inline graph from older fuses.
    pruned = g.pruned(max_entities=int(d.get("max_entities")
                                       or DEFAULT_MAX_ENTITIES)).to_dict()
    _plog("Refusion · writing graph to database", "info",
          f"{len(pruned.get('entities') or {}):,} entities → sidecar")
    if not _write_graph_sidecar(case_id, pruned):
        _plog("Refusion · graph write", "error", "sidecar write failed (see backend log)")
    ws.update_run_status(case_id, "completed",
                         details={"fusion_graph": {},
                                  "graph_counts": _counts_from_graph_dict(pruned),
                                  "report_md": report,
                                  "token_ab": token_ab, "analysis": analysis,
                                  # Record exactly which member runs this graph was
                                  # built from, so the UI can detect when new runs
                                  # have landed since (stale_member_runs) and show a
                                  # "rescan suggested" hint without re-fusing on load.
                                  "fused_run_ids": list(members),
                                  # members the LLM report/chat narrative reflects
                                  # (updated only when the report is rebuilt, not on
                                  # a plain graph re-fuse) — drives the "rescan to
                                  # refresh the report" hint.
                                  "report_run_ids": report_members,
                                  # True when this fuse left the report frozen (triage/
                                  # disposition re-fuse) → UI shows "report not up to date".
                                  "report_dirty": report_dirty,
                                  "disposition_checklist": checklist})
    log_case_event(case_id, "Refusion complete", "success",
                   f"saved to database — {len(g.entities):,} entities, "
                   f"{len(g.relationships):,} links, {len(g.findings):,} findings "
                   f"across {len(members)} run(s)")
    return g


def stale_member_runs(case_id, d=None) -> list:
    """Completed member runs NOT reflected in the persisted graph — i.e. data
    added since the last fuse. Returns their run_ids (empty when the graph is
    current, or when it predates `fused_run_ids` tracking, so we never cry
    'stale' on a legacy graph). Cheap: no graph build, just a member scan."""
    d = d or get_case(case_id) or {}
    fused = d.get("fused_run_ids")
    if fused is None:
        return []
    fused = set(fused)
    # Only runs whose MODULE is enabled count as "new data to fold in" — a disabled
    # module's runs can never enter the graph via Refusion, so flagging them as
    # stale is misleading (the banner would prompt a Refusion that does nothing).
    ws = _ws()
    out = []
    for r in ws.get_automation_runs_by_case(case_id):
        if (_run_passes_gate(r, d)
                and r.get("status") in ("completed", "success")
                and r.get("run_id") not in fused):
            out.append(r.get("run_id"))
    return out


def report_stale_runs(case_id, d=None) -> list:
    """Completed member runs the LLM report/chat narrative does NOT yet reflect —
    i.e. data present in the (always-current) graph but added since the report was
    last written. Returns their run_ids. Empty when the report is current, or for
    legacy cases that predate report_run_ids tracking. This is what the UI keys
    its 'Save & rescan to refresh the report' hint off — the deterministic graph
    (hosts/entities/links/findings/risk/timeline) auto-refreshes on load, so data
    is never stale; only the narrative can lag."""
    d = d or get_case(case_id) or {}
    rep = d.get("report_run_ids")
    if rep is None:
        return []
    rep = set(rep)
    ws = _ws()
    out = []
    for r in ws.get_automation_runs_by_case(case_id):
        if (_run_passes_gate(r, d)   # only enabled-module runs can reach the report
                and r.get("status") in ("completed", "success")
                and r.get("run_id") not in rep):
            out.append(r.get("run_id"))
    return out


def watch_and_fuse(case_id, run_id, *, poll=10, timeout=10800) -> None:
    """Background: wait until a member run reaches a terminal state, then
    re-fuse the whole case. Makes a Case a living workspace — attach an
    in-flight run and the graph/report refresh themselves when it lands."""
    import time
    ws = _ws()
    start = time.time()
    while time.time() - start < timeout:
        r = ws.get_automation_run(run_id) or {}
        if (r.get("status") or "") in ("completed", "failed", "cancelled"):
            break
        time.sleep(poll)
    try:
        fuse_case(case_id)
    except Exception:
        pass


# ── Fusion-graph sidecar storage ─────────────────────────────────────────────
# The fused graph is large (10s–100s of MB). Storing it inline in the case's
# workflow-row `details` meant get_case() deserialised the whole graph on EVERY
# metadata/report/config/log call (8–18 s per call once big). The Case Analysis
# UI never needs the raw node-link graph — it consumes derived views (report,
# timeline, risk, chat, log, config, macro counts), all small. So the graph lives
# in a per-case sidecar file, loaded ONLY when a view actually needs it
# (risk/timeline/chat/rescan/export), and the case row carries just precomputed
# `graph_counts`. Legacy cases (graph still inline) keep working via fallback.
_FUSION_GRAPH_DIR = "/app/data/fusion_graphs"


def _graph_path(case_id):
    return os.path.join(_FUSION_GRAPH_DIR, f"{case_id}.json")


def _write_graph_sidecar(case_id, graph_dict) -> bool:
    try:
        os.makedirs(_FUSION_GRAPH_DIR, exist_ok=True)
        tmp = _graph_path(case_id) + ".tmp"
        with open(tmp, "w") as f:
            json.dump(graph_dict, f, default=str)
        os.replace(tmp, _graph_path(case_id))   # atomic
        return True
    except Exception as e:
        print(f"[FUSION] sidecar write failed for {case_id}: {e}", flush=True)
        return False


def _read_graph_sidecar(case_id):
    try:
        with open(_graph_path(case_id)) as f:
            return json.load(f)
    except FileNotFoundError:
        return None
    except Exception as e:
        print(f"[FUSION] sidecar read failed for {case_id}: {e}", flush=True)
        return None


def _delete_graph_sidecar(case_id) -> None:
    try:
        os.remove(_graph_path(case_id))
    except FileNotFoundError:
        pass
    except Exception:
        pass


def _counts_from_graph_dict(fg) -> dict:
    ents = fg.get("entities") or {}
    findings = fg.get("findings") or []
    return {"hosts": sum(1 for e in ents.values() if (e or {}).get("type") == "asset"),
            "entities": len(ents),
            "links": len(fg.get("relationships") or []),
            "findings": len(findings),
            "cross_host": sum(1 for f in findings if (f or {}).get("kind") == "cross_host")}


def load_graph(case_id) -> FusionGraph:
    fg = _read_graph_sidecar(case_id)
    if fg is None:   # legacy / imported cases stored the graph inline in details
        fg = (get_case(case_id) or {}).get("fusion_graph") or {"case_id": case_id}
    return FusionGraph.from_dict(fg)


def _filter_graph_by_hosts(g, excluded_labels) -> FusionGraph:
    """Return a view of the graph with the named hosts excluded — their asset nodes,
    the entities/findings that live ONLY on them, and now-dangling relationships are
    dropped. Cuts excluded-host data from the report/LLM (token saving) while the stored
    graph keeps every host for the picker. No-op when nothing is excluded."""
    excluded = {keys.norm_host(h) for h in (excluded_labels or []) if h}
    if not excluded:
        return g
    ex_assets = set()
    for a in g.by_type("asset"):
        if keys.norm_host(a.attrs.get("hostname") or "") in excluded \
                or keys.norm_host(a.label or "") in excluded:
            ex_assets.add(a.id)
    if not ex_assets:
        return g
    gv = FusionGraph(case_id=g.case_id, run_ids=list(g.run_ids))
    keep = set()
    for e in g.entities.values():
        if e.id in ex_assets:
            continue
        al = e.attrs.get("_assets")
        if al and set(al) <= ex_assets:        # belongs only to excluded hosts
            continue
        gv.entities[e.id] = e
        keep.add(e.id)
    for f in g.findings:
        aid = set(f.asset_ids or [])
        if aid and aid <= ex_assets:           # finding only on excluded hosts
            continue
        gv.findings.append(f)
    for r in g.relationships:
        if r.src in keep and r.dst in keep:
            gv.relationships.append(r)
    gv.rebuild_indexes()
    return gv


def _merge_case_details(case_id, patch) -> None:
    """Merge a patch into the case details without disturbing its status."""
    ws = _ws()
    cur = (ws.get_automation_run(case_id) or {}).get("status") or "completed"
    ws.update_run_status(case_id, cur, details=patch)


def _now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")


# ---- Case Analysis activity log (audit trail — the case has no workflow row) ----
_CASE_LOG_CAP = 500


def log_case_event(case_id, action, status="ok", detail="", **meta) -> None:
    """Append an entry to the case's activity log. Best-effort + bounded: logging
    must NEVER raise into (or break) the action it records. Captures both the
    action and its outcome (ok/error) so the Log tab can follow everything that
    happens inside Case Analysis."""
    try:
        if not get_case(case_id):
            return                       # not a real case (e.g. 'quick', calibration ids)
        lvl = str(status or "ok").lower()
        if lvl not in ("info", "ok", "success", "warning", "error"):
            lvl = "ok"
        entry = {"ts": _now_iso() + "Z", "action": str(action)[:120],
                 "status": lvl, "detail": str(detail)[:500]}
        for k, v in (meta or {}).items():
            entry[k] = v

        def _append(details):            # atomic read-append-write under the run lock
            log = list(details.get("activity_log") or [])
            log.append(entry)
            details["activity_log"] = log[-_CASE_LOG_CAP:] if len(log) > _CASE_LOG_CAP else log

        _ws().mutate_run_details(case_id, _append)
    except Exception as e:  # noqa: BLE001 — telemetry only
        print(f"[CASE-LOG] failed to record '{action}' for {case_id}: {e}", flush=True)


def graph_counts(case_id) -> dict:
    """Lightweight stat-bar counts — read from the PRECOMPUTED `graph_counts`
    stored on the case row at fuse time, so this never deserializes the graph.
    Falls back to a legacy inline graph / the sidecar for cases fused before
    counts were precomputed."""
    d = get_case(case_id) or {}
    gc = d.get("graph_counts")
    if gc:
        return gc
    fg = d.get("fusion_graph") or _read_graph_sidecar(case_id) or {}
    ents = fg.get("entities") or {}
    findings = fg.get("findings") or []
    return {"hosts": sum(1 for e in ents.values() if (e or {}).get("type") == "asset"),
            "entities": len(ents),
            "links": len(fg.get("relationships") or []),
            "findings": len(findings),
            "cross_host": sum(1 for f in findings if (f or {}).get("kind") == "cross_host")}


def get_case_log(case_id) -> list:
    return list((get_case(case_id) or {}).get("activity_log") or [])


def clear_case_log(case_id) -> dict:
    _merge_case_details(case_id, {"activity_log": []})
    return {"cleared": True}


# ---- engagement-grade reporting on the case (branding + audience + steering) ----

_CASE_SYNTH_SYSTEM = (
    "You are condensing a DFIR analyst's chat about an incident case into a short "
    "briefing that the next report regeneration will read verbatim as ground truth. "
    "Write flowing prose — a few short paragraphs, no bullets, no headings, no IDs. "
    "Capture: which activity turned out to be legitimate/benign and why, what the "
    "operator wants removed or de-emphasised, what to focus on, and environment "
    "context that should colour the next pass (host ownership, what's normal here)."
)


def set_branding(case_id, *, customer_name=None, customer_logo_b64=None, tlp=None,
                 audience=None, language=None) -> dict:
    """Persist report branding/options on the case (logo, customer, TLP, audience)."""
    patch = {}
    for k, v in (("customer_name", customer_name), ("customer_logo_b64", customer_logo_b64),
                 ("tlp", tlp), ("audience", audience), ("language", language)):
        if v is not None:
            patch[k] = v
    if patch:
        _merge_case_details(case_id, patch)
    return {k: ("<logo>" if k == "customer_logo_b64" else v) for k, v in patch.items()}


def set_master_prompt(case_id, text) -> None:
    """Hand-set the operator steering brief (works without an LLM)."""
    _merge_case_details(case_id, {"master_prompt": (text or "").strip()})


def synthesize_master_prompt(case_id) -> str:
    """Compress the case chat into a master-prompt brief (needs a real LLM). Stores +
    returns it. Raises on no-chat / LLM failure (route surfaces the error)."""
    d = get_case(case_id)
    msgs = d.get("chat_messages") or []
    if not msgs:
        raise ValueError("no chat history to synthesise — chat about the case first")
    from services.agentic.analyzers import call_llm
    from services.memory.pipeline import _llm_config_from_runtime
    transcript = json.dumps(msgs, indent=2, default=str)
    user = (f"Chat transcript:\n```json\n{transcript[:80000]}\n```\n\n"
            "Write the briefing as described — flowing prose, no bullets/headings.")
    master = call_llm(user, _CASE_SYNTH_SYSTEM, _llm_config_from_runtime(), run_id=case_id)
    master = (master or "").strip()
    if not master:
        raise RuntimeError("synthesis returned empty")
    _merge_case_details(case_id, {"master_prompt": master})
    return master


def regenerate_report(case_id, *, audience=None, use_llm=False) -> dict:
    """Re-narrate report + advisory from the STORED graph (no re-collect/re-fuse),
    applying the case's audience + master_prompt + Timeline triage. Deterministic by
    default (free); pass use_llm=True (the 'Regenerate report' button) for the premium
    LLM narrative — the only place report generation spends tokens."""
    if audience:
        set_branding(case_id, audience=audience)
    d = get_case(case_id)
    g = load_graph(case_id)
    window = d.get("time_window") or None
    min_sev = d.get("min_severity", "informational")
    gv = _filter_graph_by_hosts(g, d.get("excluded_hosts"))
    llm_ent, llm_chars = _llm_payload_budget(d)
    llm_out = _llm_output_cap(d)
    model, provider, mode = _configured_fusion_model()
    if use_llm:
        if model:
            log_case_event(case_id, "Report · sending request to the LLM", "info",
                           f"model {model} ({provider}); payload ≤{llm_ent:,} entities, "
                           f"output ≤{llm_out or 'model max'} tokens")
        else:
            log_case_event(case_id, "Report · LLM not configured", "warning",
                           "no model set — using the deterministic narrator")
    else:
        log_case_event(case_id, "Report · regenerating (deterministic)", "info",
                       "no LLM tokens spent")
    try:
        report = llm_sim.generate_report(
            gv, window=window, min_severity=min_sev,
            initial_access=d.get("initial_access_estimate"), case_name=d.get("name", "Case"),
            run_id=case_id, audience=d.get("audience", "both"), language=d.get("language", "en"),
            master_prompt=d.get("master_prompt"),
            dispositions=d.get("dispositions") or None,
            validations=d.get("timeline_validations") or None,
            prefer_llm=use_llm, max_entities=llm_ent, budget_chars=llm_chars,
            max_output_tokens=llm_out)
        if use_llm and model:
            log_case_event(case_id, "Report · LLM responded", "success",
                           f"narrative generated ({len(report):,} chars)")
        analysis = llm_sim.analyze(gv, window=window, min_severity=min_sev, run_id=case_id,
                                   dispositions=d.get("dispositions") or None,
                                   max_entities=llm_ent, budget_chars=llm_chars,
                                   max_output_tokens=llm_out)
    except Exception as e:
        log_case_event(case_id, "Report generation", "error", f"LLM/render failed: {e}")
        raise
    try:
        _merge_case_details(case_id, {"report_md": report, "analysis": analysis,
                                      "report_dirty": False})
        log_case_event(case_id, "Report saved", "success", "report + advisory written to the database")
    except Exception as e:
        log_case_event(case_id, "Report save", "error", f"database write failed: {e}")
        raise
    return {"report_md": report, "audience": d.get("audience", "both")}


def engagement_markdown(case_id) -> str:
    """Branded full report markdown (engagement-style cover + report body) for MD/PDF
    download. Reuses the engagement cover_block so the shared PDF renderer parses it."""
    from datetime import datetime, timezone
    from services.engagement.templates import cover_block
    d = get_case(case_id)
    ws = _ws()
    sources = []
    for rid in _members_for_case(case_id, d):
        r = ws.get_automation_run(rid) or {}
        sources.append({"run_id": rid, "name": r.get("name") or rid, "section": "",
                        "automation_type": r.get("automation_type")})
    cover = cover_block(d.get("name", "Case"),
                        datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
                        sources, tlp=d.get("tlp", "AMBER"), version=1,
                        customer_name=d.get("customer_name", ""))
    body = d.get("report_md") or "_No report yet — fuse the case first._"
    return f"{cover}\n\n{body}"


# ---- Case Analysis console: config + rescan + checklist + timeline validation ----

# Human labels + formatters for the config-change audit log (the Log tab shows
# e.g. "Entity limit: 20000 → 50000" for every setting the operator changes).
_CONFIG_LABELS = {
    "max_entities": "Entity limit", "llm_max_output_tokens": "Output token cap",
    "min_severity": "Min severity", "time_window": "Time window",
    "fusion_modules": "Fusion modules", "masking": "Masking",
    "excluded_hosts": "Excluded hosts", "included_run_ids": "Included runs",
    "audience": "Report audience", "language": "Report language", "tlp": "TLP",
    "customer_name": "Customer name", "master_prompt": "Master prompt",
    "customer_logo_b64": "Customer logo",
}


def _fmt_cfg_val(k, v) -> str:
    if k == "customer_logo_b64":
        return "set" if v else "none"
    if k == "time_window":
        v = v or {}
        return f"{v.get('start') or 'open'} … {v.get('end') or 'now'}"
    if k == "fusion_modules":
        return ", ".join(v) if v else "none"
    if k == "masking":
        return "on" if (v or {}).get("enabled") else "off"
    if k == "excluded_hosts":
        return f"{len(v or [])} host(s)"
    if k == "included_run_ids":
        return "all" if v is None else f"{len(v or [])} run(s)"
    if k == "master_prompt":
        return f"{len(v)} chars" if v else "none"
    if v in (None, ""):
        return "unset"
    return str(v)[:80]


def _log_config_changes(case_id, before, patch) -> None:
    """Audit-log each setting the operator actually changed, old → new."""
    for k, new in patch.items():
        old = before.get(k)
        if old == new:
            continue
        label = _CONFIG_LABELS.get(k, k)
        log_case_event(case_id, f"Config · {label}", "info",
                       f"{_fmt_cfg_val(k, old)} → {_fmt_cfg_val(k, new)}")


def set_analysis_config(case_id, cfg) -> dict:
    """Persist the analysis variables from the config rail (time window, severity,
    masking, included runs, audience/branding/language). Only provided keys change."""
    patch = {}
    if "time_window" in cfg:
        tw = cfg.get("time_window") or {}
        patch["time_window"] = {"start": tw.get("start"), "end": tw.get("end")}
    for k in ("min_severity", "audience", "language", "tlp", "customer_name",
              "customer_logo_b64", "master_prompt"):
        if cfg.get(k) is not None:
            patch[k] = cfg[k]
    if "masking" in cfg:
        mk = cfg.get("masking") or {}
        patch["masking"] = {"enabled": bool(mk.get("enabled")),
                            "patterns": [p for p in (mk.get("patterns") or []) if p]}
    if "included_run_ids" in cfg:          # None = all; list = subset (legacy)
        patch["included_run_ids"] = cfg["included_run_ids"]
    if "excluded_hosts" in cfg:            # host labels to drop from the report/LLM
        patch["excluded_hosts"] = [h for h in (cfg.get("excluded_hosts") or []) if h]
    if "max_entities" in cfg:              # operator cap on the stored graph
        try:
            patch["max_entities"] = max(100, min(int(cfg["max_entities"]), MAX_GRAPH_ENTITIES))
        except (TypeError, ValueError):
            pass
    if "llm_max_output_tokens" in cfg:     # cap on tokens the model WRITES per call
        try:
            v = int(cfg["llm_max_output_tokens"])
            patch["llm_max_output_tokens"] = max(256, min(v, 64000)) if v else None
        except (TypeError, ValueError):
            pass
    if "fusion_modules" in cfg:            # which modules fuse (only available ones honored)
        mods = normalize_modules(cfg.get("fusion_modules"))
        patch["fusion_modules"] = [m for m in mods
                                   if m in FUSION_MODULES_AVAILABLE] or list(FUSION_MODULES_DEFAULT)
    if patch:
        before = get_case(case_id) or {}
        _log_config_changes(case_id, before, patch)
        try:
            _merge_case_details(case_id, patch)
            log_case_event(case_id, "Configuration saved", "success",
                           f"{len(patch)} setting(s) written to the database")
        except Exception as e:        # surface DB write failures in the log
            log_case_event(case_id, "Configuration save", "error",
                           f"database write failed: {e}")
            raise
    return {k: ("<logo>" if k == "customer_logo_b64" else v) for k, v in patch.items()}


def rescan(case_id, cfg=None) -> dict:
    """THE config-driven action: persist the rail's variables then re-correlate +
    regenerate. Replaces the bare re-fuse for the UI. Rescan is an explicit rebuild,
    so it DOES refresh the report (deterministically — reflecting the new masking /
    host-exclusion / severity); the premium LLM narrative is the Regenerate button."""
    if cfg:
        set_analysis_config(case_id, cfg)
    _merge_case_details(case_id, {"report_md": ""})   # force fuse to rebuild the report
    g = fuse_case(case_id)
    return {"entities": len(g.entities), "relationships": len(g.relationships),
            "findings": len(g.findings),
            "cross_host_findings": sum(1 for f in g.findings if f.kind == "cross_host")}


def case_members(case_id) -> list:
    """Runs tagged to the case + their host + whether they're currently included — feeds
    the include/exclude picker in the config rail."""
    ws = _ws()
    d = get_case(case_id)
    inc = d.get("included_run_ids")
    inc_set = set(inc) if inc is not None else None
    # best-effort OS per host, reusing the velociraptor snapshot (host/client_id -> os)
    os_by = {}
    try:
        from services.velociraptor_service import get_clients_from_snapshot
        for c in (get_clients_from_snapshot(include_offline=True) or []):
            o = (c.get("os") or "").lower() or "unknown"
            if c.get("hostname"):
                os_by[str(c["hostname"]).lower()] = o
            if c.get("client_id"):
                os_by[str(c["client_id"]).lower()] = o
    except Exception:
        pass
    out = []
    for rid in _members_for_case(case_id, d):
        r = ws.get_automation_run(rid) or {}
        det = r.get("details") or {}
        host = det.get("client_name") or det.get("account") or det.get("account_id") \
            or det.get("tenant_id") or det.get("subscription_id")
        if not host:
            hn = det.get("hostnames")
            if isinstance(hn, dict):
                host = ", ".join(str(v) for v in hn.values()) or None
            elif isinstance(hn, list):
                host = ", ".join(str(v) for v in hn) or None
        # last resort: the run's human name (e.g. "AWS Scan: …") — never the raw run_id,
        # which read as "run names not hosts". Cloud scans with no account land here.
        # host-scoped = a single endpoint (agentic/memory/timesketch on a client). Hunts,
        # CVE sweeps, engagement reports and cloud scans are NOT a single host.
        host_scoped = bool(det.get("client_name") or det.get("hostnames"))
        host = host or r.get("name") or rid
        atype = r.get("automation_type")
        if atype in ("aws_scan", "azure_scan"):
            os_name = "aws" if atype == "aws_scan" else "azure"
        elif host_scoped:
            cid = det.get("client_id")
            os_name = os_by.get(str(host).lower()) \
                or (os_by.get(str(cid).lower()) if cid else None) or "unknown"
        else:
            os_name = "unknown"
        out.append({"run_id": rid, "type": atype, "host": host, "os": os_name,
                    "host_scoped": host_scoped, "status": r.get("status"),
                    # agentic-vs-general tag (Velociraptor runs only) so the UI can
                    # show which runs the 'Velociraptor (Agentic)' module includes.
                    "is_agentic": _is_agentic_run(r) if atype in _VELOCIRAPTOR_TYPES else None,
                    "included": (inc_set is None) or (rid in inc_set)})
    return out


def decide_checklist_item(case_id, item_id, decision) -> dict:
    """Customer confirms a checklist item. accept => the finding is benign (dispositioned
    + re-fused, suppressed); decline => kept as a real finding."""
    d = get_case(case_id)
    items = d.get("disposition_checklist") or []
    item = next((x for x in items if x.get("id") == item_id), None)
    if not item:
        return {"error": "checklist item not found"}
    decision = "accept" if decision == "accept" else "decline"
    item["status"] = "accepted" if decision == "accept" else "declined"
    _merge_case_details(case_id, {"disposition_checklist": items})
    if decision == "accept" and item.get("finding_id"):
        # benign confirmation -> disposition + re-fuse (this re-persists the checklist too)
        set_disposition(case_id, item["finding_id"], verdict="benign",
                        attribution="customer",
                        reason=f"customer-confirmed benign: {item.get('question', '')}",
                        scope="case")
    return {"item_id": item_id, "status": item["status"]}


# Timeline validation states (fully reversible — every transition is allowed):
#   real      -> confirmed malicious / keep      (clears any suppression)
#   not_real  -> false positive                  (suppress: disposition benign / operator)
#   known_it  -> IT confirms expected activity   (suppress: disposition benign / it_admin)
#   pending   -> not yet triaged                 (clears any suppression + the record)
_TL_STATES = ("real", "not_real", "known_it", "pending")


def validate_timeline(case_id, finding_id, status, notes="") -> dict:
    """Operator triages a timeline entry. Reversible: changing the status removes
    the previous record and re-applies/clears the matching suppression so a row
    can move freely between real / not_real / known_it / pending.

    Manual events (finding_id 'manual:…') carry their own status on the event
    record — they have no graph finding to suppress."""
    status = status if status in _TL_STATES else "pending"
    log_case_event(case_id, "Timeline · validation", "info",
                   f"{finding_id} marked {status}" + (f" — {notes}" if notes else ""))

    if str(finding_id).startswith("manual:"):
        return _set_manual_event_status(case_id, finding_id, status, notes)

    # Snapshot the finding's CURRENT occurrence watermark — the verdict covers exactly
    # this much activity; new activity later re-opens it (see correlate._wm_new_activity).
    wm = None
    try:
        f = next((x for x in load_graph(case_id).findings if x.id == finding_id), None)
        if f is not None:
            wm = f.watermark()
    except Exception:
        wm = None

    d = get_case(case_id)
    vals = [v for v in (d.get("timeline_validations") or []) if v.get("finding_id") != finding_id]
    if status != "pending":
        vals.append({"finding_id": finding_id, "status": status, "notes": notes,
                     "watermark": wm})
    _merge_case_details(case_id, {"timeline_validations": vals})

    if status == "not_real":
        set_disposition(case_id, finding_id, verdict="benign", attribution="operator",
                        reason=f"timeline: marked not real{(' — ' + notes) if notes else ''}",
                        scope="case", watermark=wm)
    elif status == "known_it":
        set_disposition(case_id, finding_id, verdict="benign", attribution="it_admin",
                        reason=f"timeline: IT confirms expected{(' — ' + notes) if notes else ''}",
                        scope="case", watermark=wm)
    else:
        # real or pending — un-suppress (no-op if there was no disposition).
        clear_disposition(case_id, finding_id)
    return {"finding_id": finding_id, "status": status}


def add_manual_timeline_event(case_id, event) -> dict:
    """Operator-entered timeline fact (e.g. 'IT pushed a GPO at 14:05'). Stored on
    the case, merged into the timeline. Editable + deletable; never suppressed by
    fuse since it isn't a graph finding."""
    if not get_case(case_id):
        return {"error": "case not found"}
    eid = "manual:" + keys._h(f"{case_id}:{event.get('ts','')}:{event.get('title','')}"
                              f":{_now_iso()}", 12)
    row = {"finding_id": eid, "manual": True, "source": "manual",
           "ts": (event.get("ts") or "").strip(),
           "host": (event.get("host") or "").strip() or "-",
           "title": (event.get("title") or "").strip() or "(manual event)",
           "severity": (event.get("severity") or "informational").strip().lower(),
           "artifacts": ["manual"], "phase": "Manual",
           "status": (event.get("status") if event.get("status") in _TL_STATES else "real"),
           "notes": (event.get("notes") or event.get("description") or "").strip(),
           "created_at": _now_iso()}
    d = get_case(case_id)
    evs = list(d.get("manual_timeline_events") or []) + [row]
    _merge_case_details(case_id, {"manual_timeline_events": evs})
    log_case_event(case_id, "Timeline · manual event added", "info",
                   f"{row['title']} @ {row['ts'] or 'no ts'} on {row['host']}")
    return row


def delete_manual_timeline_event(case_id, event_id) -> dict:
    d = get_case(case_id)
    evs = [e for e in (d.get("manual_timeline_events") or []) if e.get("finding_id") != event_id]
    _merge_case_details(case_id, {"manual_timeline_events": evs})
    log_case_event(case_id, "Timeline · manual event deleted", "info", event_id)
    return {"event_id": event_id, "deleted": True}


def _set_manual_event_status(case_id, event_id, status, notes="") -> dict:
    d = get_case(case_id)
    evs = list(d.get("manual_timeline_events") or [])
    hit = next((e for e in evs if e.get("finding_id") == event_id), None)
    if not hit:
        return {"error": "manual event not found"}
    hit["status"] = status
    if notes:
        hit["notes"] = notes
    _merge_case_details(case_id, {"manual_timeline_events": evs})
    return {"finding_id": event_id, "status": status}


def case_hosts(case_id) -> list:
    """The case's host IDENTITIES = the fused graph's asset nodes (endpoints, already
    deduped by client_id/hostname across modules; + cloud accounts), with OS and the
    current excluded state. This is what the 'Hosts (include)' picker lists."""
    d = get_case(case_id)
    g = load_graph(case_id)
    excluded = {keys.norm_host(h) for h in (d.get("excluded_hosts") or [])}
    os_by = {}
    try:
        from services.velociraptor_service import get_clients_from_snapshot
        for c in (get_clients_from_snapshot(include_offline=True) or []):
            o = (c.get("os") or "").lower() or "unknown"
            if c.get("hostname"):
                os_by[str(c["hostname"]).lower()] = o
            if c.get("client_id"):
                os_by[str(c["client_id"]).lower()] = o
    except Exception:
        pass
    out = []
    for a in g.by_type("asset"):
        label = a.label or a.id
        if a.id.startswith("asset:cloud_account:"):
            parts = a.id.split(":")
            out.append({"host": label, "os": parts[2] if len(parts) > 2 else "cloud",
                        "kind": "cloud", "sources": list(a.sources or []),
                        "excluded": keys.norm_host(label) in excluded})
        else:
            cid = a.id.split(":")[-1]
            os_name = os_by.get(str(label).lower()) or os_by.get(str(cid).lower()) or "unknown"
            out.append({"host": label, "os": os_name, "kind": "endpoint",
                        "sources": list(a.sources or []),
                        "excluded": keys.norm_host(label) in excluded})
    out.sort(key=lambda h: (h["os"], h["host"].lower()))
    return out


def get_timeline(case_id) -> list:
    """Unified case timeline: every finding (with its source artifact + 4-state
    validation) PLUS operator-added manual events, sorted by time. Honors
    host-exclusion so it matches the report.

    Each row: finding_id, ts, host, phase, title, severity, mitre, artifacts,
    source ('fusion'|'manual'), validation ('real'|'not_real'|'known_it'|
    'pending'), suggested_benign (analyst hinted it looks expected), manual."""
    from services.fusion.correlate import _wm_new_activity
    d = get_case(case_id)
    g = _filter_graph_by_hosts(load_graph(case_id), d.get("excluded_hosts"))
    vrec = {v.get("finding_id"): v for v in (d.get("timeline_validations") or [])}
    fwm = {f.id: f.watermark() for f in g.findings}     # current occurrence watermark
    # analyst "looks benign" suggestions (the old checklist) -> inline hint
    suggested = {it.get("finding_id") for it in (d.get("disposition_checklist") or [])
                 if it.get("suggestion") == "benign"}
    rows = render.timeline(g, window=d.get("time_window") or None)
    for r in rows:
        fid = r.get("finding_id")
        v = vrec.get(fid)
        r["reopened"] = False
        if v:
            st = v.get("status", "pending")
            # A benign verdict (Known/False-positive) RE-OPENS to Pending when new
            # activity arrived since it was made — it only covered the watermark it
            # snapshotted. Real/pending are not occurrence-bound.
            if st in ("known_it", "not_real") and _wm_new_activity(v.get("watermark"), fwm.get(fid, "")):
                r["validation"] = "pending"
                r["reopened"] = True
            else:
                r["validation"] = st
        else:
            r["validation"] = "pending"
        r["suggested_benign"] = fid in suggested
        r["manual"] = False
    # manual events carry their own status on the record
    for e in (d.get("manual_timeline_events") or []):
        row = dict(e)
        row["ts"] = render.fmt_ts(e.get("ts"))     # same display format as findings
        row["validation"] = e.get("status", "real")
        row.setdefault("mitre", [])
        row.setdefault("suggested_benign", False)
        rows.append(row)
    rows.sort(key=lambda r: (r.get("ts") or "9999"))
    return rows


def chat_case(case_id, question) -> str:
    d = get_case(case_id)
    g = load_graph(case_id)
    # Log the ACTION only (never the message content) so the audit trail stays useful
    # without leaking case Q&A into the log.
    log_case_event(case_id, "Chat · question received", "info", f"{len(question or '')} chars")
    # FP-triage via chat: if the message attributes activity to IT/employee/etc and grounds
    # to a real finding/entity, record the disposition + re-fuse, then confirm.
    disp = llm_sim.detect_disposition(g, question)
    if disp:
        log_case_event(case_id, "Chat · disposition detected", "info",
                       f"{disp.get('label')} → {disp.get('verdict')} ({disp.get('attribution')})")
        set_disposition(case_id, disp["target"], verdict=disp["verdict"],
                        attribution=disp["attribution"], reason=disp.get("reason", ""),
                        scope=disp.get("scope", "case"))
        ans = (f"Noted — marked **{disp['label']}** as {disp['verdict']} "
               f"({disp['attribution']}). It's suppressed from active findings and won't "
               f"drive host risk; re-fused. Say 'environment' to suppress it fleet-wide.")
    else:
        model, provider, _m = _configured_fusion_model()
        log_case_event(case_id, "Chat · sending to LLM", "info",
                       f"model {model} ({provider})" if model else "deterministic (no model set)")
        try:
            ans = llm_sim.chat(g, question, history=d.get("chat_messages") or [],
                               window=d.get("time_window") or None,
                               min_severity=d.get("min_severity", "informational"),
                               run_id=case_id, dispositions=d.get("dispositions") or None,
                               validations=d.get("timeline_validations") or None)
            log_case_event(case_id, "Chat · reply generated", "success", f"{len(ans or '')} chars")
        except Exception as e:
            log_case_event(case_id, "Chat", "error", f"LLM failed: {e}")
            raise
    def _append_msgs(details):           # atomic, so concurrent turns don't clobber
        msgs = list(details.get("chat_messages") or [])
        msgs += [{"role": "user", "content": question},
                 {"role": "assistant", "content": ans}]
        details["chat_messages"] = msgs
    _ws().mutate_run_details(case_id, _append_msgs)
    return ans


def get_chat(case_id) -> list:
    """The persisted conversation for a case (survives page refreshes)."""
    return list((get_case(case_id) or {}).get("chat_messages") or [])


def clear_chat(case_id) -> dict:
    _merge_case_details(case_id, {"chat_messages": []})
    return {"cleared": True}
