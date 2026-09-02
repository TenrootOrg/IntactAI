"""Case persistence + fuse orchestration.

A Case is just a workflow row (``automation_type='case'``) whose ``details``
hold the window/severity, member run ids, the fused graph, the report, and
chat. Reuses workflow_service entirely — no new table. Member runs are
fetched, dispatched to their module mapper, assembled into one graph by
``correlate.assemble``, then narrated by ``llm_sim`` (simulated).
"""

from __future__ import annotations

import hashlib
import json
import os
import threading

from .schema import FusionGraph
from . import correlate, llm_sim, keys, render, budget
from .mappers import map_memory, map_agentic, map_timesketch, map_cloud
from .mappers.agentic import SUPPORTED_ARTIFACTS, _artifact_base


def _filter_supported(cd):
    """Fusion INGEST allowlist: keep only artifacts we support (the hardcoded
    SUPPORTED_ARTIFACTS set), applied here at the boundary — before map_agentic —
    so the mapper stays a pure artifact->entity function and cases NEVER ingest raw
    / unsupported Velociraptor data regardless of source (collection/hunt/import)."""
    if not cd or not SUPPORTED_ARTIFACTS:
        return cd
    return {k: v for k, v in cd.items() if _artifact_base(k) in SUPPORTED_ARTIFACTS}

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
# We fuse ONLY the agentic blueprints — their artifacts are the ones the agentic
# mapper actually understands (see "SUPPORTED ARTIFACTS" in mappers/agentic.py).
# General / ad-hoc hunts are intentionally NOT fusable: 'velociraptor_all' has
# been removed from the picker (legacy case configs that still carry it normalize
# back to agentic). 'velociraptor_all' stays in TYPES only as that alias target.
# `available` modules can be toggled in the UI; `disabled` ones are shown greyed.
FUSION_MODULE_TYPES = {
    "velociraptor_agentic": {"velociraptor_collection", "velociraptor_upload"},
    "velociraptor_all": {"velociraptor_collection", "velociraptor_upload",
                         "velociraptor_hunt"},
    "memory": {"memory"},
    "timesketch": {"timesketch"},
    "aws": {"aws_scan"},
    "azure": {"azure_scan"},
    # legacy alias for cases saved before the agentic/all split (maps to agentic)
    "velociraptor": {"velociraptor_collection", "velociraptor_upload"},
}
# Order + membership of the UI picker. 'velociraptor_all' and the legacy
# 'velociraptor' alias are intentionally NOT shown — only agentic blueprints fuse.
#
# TimeSketch and Azure are also not shown. They were rendered greyed-out with a
# "disabled" badge, which reads as "this is broken / you are missing something"
# rather than "not built yet" — two dead rows in a five-row picker, permanently.
# They stay in FUSION_MODULE_TYPES and _FUSION_MODULE_LABELS below so a legacy
# case that still carries one keeps mapping correctly; only their visibility is
# removed. To bring either back, add it here AND to FUSION_MODULES_AVAILABLE —
# listing it here alone just restores the greyed row.
FUSION_MODULES_UI = ["velociraptor_agentic", "memory", "aws"]
# Selectable now: Velociraptor (Agentic), Memory (VolWeb) and AWS (CloudTrail),
# all three on by default. TimeSketch/Azure stay greyed/disabled.
#
# AWS was opt-in on the reasoning that "not every case is cloud". That reasoning
# had it backwards: a case with no CloudTrail scan has no aws_scan runs, so the
# module being on costs exactly nothing — the gate has nothing to admit. The
# only cases it changes are the ones that DID run a CloudTrail scan, and there
# an off-by-default module meant the scan the operator deliberately ran was
# silently left out of the fused graph and the report until they found this
# checkbox. Defaulting off protected nobody and hid real evidence.
FUSION_MODULES_AVAILABLE = ("velociraptor_agentic", "memory", "aws")
FUSION_MODULES_DEFAULT = ["velociraptor_agentic", "memory", "aws"]
_FUSION_MODULE_LABELS = {
    "velociraptor_agentic": "Velociraptor (Agentic)",
    "velociraptor_all": "Velociraptor (All)",
    "memory": "Volatile Memory (VolWeb)",
    "timesketch": "TimeSketch", "aws": "AWS (CloudTrail)", "azure": "Azure",
}


def normalize_modules(mods):
    """Map legacy module names to current ones + apply the default. Keeps cases
    saved before the agentic/all rename working without a data migration."""
    if not mods:
        return list(FUSION_MODULES_DEFAULT)
    # legacy 'velociraptor' AND the now-removed 'velociraptor_all' both collapse
    # to agentic — we only fuse agentic blueprints.
    _ALIAS = {"velociraptor": "velociraptor_agentic", "velociraptor_all": "velociraptor_agentic"}
    out = [_ALIAS.get(m, m) for m in mods]
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


_VELOCIRAPTOR_TYPES = {"velociraptor_collection", "velociraptor_upload",
                       "velociraptor_hunt", "velociraptor_offline_import",
                       "velociraptor_adopt"}


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
    Non-Velociraptor modules (memory/aws/azure/timesketch) gate on type as
    before. Replaces the old pure-type gate (`automation_type in
    _enabled_run_types`) so an agentic HUNT now fuses under 'Velociraptor
    (Agentic)' and a non-agentic collection/import no longer does."""
    atype = run.get("automation_type")
    mods = set(normalize_modules(d.get("fusion_modules")))
    if atype in _VELOCIRAPTOR_TYPES:
        # Any velociraptor run (collection / offline-collector import / hunt) fuses when a
        # velociraptor module is enabled — provenance no longer EXCLUDES a whole run. The
        # agentic ARTIFACT allowlist (_filter_supported, applied in every velo
        # contribution) keeps only the "agentic-confirmed" artifacts, so a run that did
        # NOT come from an agentic blueprint still contributes exactly those artifacts
        # (or nothing). This is what makes offline-collector imports / general hunts /
        # ad-hoc collections all fuse; `is_agentic` is now a display label, not a gate.
        return bool(mods & {"velociraptor_all", "velociraptor_agentic", "velociraptor"})
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
    fit the char budget, so a 500k graph cap can't overflow the model context.

    The ceiling starts at the static _LLM_MAX_BUDGET_CHARS (written for a
    ~128k-context model) and is then DERIVED from the selected model's real
    context window — see budget.adaptive_budget(). Returns
    (llm_max_entities, budget_chars)."""
    n = d.get("max_entities")
    try:
        n = int(n)
    except (TypeError, ValueError):
        n = DEFAULT_MAX_ENTITIES
    n = max(20, n)

    budget_chars = _LLM_MAX_BUDGET_CHARS
    # LOCKED ON. This used to be the case's 'Use the model's full context'
    # checkbox. It never earned the choice: the static ceiling was written for a
    # ~128k-context model and silently wasted most of a modern window, and the
    # derivation below can only ever RAISE the ceiling — so turning it OFF could
    # not cap spend against any measured baseline, it could only pin the payload
    # back to an obsolete constant. Cost is steered by the three settings that
    # actually bound it: Entity limit, Identity limit and Output token cap.
    try:
        from services.agentic.analyzers._llm import get_model_context_length
        model, provider, _ = _configured_fusion_model()
        adaptive = budget.adaptive_budget(
            get_model_context_length(model or "", provider or ""),
            _effective_output_cap(d))
        if adaptive:
            # Only ever RAISE the ceiling here, never lower it: a small local
            # model resolving to a tiny window would otherwise starve the
            # report to a few entities, which is not what "use the full
            # context" means to an operator.
            budget_chars = max(budget_chars, adaptive[0])
    except Exception:  # noqa: BLE001 — never break fusion over a budget hint
        pass

    # TRANSPORT CEILING (measured): the model's context is not the only limit — the
    # Codex CLI hard-rejects any request over 1 MiB of characters regardless of how
    # large the model's window is. Clamp AFTER the adaptive raise, or selecting a
    # large-context model computes a multi-megabyte payload and every report fails
    # with input_too_large. See budget.transport_cap_chars.
    try:
        _cap = budget.transport_cap_chars(_configured_fusion_model()[1])
        if _cap and budget_chars > _cap:
            budget_chars = _cap
    except Exception:  # noqa: BLE001 — a cap hint must never break fusion
        pass

    safe_cap = budget_chars // _LLM_CHARS_PER_ENTITY            # entities that fit the context
    return min(n, safe_cap), budget_chars


def _llm_identity_budget(d):
    """Max identities the LLM payload may include — the case's 'Identity limit'
    setting (Case Analysis -> Configuration). Unset/None means 'tied to the
    Entity limit': render._distilled_at() clamps identities to whatever
    max_entities already is (see _llm_payload_budget), so raising the Entity
    limit already raises this too with no separate action needed. Set this
    explicitly LOWER to show fewer identity rows than the entity budget would
    otherwise allow (a more concise/private payload) — it can only lower the
    effective count, never raise it past the entity ceiling, so a large value
    here can't blow past the same context-safe budget everything else respects."""
    n = d.get("max_identities")
    try:
        n = int(n)
    except (TypeError, ValueError):
        return None
    return max(0, n)


def _effective_output_cap(d):
    """Max tokens the model WRITES per LLM call for THIS case: ALWAYS the selected
    model's max output. This was a per-case 'Output token cap' field; see the
    LOCKED block in update_case_config for why it stopped being a choice.

    Deliberately ignores any stored llm_max_output_tokens rather than reading it
    with a default: cases configured before the field was removed still carry a
    value, and they must not stay truncated until someone re-saves them.

    Clamped to _MAX_OUTPUT_TOKENS_PER_CALL — see there for why asking a provider
    for the model's true maximum makes the request fail outright."""
    model, provider, _ = _configured_fusion_model()
    return min(_model_max_output(model, provider), _MAX_OUTPUT_TOKENS_PER_CALL)


# Rescan-cost model: a rescan makes 2 LLM passes (report + advisory), each gets
# the distilled payload (~fusion_approx tokens) + a small system prompt, and
# writes up to the output cap. All approximate — for a pre-spend sanity number.
_RESCAN_LLM_CALLS = 2

# Expected tokens the model WRITES per call, for the cost estimate only — never a
# limit on generation. A fused report and its advisory land in the low thousands;
# this is the figure to tune if the estimate reads consistently high or low
# against real invoices. It exists because the real ceiling (the model max) is a
# useless basis for a dollar estimate — see estimate_rescan_cost.
_RESCAN_EXPECTED_OUT_TOKENS = 8000
_SYS_PROMPT_TOKENS = 3000
_DEFAULT_OUTPUT_TOKENS = 4000

# Ceiling on what we ASK the model to be allowed to write, per call.
#
# Not the model's maximum, deliberately. max_tokens is a RESERVATION against the
# key's remaining allowance, not a bill -- OpenRouter refuses a request whose
# worst case it cannot cover, before generating a token:
#
#   402: "You requested up to 384000 tokens, but can only afford 298717"
#        limit_source: openrouter_credits
#
# So the same request succeeds on a cheap model and fails on a pricier one at
# the same balance: asking for a full 384k output reserves 384k * the model's
# OUTPUT RATE, and moving deepseek-v4-flash -> deepseek-v4-pro multiplied that
# reservation ~18x. Nothing was wrong with the key or the credit; the single
# call simply tried to reserve more of a monthly cap than it had left. It is
# also self-worsening under concurrency -- the affordable figure fell 373396 ->
# 298717 across retries while other fuses held reservations of their own.
#
# The failure is silent: generate_report catches it and returns the
# deterministic report, so the symptom reads as "the narrative stopped working
# when I changed model" rather than as a billing refusal.
#
# 32k is far more than any report needs (the longest reference technical report
# is ~21k tokens) and reserves cents rather than a dollar. It bounds the
# RESERVATION, not the answer -- if a report ever genuinely hits this, raise it
# rather than letting it truncate.
_MAX_OUTPUT_TOKENS_PER_CALL = 32000


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
    """The configured model's max output tokens (catalog/alias resolved).

    When the catalog does not carry one, fall back to _MAX_OUTPUT_TOKENS_PER_CALL
    rather than _DEFAULT_OUTPUT_TOKENS. 4000 is a floor from an era of smaller
    models and is now actively harmful: a reasoning model spends its output
    budget thinking BEFORE it emits visible text, so at 4000 against a large
    payload the whole budget goes to reasoning and the reply comes back empty
    with HTTP 200 — the "(the model returned an empty answer)" failure.

    This is not hypothetical for unpriced catalogs: codex-cli reports
    max_output_tokens=None for every model it serves, so a freshly connected
    subscription resolved to 4000 and would have failed exactly that way.
    """
    try:
        from services.agentic.analyzers._llm import get_model_max_output_tokens
        mx = get_model_max_output_tokens(model or "", provider or "claude")
        if mx:
            return int(mx)
    except Exception:
        pass
    return _MAX_OUTPUT_TOKENS_PER_CALL


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
    model_max_out = _model_max_output(model, provider)
    # Estimate on EXPECTED output, not on the ceiling. _effective_output_cap is
    # now always the model max (the per-case cap was removed), and a model that
    # may write 384k tokens does not write 384k tokens — it writes a report and
    # stops. Costing the ceiling would put a number two orders of magnitude too
    # large in front of the operator, which is worse than no number at all.
    out_per_call = min(_RESCAN_EXPECTED_OUT_TOKENS, _effective_output_cap(d))
    out_tokens = out_per_call * calls

    def _side(in_one):
        in_tokens = (in_one + _SYS_PROMPT_TOKENS) * calls
        return {"input_tokens": in_tokens,
                "usd": round(_estimate_llm_cost(model or "", in_tokens, out_tokens), 4)}

    before, after = _side(raw_in), _side(fused_in)
    # A subscription provider is not metered per token, so a dollar figure would
    # be fiction. Flag it instead and let the UI say "subscription" — the model
    # name still matters (the plan chooses one when the field is left blank).
    subscription = False
    try:
        from services.agentic import subscription_cli as _sub
        subscription = _sub.is_subscription_provider(provider)
    except Exception:  # noqa: BLE001
        subscription = False
    return {"model": model, "provider": provider, "mode": mode,
            "subscription": subscription,
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
                    reason="", scope="case", by="operator", watermark=None,
                    trigger=None) -> dict:
    """Record an operator triage on a finding/entity ('that PsExec was IT'), re-fuse so it
    takes effect, and — when scope='environment' — fold it into the env baseline so it
    suppresses across FUTURE cases too. Returns the disposition.

    `watermark` (occurrence snapshot from the timeline) binds a benign verdict to the
    occurrences it covered: when the finding later shows new activity beyond it, the
    suppression is treated as stale and the finding re-opens (correlate._apply_dispositions).
    None = no watermark (e.g. chat entity dispositions), which stay broad as before."""
    ws = _ws()
    disp = {"target": target, "verdict": verdict, "attribution": attribution,
            "reason": reason, "scope": scope, "by": by}
    if watermark:
        disp["watermark"] = watermark

    def _mutate(details):
        existing = [x for x in (details.get("dispositions") or []) if x.get("target") != target]
        details["dispositions"] = existing + [disp]

    # Atomic read-modify-write under the run lock — a plain get_case() +
    # update_run_status() (the old pattern) reads a snapshot, computes the
    # new list from it, then blind-overwrites: a concurrent writer (another
    # operator, or the watch_and_fuse background re-fuse thread) whose write
    # landed in between is silently lost.
    ws.mutate_run_details(case_id, _mutate)
    ws.update_run_status(case_id, "pending")
    log_case_event(case_id, "Risk · disposition applied", "info",
                   f"{target} → {verdict} ({attribution}, scope={scope}); re-fusing")
    if scope == "environment" and verdict == "benign":
        _promote_disposition_to_baseline(case_id, target)
    fuse_case(case_id, trigger=trigger or TRIGGER_DISPOSITION)
    return disp


def _set_pending_disposition(case_id, proposal) -> None:
    """Park (or clear) a triage verdict awaiting the operator's yes.

    Kept on the case row rather than in memory so the offer survives a backend
    restart and cannot leak between cases.
    """
    def _mutate(details):
        if proposal:
            details["pending_disposition"] = proposal
        else:
            details.pop("pending_disposition", None)
    try:
        _ws().mutate_run_details(case_id, _mutate)
    except Exception as e:  # noqa: BLE001 — never break the chat over this
        print(f"[FUSION] pending disposition not saved for {case_id}: {e}", flush=True)


def clear_disposition(case_id, target) -> dict:
    """Reverse an operator triage on a target (un-suppress) and re-fuse so a
    finding marked not-real / known-IT comes back to its real severity. The
    counterpart to set_disposition — makes validation reversible."""
    ws = _ws()

    def _mutate(details):
        details["dispositions"] = [x for x in (details.get("dispositions") or [])
                                   if x.get("target") != target]

    ws.mutate_run_details(case_id, _mutate)
    ws.update_run_status(case_id, "pending")
    log_case_event(case_id, "Risk · disposition cleared", "info", f"{target}; re-fusing")
    fuse_case(case_id, trigger=TRIGGER_DISPOSITION_CLEARED)
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


def _case_created_dt(case_id):
    """Creation time from the case id ('<type>_<ms-epoch>', see
    workflow_service.create_automation_run), falling back to now."""
    from datetime import datetime, timezone
    try:
        ms = int(str(case_id).rsplit("_", 1)[1])
        return datetime.fromtimestamp(ms / 1000, tz=timezone.utc)
    except Exception:
        return datetime.now(timezone.utc)


def _default_window(created_dt) -> dict:
    """Default case scope: the 10 YEARS UP TO creation, both bounds concrete.

    The window is wide on purpose — 10 years back reaches any real DFIR evidence,
    so nothing relevant is hidden by default (a narrow default was the QA symptom:
    findings older than the window silently vanished). What matters is that the
    bounds are CONCRETE rather than 'open': a fixed [start, end] is reproducible
    (it doesn't drift as wall-clock time passes) and is compared as a real instant
    by correlate.in_window, which is the timezone-safe path. `end` is the creation
    time; the lower bound is never cleared — see set_analysis_config."""
    from datetime import timedelta
    fmt = "%Y-%m-%dT%H:%M:%S"
    try:
        start_dt = created_dt.replace(year=created_dt.year - 10)
    except ValueError:                     # created on Feb 29 -> no Feb 29 ten years back
        start_dt = created_dt - timedelta(days=3653)
    return {"start": start_dt.strftime(fmt),
            "end": created_dt.strftime(fmt)}


def create_case(name, *, time_window=None, initial_access=None,
                min_severity="medium", member_run_ids=None, is_default=False,
                is_system=False) -> str:
    from datetime import datetime, timezone
    tw = dict(time_window or {})
    # Default the scope to [creation-10y, creation] for normal investigation
    # cases — wide enough to include any real evidence, but with CONCRETE bounds
    # (reproducible, timezone-safe compare). System / default catch-all cases keep
    # an open window. Only fill bounds the caller left blank.
    if not is_default and not is_system:
        dw = _default_window(datetime.now(timezone.utc))
        if not tw.get("start"):
            tw["start"] = dw["start"]
        if not tw.get("end"):
            tw["end"] = dw["end"]
    # The case row is itself a workflow row but is NEVER case-scoped — pass
    # case_id=None explicitly so the request's active case doesn't tag it.
    return _ws().create_automation_run(
        automation_type=CASE_TYPE, name=f"Case — {name}", case_id=None,
        details={"name": name, "time_window": tw,
                 "initial_access_estimate": initial_access, "min_severity": min_severity,
                 "member_run_ids": list(member_run_ids or []),
                 "is_default": bool(is_default), "is_system": bool(is_system),
                 "fusion_graph": {}, "report_md": "", "chat_messages": []})


def get_case(case_id) -> dict:
    run = _ws().get_automation_run(case_id)
    if not run or run.get("automation_type") != CASE_TYPE:
        return {}
    return run.get("details") or {}


def _graph_filter_signature(d, baseline) -> str:
    """Everything whose change invalidates the STORED graph.

    The stored graph is the FILTERED set — correlate.assemble drops entities
    outside the window or under the severity floor at ingest, and module gating
    decides which runs contribute at all. So none of these can be re-applied to
    a graph that was built under different ones; they need a rebuild.

    Dispositions are in here for a subtler reason: suppression is global. A
    verdict recorded on one finding can re-open or silence others through
    _apply_dispositions, so a triage action is a rebuild even though no new data
    arrived. That is also what today's per-action re-fuses already do.
    """
    tw = d.get("time_window") or {}
    payload = {
        "window": [tw.get("start"), tw.get("end")],
        "min_severity": d.get("min_severity", "informational"),
        "modules": sorted(normalize_modules(d.get("fusion_modules"))),
        "included": sorted(d.get("included_run_ids") or []) if d.get("included_run_ids") is not None else None,
        "is_baseline": bool(d.get("is_baseline")),
        "baseline": bool(baseline),
        "dispositions": _stable_hash(d.get("dispositions") or {}),
    }
    return _stable_hash(payload)


def _stable_hash(obj) -> str:
    try:
        return hashlib.sha256(
            json.dumps(obj, sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()[:16]
    except Exception:
        return "unhashable"


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


def attach_runs(case_id, run_ids) -> tuple[list, list]:
    """Legacy explicit attach (kept for back-compat / the API). In the workspace
    model runs auto-belong via their case_id tag; this also stamps the tag so a
    manually-attached run shows up under the case everywhere.

    A run already tagged to a DIFFERENT existing case is REJECTED rather than
    silently added to this case's legacy member_run_ids — previously it kept
    its old case_id tag but also joined this case's member list, so it fused
    into (and leaked evidence across) BOTH cases permanently with no error.
    Re-attaching a run to the SAME case, or a run with no case_id yet, is
    unaffected.

    Returns (members, rejected) where `rejected` is a list of
    {"run_id": ..., "owner_case_id": ...} for skipped runs.
    """
    from services.file_storage_service import get_workflow
    d = get_case(case_id)
    rejected = []
    accepted = []
    for rid in run_ids:
        run = get_workflow(rid)
        owner = run.get("case_id") if run else None
        if owner and owner != case_id:
            rejected.append({"run_id": rid, "owner_case_id": owner})
            continue
        accepted.append(rid)
    members = list(dict.fromkeys((d.get("member_run_ids") or []) + accepted))
    _ws().update_run_status(case_id, "pending", details={"member_run_ids": members})
    for rid in accepted:                       # tag the run into this workspace too
        run = get_workflow(rid)
        if run and not run.get("case_id"):
            run["case_id"] = case_id
            from services.file_storage_service import save_workflow
            save_workflow(run)
    return members, rejected


# Portable case bundles (export/import between appliances) live in case_bundle.py:
# a bundle is a streamed ZIP carrying the collected payloads, not a JSON document,
# and importing one has to remap every run id — neither belongs in the graph store.

def _unfail_stale_idle_workspace(run: dict) -> None:
    """A workspace ("case") row has no natural "completed" state — it's a
    container, not a job — so cleanup_orphan_workflows()'s idle->failed
    reaper used to mistake a quiet built-in workspace (no investigation
    activity for >10h) for an orphaned job. That's now fixed at the source
    (the reaper skips case/fusion_baseline rows), but a box that already hit
    it before that fix has the built-in workspace permanently stuck 'failed'
    forever after — self-heal it back to 'running' the next time it's
    looked up, so an already-affected box recovers without a manual repair."""
    if run.get("status") != "failed":
        return
    if "idle for" not in (run.get("error") or "").lower():
        return
    try:
        # update_run_status() only overwrites `error` when truthy (there's no
        # "clear" sentinel), so leaving it None would keep showing the stale
        # "idle for Nh" message even after status flips back to 'running'.
        _ws().update_run_status(
            run.get("run_id"), "running",
            error="(resumed — self-healed from a stale idle-timeout failure)")
    except Exception:
        pass


def ensure_default_case() -> str:
    """Return the id of the Default workspace, creating it if missing. Idempotent —
    safe to call on every startup."""
    ws = _ws()
    for r in ws.get_all_automation_runs() or []:
        if r.get("automation_type") != CASE_TYPE:
            continue
        det = r.get("details") or {}
        if det.get("is_default") or det.get("name") == DEFAULT_CASE_NAME:
            _unfail_stale_idle_workspace(r)
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
            _unfail_stale_idle_workspace(r)
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
    try:                                   # a pending auto-fuse would fire into a
        from . import autofuse              # case that no longer exists
        autofuse.cancel(case_id)
    except Exception:
        pass
    run_ids = [r.get("run_id") for r in ws.get_automation_runs_by_case(case_id)]
    for rid in run_ids:
        delete_workflow(rid)
        _delete_run_payloads(rid)
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
    # Also purge this case's entries from the cross-case KB — otherwise its
    # IOC/account/hash entities stay indexed forever and keep resurfacing as
    # "prior sightings" in unrelated future cases even after deletion.
    try:
        from . import kb
        kb.delete_case_entities(case_id)
    except Exception:
        pass
    return {"deleted": True, "runs_deleted": len(run_ids),
            "baselines_deleted": removed_baselines}


def _delete_run_payloads(rid) -> None:
    """Remove a deleted run's collected data from disk.

    Deleting the row alone left /data/downloads/<run_id>/raw_results.json behind
    — half a gigabyte per collection, unreachable (nothing can find it without
    the row) and reclaimable only by the Maintenance purge, which is all-or-
    nothing and takes every LIVE case's evidence with it. That was tolerable
    while runs were only ever created by collecting; importing a case COPIES
    those files, so a deleted import would strand its gigabytes permanently.

    Best-effort: a case delete must never fail over a file that would not go."""
    import re as _re
    import shutil as _shutil
    if not rid or not _re.match(r"^[A-Za-z0-9_]+$", str(rid)):
        return                          # never let a crafted id escape the dir
    for base in ("/app/data/downloads", "/data/downloads"):
        try:
            _shutil.rmtree(os.path.join(base, str(rid)), ignore_errors=True)
        except Exception:
            pass
    for base in ("/app/data/aws_runs", "/data/aws_runs"):
        try:
            os.remove(os.path.join(base, f"{rid}.json"))
        except Exception:
            pass


def _memory_contribution(rid, det):
    asset = keys.asset_id(det.get("client_id") or rid)
    host = det.get("client_name")
    # Prefer the run-time snapshot the memory pipeline persists BEFORE its
    # cleanup purges the VolWeb evidence dir. The yarascan results live in a
    # file under that dir, so a live re-fetch here 404s and silently drops
    # every yara hit from the graph (plugin rows survive in VolWeb's DB; yara
    # does not). The snapshot also avoids a VolWeb round-trip per fuse. Older
    # runs predating the snapshot fall back to the live fetch below.
    import json
    import os
    plugins = hits = None
    for base in (f"/app/data/downloads/{rid}", f"/data/downloads/{rid}"):
        fp = os.path.join(base, "memory_payload.json")
        if os.path.exists(fp):
            try:
                with open(fp) as f:
                    snap = json.load(f)
                plugins = snap.get("plugins") or {}
                hits = snap.get("yara") or []
            except Exception:
                plugins = hits = None
            break
    if plugins is None:
        from services.memory.volweb_client import VolWebClient
        from services.memory.analyzers import _build_plugin_payload, _build_yara_payload
        evid = det.get("evidence_id")
        if not evid:
            # A memory run that never produced evidence — cancelled during
            # acquisition, or failed before VolWeb registered anything. Without
            # this guard the id flows straight into
            # `/api/evidence/{evid}/plugins/`, requesting the literal path
            # `/api/evidence/None/plugins/`, which 404s. Fusion then surfaces a
            # page of HTML in a case warning, so a run with simply nothing to
            # contribute reads like a VolWeb outage.
            #
            # Falls through with empty payloads rather than returning early, so
            # the asset anchor is still created and the return shape stays
            # whatever map_memory produces.
            plugins, hits = [], []
        else:
            client = VolWebClient()
            plugins, _w = _build_plugin_payload(client, evid)
            try:                          # yara is optional — never lose plugins over it
                hits, _t = _build_yara_payload(client, evid)
            except Exception:
                hits = []
    return map_memory({"plugins": plugins, "yara": hits, "host": host},
                      run_id=rid, asset=asset, hostname=host)


def _flatten_cloud_findings(raw):
    """AWS/Azure findings are persisted keyed by source/rule (``{src: [finding,...]}``)
    or, for older/test rows, already a flat list. map_cloud wants a flat list of
    finding dicts, so normalise either shape here."""
    if isinstance(raw, list):
        return [f for f in raw if isinstance(f, dict)]
    if isinstance(raw, dict):
        out = []
        for v in raw.values():
            if isinstance(v, list):
                out.extend(f for f in v if isinstance(f, dict))
            elif isinstance(v, dict):
                out.append(v)
        return out
    return []


def _cloud_account(det, findings):
    """Best-effort cloud account/tenant id for the asset anchor: explicit run
    detail first, else read it off the first CloudTrail record."""
    acct = (det.get("account") or det.get("account_id") or det.get("tenant_id")
            or det.get("aws_account"))
    if acct:
        return acct
    for f in findings:
        rec = f.get("matched_record") if isinstance(f.get("matched_record"), dict) else f
        if not isinstance(rec, dict):
            continue
        a = rec.get("recipientAccountId")
        if not a:
            ui = rec.get("userIdentity")
            if isinstance(ui, dict):
                a = ui.get("accountId")
        if a:
            return a
    return None


def _cloud_contribution(rid, det, provider):
    """Fuse an AWS/Azure scan. The pipeline is collect-only: SIGMA findings +
    state snapshots feed the case via the cloud mapper. Findings live inline on
    small/test rows (``details.findings``), else in the persisted run file the
    aws route writes (/data/aws_runs/<rid>.json) to avoid bloating the run blob."""
    raw = det.get("findings") or det.get("sigma_findings")
    if not raw:
        fb = det.get("findings_by_severity")
        if isinstance(fb, dict):
            raw = fb
    synthetic = bool(det.get("synthetic"))
    if not raw:
        import json
        import os
        for base in (f"/app/data/aws_runs/{rid}.json", f"/data/aws_runs/{rid}.json"):
            if os.path.exists(base):
                try:
                    with open(base) as f:
                        _persisted = json.load(f) or {}
                    raw = _persisted.get("findings")
                    synthetic = synthetic or bool(_persisted.get("synthetic"))
                except Exception:
                    raw = None
                break
    # Demo data must never become case evidence. AWS ships attack-shaped
    # fixtures for development, and the cloud mapper turns their IPs into
    # `ioc:ip` nodes — which are GLOBAL, so a fictional address would collapse
    # with real endpoint NetScan hits and cross-correlate against actual
    # evidence. A run that used them is marked at the pipeline; drop it here.
    if synthetic:
        return [], []
    finds = _flatten_cloud_findings(raw)
    if not finds:
        return [], []
    return map_cloud(finds, run_id=rid, provider=provider,
                     account=_cloud_account(det, finds))


# A run's raw_results.json is read with json.load, which expands it in memory.
# Measured on this appliance: a 539.9 MB file peaked at 1.64 GB RSS — 3.1x. Use a
# margin over that, because the parse transiently holds both the text and the
# objects.
_PAYLOAD_RAM_MULTIPLIER = 4.0


def _available_ram_bytes():
    """MemAvailable, or None when it cannot be read (never guess a number —
    a wrong guess here either blocks a fuse that would have worked or fails to
    block one that kills the box)."""
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemAvailable:"):
                    return int(line.split()[1]) * 1024
    except Exception:
        pass
    return None


def _payload_too_big(fp, log=None):
    """True when loading `fp` would plausibly exhaust the box.

    WHY THIS EXISTS. json.load has no ceiling: a payload larger than free memory
    does not raise, it takes the machine down. That happened on this appliance —
    the backend was OOM-killed mid-fuse and the operator had to restart the host.
    The fuse itself is already streamed one member run at a time
    (see PASS 2), so the exposure is a SINGLE oversized run, not the case total.

    A refusal that names the file and the numbers is strictly better than a dead
    box: the other member runs still fuse, and the run stays stale so it is
    retried once there is headroom."""
    import os
    try:
        size = os.path.getsize(fp)
    except Exception:
        return False
    avail = _available_ram_bytes()
    if not avail:
        return False                      # cannot judge -> do not block
    need = size * _PAYLOAD_RAM_MULTIPLIER
    if need < avail * 0.6:                # comfortably fits
        return False
    if log:
        log(f"fuse: SKIPPING {os.path.basename(os.path.dirname(fp))} — its "
            f"raw_results.json is {size/1e9:.2f} GB and would need about "
            f"{need/1e9:.2f} GB to parse, with only {avail/1e9:.2f} GB available. "
            f"Loading it would exhaust this host. The other runs still fuse, and "
            f"this one stays pending — free memory (or give the appliance more) "
            f"and Refuse again.", "error")
    return True


def _agentic_collected_data(rid, det, log=None):
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
            if _payload_too_big(fp, log=log):
                return {}
            try:
                with open(fp) as f:
                    return json.load(f)
            except Exception:
                return {}
    return {}


def get_evidence_rows(case_id, finding_id, *, max_rows=10):
    """RAG drill-down: resolve a finding's evidence locators ('<artifact>/row=<i>')
    to the actual RAW rows in each contributing run's raw_results.json. The pointer
    (EvidenceRef.locator) already exists on every mapped entity/finding; this is what
    turns 'the graph says X' into 'here is the exact row X came from' — the retrieval
    the analyst (and, later, the agentic loop) drills with. Loads each run's raw file
    at most once (OOM-guarded via _agentic_collected_data). Returns a compact list
    [{run_id, artifact, row_index, row}]."""
    g = load_graph(case_id)
    f = next((x for x in g.findings if x.id == finding_id), None)
    if not f:
        return []
    refs = list(f.evidence or [])
    for eid in (f.entity_ids or []):
        e = g.entities.get(eid)
        if e:
            refs += list(e.evidence or [])
    cache, out, seen = {}, [], set()
    for ref in refs:
        rid = getattr(ref, "run_id", None)
        loc = getattr(ref, "locator", None)
        if not (rid and loc) or "/row=" not in loc or (rid, loc) in seen:
            continue
        seen.add((rid, loc))
        artifact, _, idx = loc.partition("/row=")
        try:
            idx = int(idx)
        except ValueError:
            continue
        if rid not in cache:
            run = _ws().get_automation_run(rid) or {}
            cache[rid] = _agentic_collected_data(rid, run.get("details") or {}) or {}
        data = cache[rid] or {}
        rows = data.get(artifact) or data.get(artifact.split("/")[0]) or []
        if isinstance(rows, list) and 0 <= idx < len(rows):
            out.append({"run_id": rid, "artifact": artifact, "row_index": idx, "row": rows[idx]})
        if len(out) >= max_rows:
            break
    return out


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
    flow_id = det.get("flow_id")
    client_id = det.get("client_id")
    # A hunt export stores hunt_id; a single-host offline import stores flow_id +
    # client_id (no hunt). Support both — pull by whichever locator is present.
    if not hunt_id and not (flow_id and client_id):
        if log:
            log(f"run {rid} has no hunt_id or flow/client_id — cannot fuse", "warning")
        return [], []
    # ALWAYS pull live so an in-flight hunt shows its current partial data and each
    # rescan picks up whatever has arrived since — no need to wait for the hunt to
    # finish. A snapshot is persisted only as a fallback for when Velociraptor is
    # unreachable.
    cd = {}
    try:
        from services.agentic.collectors import get_existing_collection_results, persist_pipeline_artifacts
        cd, _arts, client_info = get_existing_collection_results(
            rid, flow_id=(None if hunt_id else flow_id),
            hunt_id=hunt_id, client_ids=(None if hunt_id else [client_id]),
            only_artifacts=SUPPORTED_ARTIFACTS)
        if cd:
            # Merged, not overwritten: this fetch is scoped to what fusion maps,
            # so writing it straight over the snapshot would delete every other
            # artifact the hunt collected.
            _resnapshot_without_losing_rows(rid, det, cd)
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
    ents, rels = map_agentic(_filter_supported(cd), run_id=rid, hostnames=det.get("hostnames") or {})
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


def _resnapshot_without_losing_rows(rid, det, fetched):
    """Persist `fetched` over the run's snapshot WITHOUT dropping what it holds.

    Fusion fetches only the artifacts it supports (322 rows of a real 713,520-row
    collection), so writing that straight to raw_results.json would delete the
    run's Windows.NTFS.MFT and Windows.Forensics.Usn — 708,198 rows the operator
    collected on purpose and can still download. The refreshed sources are merged
    OVER the existing ones and everything else is left alone.
    """
    try:
        from services.agentic.collectors import persist_pipeline_artifacts
        merged = dict(_agentic_collected_data(rid, det) or {})
        merged.update(fetched or {})
        persist_pipeline_artifacts(rid, merged)
    except Exception:
        pass


def _refetch_agentic_rows(rid, det, log=None):
    """Ask Velociraptor for this collection's CURRENT results, and re-snapshot.

    A collection run fuses from raw_results.json — the snapshot written when the
    collection ended. That snapshot is frozen, and three ordinary situations
    leave the server holding more than it contains: the collection budget
    expired while the flow was still running (measured on a live 10-minute
    BestPractice run, which ended with "Some flows had not finished yet — they
    keep running in Velociraptor"), a flow errored and was abandoned by releases
    before that was fixed, or the fetch was cut short.

    So a MANUAL Refusion re-reads them. Not every fuse: this is a full result
    fetch per member run, measured at minutes for one 350k-row artifact, and the
    automatic fuse must stay quick. The operator pressing Refusion is asking for
    exactly this and is watching it happen.

    Returns None when there is nothing to re-fetch or the fetch fails, so the
    caller falls back to the snapshot rather than fusing an empty case.
    """
    flow = det.get("flow_id")
    flows = flow if isinstance(flow, list) else ([flow] if flow else [])
    if not flows:
        return None
    cid = det.get("client_id")
    try:
        from services.agentic.collectors import get_existing_collection_results
        merged = {}
        for fid in flows:
            got, _a, _ci = get_existing_collection_results(
                rid, flow_id=fid, client_ids=([cid] if cid else None),
                only_artifacts=SUPPORTED_ARTIFACTS)
            for k, v in (got or {}).items():
                merged.setdefault(k, [])
                merged[k].extend(v or [])
        if not merged:
            return None
        _resnapshot_without_losing_rows(rid, det, merged)
        if log:
            log(f"run {rid}: re-read {sum(len(v) for v in merged.values()):,} row(s) "
                f"from Velociraptor", "info")
        return merged
    except Exception as e:                      # noqa: BLE001 — never fail a fuse
        if log:
            log(f"run {rid}: could not re-read from Velociraptor ({e}); "
                f"using the stored snapshot", "warning")
        return None


def _contribution_for_run(run, log=None, refetch=False):
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
            rows = _refetch_agentic_rows(rid, det, log=log) if refetch else None
            if rows is None:
                rows = _agentic_collected_data(rid, det, log=log)
            ents, rels = map_agentic(_filter_supported(rows), run_id=rid,
                                     hostnames=det.get("hostnames") or {})
            # Coverage is by DATA SOURCE, and a collection is Velociraptor data
            # whether or not the agent post-analyzed it — exactly like a hunt,
            # upload, import or adopt (all already relabelled). Relabel both here
            # so the coverage column reads "velociraptor", never a confusing
            # "agentic" that made the same source look like two.
            _relabel_source(ents, rels, "agentic", "velociraptor")
            return ents, rels
        if atype in ("velociraptor_hunt", "velociraptor_offline_import",
                     "velociraptor_adopt"):
            # An offline import lands its rows under a Velociraptor HUNT (the
            # importer stores hunt_id on the run); read it the same way as a live
            # hunt. An ADOPTED flow/hunt is the same shape again — _velo_hunt_
            # contribution already handles both a hunt_id and a flow_id+client_id
            # locator, pulls live with only_artifacts=SUPPORTED_ARTIFACTS, and
            # relabels the source 'velociraptor' (no agent ran). The artifact
            # allowlist in the mapper keeps the graph clean.
            return _velo_hunt_contribution(rid, det, log=log)
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
            return _cloud_contribution(rid, det, prov)
    except Exception as e:  # never let one run break the fuse
        if log:
            log(f"fuse: run {rid} ({atype}) skipped: {e}", "warning")
    return [], []


class FusionBusy(RuntimeError):
    """A fuse is already running for this case, in another thread."""


# What caused a fuse. Recorded on every Refusion line in the case activity log so
# the operator can tell their own click apart from a colleague's, from a triage
# action that re-fuses as a side effect, and from anything running on its own.
# Keep these short — they render inline in the Log tab.
TRIGGER_MANUAL_REFUSION = "the Refusion button"
TRIGGER_MANUAL_RESCAN = "the Rescan (LLM) button"
TRIGGER_API_FUSE = "an API fuse request"
TRIGGER_CASE_CREATED = "case creation"
TRIGGER_DISPOSITION = "a triage disposition"
TRIGGER_DISPOSITION_CLEARED = "a cleared triage disposition"
TRIGGER_CHECKLIST = "a checklist decision"
TRIGGER_TIMELINE = "a timeline validation"
TRIGGER_IDENTITY = "an identity decision"
TRIGGER_AUTOMATIC_RUN_LANDED = "AUTOMATIC — a member run finished"
TRIGGER_AUTOMATIC_FIRST_VIEW = "AUTOMATIC — first view of a case with no graph yet"
_TRIGGER_UNKNOWN = "an unlabelled caller"


_FUSE_LOCKS: dict = {}
_FUSE_LOCKS_GUARD = threading.Lock()


def _fuse_lock(case_id):
    """Per-case re-entrant lock. RLock, not Lock, because several callers fuse
    from inside an operation that is itself under the lock (set_disposition ->
    fuse_case). Re-entrancy lets the SAME thread nest freely while still
    rejecting a genuinely concurrent fuse from another request."""
    with _FUSE_LOCKS_GUARD:
        return _FUSE_LOCKS.setdefault(case_id, threading.RLock())


def fuse_case(case_id, *, contributions_override=None, log=None, _record=True,
              force_report=False, trigger=None, allow_llm=True,
              refetch=None) -> FusionGraph:
    """Fuse the case. Refuses to run concurrently with itself.

    `allow_llm=False` forbids this fuse from calling the model even when one is
    configured and the case has no report yet. Automatic fuses pass it: the
    narrative is the expensive part and the thing an analyst is actually reading,
    so a background rebuild produces the deterministic report and leaves the
    narrative for a deliberate Rescan. Nothing is ever billed without a click.

    `force_report` rebuilds the report/advisory even though one already exists --
    what Rescan means. It is a PARAMETER rather than the caller blanking
    `report_md` first, because blanking happens outside this lock: rescan() used to
    write `report_md = ""` and only then call fuse_case, so a FusionBusy raised
    here left the case with its report destroyed and nothing to rebuild it. The
    operator saw an error and lost the narrative. Nothing is cleared now until the
    lock is held and a replacement is in hand.

    Saving the Configuration rail triggers a rescan, and nothing stopped a second
    one starting on top of a first still in progress. That was survivable while a
    fuse took seconds and made no model calls; with the narrative on by default a
    fuse can sit for minutes on an LLM response, so the window is now wide enough
    to hit by hand -- observed with two calls to the provider in flight for the
    same case at once, both billed, the loser's writes silently overwritten.
    """
    lock = _fuse_lock(case_id)
    if not lock.acquire(blocking=False):
        # NOT logged as a fuse failure — nothing was attempted. The route's
        # FusionBusy handler records it as "deferred" instead.
        raise FusionBusy(
            "a fuse is already running for this case — wait for it to finish "
            "(the report can take minutes while the model writes the narrative)")
    trig = (trigger or _TRIGGER_UNKNOWN).strip()
    phase = {"at": "starting", "pct": 0}
    try:
        return _fuse_case_locked(case_id, contributions_override=contributions_override,
                                 log=log, _record=_record, force_report=force_report,
                                 trigger=trigger, allow_llm=allow_llm,
                                 refetch=refetch, _phase=phase)
    except Exception as e:
        # A fuse that dies used to leave the log ending mid-progress — the last row
        # was whatever phase it reached, with no indication anything went wrong, so
        # the Log tab read as a job still running. Say plainly that it failed, what
        # asked for it, and how far it got, then re-raise so the caller still errors.
        if _record:
            log_case_event(case_id, "Refusion failed", "error",
                           f"triggered by {trig} — failed during '{phase['at']}' "
                           f"at {phase['pct']}% — {type(e).__name__}: {e}",
                           pct=phase["pct"])
        raise
    finally:
        lock.release()


def _fuse_case_locked(case_id, *, contributions_override=None, log=None, _record=True,
                      force_report=False, trigger=None, allow_llm=True,
                      refetch=None, _phase=None) -> FusionGraph:
    ws = _ws()
    d = get_case(case_id)
    # WHY this fuse is running. A fuse costs ~33s on a real case (9 hosts / 18.7k
    # entities) and the log used to open with a bare "Refusion · starting" — so an
    # operator watching the box spend half a minute had no way to tell whether they
    # had caused it, a colleague had, or something ran on its own. Every caller
    # names its trigger; `_TRIGGER_UNKNOWN` marks the ones that have not been
    # taught to, so an unlabelled fuse is visible rather than silently generic.
    trig = (trigger or _TRIGGER_UNKNOWN).strip()
    # WHEN TO GO BACK TO VELOCIRAPTOR. Only when a person asked for this fuse.
    #
    # A collection's rows come from a snapshot taken when it ended, and
    # Velociraptor routinely holds more than that — a flow that outlived the
    # collection budget keeps running server-side. Re-reading fixes it, and
    # costs a full result fetch per member run (minutes, for one large
    # artifact). That is fine for a Refusion the operator is watching and quite
    # wrong for the automatic fuse that follows every landing run, which has to
    # stay quick. So: manual triggers re-read, everything else uses the snapshot.
    if refetch is None:
        refetch = trig in (TRIGGER_MANUAL_REFUSION, TRIGGER_MANUAL_RESCAN,
                           TRIGGER_API_FUSE)
    # Shared with fuse_case so a failure there can name the phase this reached.
    _phase = _phase if _phase is not None else {"at": "starting", "pct": 0}

    def _plog(msg, status="info", detail="", pct=None):
        # progress -> case log (recorded fuses only). When a pct is given, append
        # "<pct>%" to the detail and stash pct as a structured field so the Log
        # tab can render a progress bar. Deliberately NO ETA: a time estimate
        # from elapsed-so-far swings wildly as uneven phases complete (it read
        # "~0s" at the start and jumped around after), so percentage alone is
        # the honest, stable signal.
        # Remember the furthest phase reached, so a failure below can say WHERE the
        # fuse died instead of only that it did. Tracked even when _record is off.
        _phase["at"] = msg.split("·", 1)[-1].strip() or msg
        if pct is not None:
            _phase["pct"] = int(pct)
        if not _record:
            return
        if pct is not None:
            tag = f"{int(pct)}%"
            detail = (f"{detail} · {tag}" if detail else tag)
            log_case_event(case_id, msg, status, detail, pct=int(pct))
        else:
            log_case_event(case_id, msg, status, detail)

    _plog("Refusion · starting", "info",
          f"triggered by {trig} — preparing to re-fuse the case graph", pct=1)
    members = _members_for_case(case_id, d)
    # include/exclude: scope the fusion to a chosen subset of the case's runs (None = all)
    inc = d.get("included_run_ids")
    if inc is not None:
        members = [m for m in members if m in set(inc)]
    seed_graph = None            # set below only on the additive path
    if contributions_override is not None:
        contributions = contributions_override
        # Counted off the override itself, so the name `contributions` is never
        # measured — below it is a generator, and len() on one raises.
        _n_contrib = len(contributions_override)
    else:
        # Module gating: only fuse runs whose module is enabled for this case
        # (default = velociraptor only). Disabled modules' runs stay tagged
        # members but contribute nothing to the graph. Drop the filtered runs
        # from `members` too so run_ids/baseline reflect what was actually fused.
        _plog("Refusion · reading + mapping run data", "info",
              f"{len(members)} member run(s)"
              + (" · re-reading each one from Velociraptor (this is why a manual "
                 "Refusion takes longer than an automatic one)" if refetch else ""),
              pct=5)
        # PASS 1 — decide membership. Module gating + terminal state: a run row is
        # ~1 KB, so this is cheap and touches none of the evidence.
        # (Disabled modules' runs stay tagged members but contribute nothing; they
        # are dropped from `members` too so run_ids/baseline reflect what was fused.)
        #
        # A RUN STILL IN FLIGHT IS NOT A MEMBER OF THIS FUSE, and leaving it in was
        # a silent data-loss race. `members` is membership by case TAG, with no
        # regard for status, and the fuse writes fused_run_ids = list(members) —
        # so a Refusion pressed while a job was running stamped that job as
        # "already fused" with none of its data in the graph. stale_member_runs
        # then applies the opposite rule (terminal AND not in fused_run_ids), so
        # when the job finally finished it was not stale, the automatic fuse woke
        # up, found nothing to do, and returned. No graph update, no report, and
        # nothing in any log to say why.
        #
        # Measured on this appliance 2026-08-26: memory_1787736379968 was created
        # 09:26:19, a Refusion ran 09:28:06 while it was still collecting, and the
        # run completed 09:42:01 — the case log ends at the Refusion and its
        # 15-minute memory acquisition never reached the case.
        #
        # Same predicate stale_member_runs uses, so the two halves now agree:
        # a run is fused when it is terminal, and stale until it has been.
        #
        # TERMINAL means "not still collecting" — cancelled and failed included.
        # This said ("completed", "success"), which is SUCCESSFUL-only and
        # contradicted the sentence above it. An operator who stops a
        # collection keeps everything Velociraptor already handed over, and
        # _members_for_case applies no status filter, so that data is a member
        # of the case that fusion then refused to read. Reproduced on case
        # 'test2': a cancelled run holding 481,253 rows mapped to 446 entities
        # via _contribution_for_run, yet fuse_case produced 0 — and because
        # stale_member_runs used the same wrong predicate, nothing ever
        # reported why.
        kept, kept_runs = [], []
        for rid in members:
            run = ws.get_automation_run(rid)
            if not run:
                continue
            if not _run_passes_gate(run, d):
                continue
            if (run.get("status") or "") in ("running", "pending"):
                continue
            kept.append(rid)
            kept_runs.append((rid, run))
        members = kept

        # ---- ADD, OR REBUILD? -------------------------------------------
        #
        # A full rebuild re-reads and re-maps EVERY member run — measured at
        # 27-54s on a real case, against ~1s for the correlation itself. When the
        # only thing that happened is that a run landed, all of that work
        # reproduces a graph we already have.
        #
        # Rebuilding is required when a GLOBAL parameter moved, because the
        # stored graph is the filtered set: window, severity floor, module
        # selection, included runs, the baseline, and dispositions (suppression
        # reaches findings the new run never touched). _graph_filter_signature
        # captures all of them, and a manual Refusion is exactly when they change.
        #
        # Everything else — a run finishing, a re-collect bringing more rows — is
        # additive, so the new runs are mapped onto the stored graph and the
        # derivation passes re-run over the merged result. Both merge primitives
        # are keyed and idempotent (FusionGraph.upsert / relate), so nothing is
        # duplicated by doing this repeatedly.
        # Baseline resolved HERE, before the decision, because it is part of the
        # signature: a case that has since captured (or lost) an environment
        # baseline cannot add to a graph built without (or with) one.
        _baseline_for_sig = (None if d.get("is_baseline")
                             else load_baseline(_env_key_from_members(members)))
        _sig = _graph_filter_signature(d, _baseline_for_sig)
        _already = [r for r in (d.get("fused_run_ids") or []) if r in set(members)]
        _incremental_ok = (
            trig == TRIGGER_AUTOMATIC_RUN_LANDED
            and bool(_already)
            and d.get("graph_filter_sig") == _sig
            and not contributions_override
        )
        if _incremental_ok:
            try:
                seed_graph = load_graph(case_id)
                _cap = int(d.get("max_entities") or DEFAULT_MAX_ENTITIES)
                if not seed_graph.entities or len(seed_graph.entities) >= _cap:
                    # A graph at the storage cap was PRUNED on the way to disk, so
                    # it is not a faithful base to add to — adding would compound
                    # the loss silently on every landing run.
                    seed_graph = None
            except Exception as _e:                  # noqa: BLE001
                _plog("Refusion · rebuilding", "info",
                      f"stored graph unreadable ({type(_e).__name__}) — full rebuild")
                seed_graph = None

        if seed_graph is not None:
            _new = [(rid, run) for rid, run in kept_runs if rid not in set(_already)]
            _plog("Refusion · adding new data", "info",
                  f"{len(_new)} new run(s) onto {len(seed_graph.entities):,} stored "
                  f"entities — the other {len(_already)} run(s) are already in the "
                  f"graph and are not re-read", pct=5)
            kept_runs = _new

        # PASS 2 — map the evidence, ONE RUN AT A TIME.
        #
        # This is a generator, not a list, and that is the whole point. Building
        # the list held every run's mapped entities in memory at once while
        # assemble() filtered them down: a single 547 MB capture maps to ~228,000
        # entity objects, of which ~18,700 survive the window/severity filter. Five
        # member runs therefore pinned ~1.1M objects to produce a 18,749-entity
        # graph, and the backend was OOM-killed at 5.6 GB doing exactly that on a
        # 15 GB box. Yielding lets each run's objects be collected as soon as
        # assemble has upserted them, so peak memory is one run plus the graph
        # instead of every run plus the graph.
        _nmem = max(1, len(kept_runs))

        def _contributions():
            for _i, (rid, run) in enumerate(kept_runs):
                yield _contribution_for_run(run, log=log, refetch=refetch)
                # 5% → 40% spread across the member runs (the per-run read + map is
                # the bulk of I/O for a multi-host hunt import).
                _plog(f"Refusion · mapped {_i + 1}/{_nmem} run(s)", "info",
                      (run.get("name") or rid)[:60],
                      pct=5 + int(35 * (_i + 1) / _nmem))

        contributions = _contributions()
        # Counted from the membership pass, NOT from `contributions` — that is now a
        # generator and len() on it raises. The count is the same either way, and it
        # is known before a single byte of evidence is read.
        _n_contrib = len(kept_runs)
    window = d.get("time_window") or None
    min_sev = d.get("min_severity", "informational")
    _plog("Refusion · building case graph", "info",
          f"window {(window or {}).get('start') or 'open'}…{(window or {}).get('end') or 'now'}, "
          f"severity {min_sev}+ · {_n_contrib} contributing run(s)", pct=45)
    # subtract the environment baseline (if one was captured) so provisioning /
    # automation noise doesn't read as attack signal.
    baseline = None if d.get("is_baseline") else load_baseline(_env_key_from_members(members))
    _sig_full = _graph_filter_signature(d, baseline)
    g = correlate.assemble(case_id, contributions, members, baseline=baseline, window=window,
                           min_severity=min_sev, dispositions=d.get("dispositions") or None,
                           seed=seed_graph)
    # Optional cross-infra identity correlation: add analyst-confirmed / auto / manual
    # identity edges. Best-effort + fully isolated — never breaks the fuse (below).
    _apply_identity_links(g, d, log=_plog if _record else None)
    _plog("Refusion · graph built", "info",
          f"{len(g.entities):,} entities, {len(g.relationships):,} links, "
          f"{len(g.findings):,} findings", pct=80)
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
    if d.get("report_md") and not force_report:
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
        # Decided BEFORE the log line so the progress message describes what is
        # actually about to happen. It used to read "deterministic report" in
        # every case, which was true while the narrative was opt-in and became a
        # lie the moment it became the default -- the operator watched 88% for
        # minutes while the box sat on an LLM call the log said it was not making.
        # Narrate iff a model is actually usable. "Air-gap analysis" used to be a
        # per-case tick that forced the deterministic template — and it confused
        # more than it helped: on an appliance with no model configured the report
        # was deterministic whether the box was ticked or not, so the setting
        # looked broken. There is nothing left to decide. No model, no key, or no
        # route means the deterministic report, and the Analysis tab says which.
        _narrate = allow_llm and llm_sim._use_real()
        _plog("Refusion · generating report", "info",
              ("narrated report (this waits on the model), advisory & checklist"
               if _narrate else
               "deterministic report, advisory & checklist"), pct=88)
        llm_ent, llm_chars = _llm_payload_budget(d)
        llm_ident = _llm_identity_budget(d)
        llm_out = _effective_output_cap(d)
        report = llm_sim.generate_report(
            gv, window=window, min_severity=min_sev,
            initial_access=d.get("initial_access_estimate"),
            case_name=d.get("name", "Case"), run_id=case_id,
            audience=d.get("audience", "both"), language=d.get("language", "en"),
            master_prompt=d.get("master_prompt"), mask=mask,
            dispositions=d.get("dispositions") or None,
            validations=d.get("timeline_validations") or None,
            # First scan narrates with the model whenever one is configured. It
            # used to be hardcoded False -- "fast, free, deterministic; LLM on
            # Rescan" -- which meant the report an operator actually READ was the
            # string-interpolated template, and the real narrative only existed if
            # they knew to press Regenerate. Almost nobody did, so the product was
            # judged on the template. A box with no model, no key or no route gets
            # the deterministic report automatically and is told which it is; there
            # is no longer a tick for that.
            prefer_llm=_narrate,
            max_entities=llm_ent, budget_chars=llm_chars, max_output_tokens=llm_out,
            detail="explicit", max_identities=llm_ident)
        # ADVISORY analyst pass — incident-grouping + grounded hypotheses. Stored
        # SEPARATELY from the deterministic findings; fed prior operator dispositions.
        # The advisory is the SECOND model call in this branch. An automatic fuse
        # must skip it for the same reason it skips the narrative — and skipping
        # it keeps any advisory the operator already had, rather than replacing
        # a real one with an empty deterministic stand-in.
        if allow_llm:
            analysis = llm_sim.analyze(gv, window=window, min_severity=min_sev, run_id=case_id,
                                       dispositions=d.get("dispositions") or None,
                                       max_entities=llm_ent, budget_chars=llm_chars,
                                       max_output_tokens=llm_out, mask=mask,
                                       max_identities=llm_ident)
        else:
            analysis = d.get("analysis") or {}
        report_members = list(members)   # report now reflects exactly these members
        report_dirty = False             # report freshly generated → up to date
    # customer-confirmation checklist — generate once (preserve operator decisions on
    # re-fuse). GENERATED here, but WRITTEN after the bulk patch below via
    # _mutate_list_field — see the note there for why it may not ride along in the patch.
    # `allow_llm` GUARDS THIS TOO, and it did not, which made a documented
    # promise false. The automatic fuse passes allow_llm=False precisely so a
    # graph rebuild is fast, free and cannot be held up by a provider — the
    # report and advisory above both honour it. This call did not, so every
    # first automatic fuse of a case made a model call anyway, and with a model
    # configured but unreachable it blocked the fuse for up to
    # ONLINE_LLM_TIMEOUT_SECONDS (600) while holding the case's fuse lock, so
    # data landing behind it got FusionBusy and retried. Measured on a live
    # appliance: an automatic fuse sat in "LLM · calling OpenAI (Subscription)"
    # and never reached "Refusion complete".
    #
    # The checklist is not lost by skipping it here: regenerate_report generates
    # one when the case has none, and the automatic path calls that immediately
    # after the fuse (services/fusion/autofuse.py). Every model call now happens
    # in the narration step, which is the one allowed to be slow and billed.
    fresh_checklist = None
    if allow_llm and not d.get("disposition_checklist"):
        try:
            fresh_checklist = llm_sim.generate_disposition_checklist(
                gv, window=window, min_severity=min_sev, run_id=case_id, mask=mask)
        except Exception:
            fresh_checklist = None

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
        _li = _llm_identity_budget(d)
        # report_detail=explicit adds per-event evidence to the payload, so the token
        # A/B + Rescan price must reflect the SELECTED mode (re-priced on Refusion).
        distilled = render.distilled(g, window=window, min_severity=min_sev,
                                     max_entities=_le, budget_chars=_lc,
                                     detail="explicit", max_identities=_li)
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
          f"{len(pruned.get('entities') or {}):,} entities → sidecar", pct=95)
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
                                  # What this graph was built under. The next
                                  # automatic fuse may only ADD to it if these
                                  # still match — see _graph_filter_signature.
                                  "graph_filter_sig": _sig_full,
                                  # members the LLM report/chat narrative reflects
                                  # (updated only when the report is rebuilt, not on
                                  # a plain graph re-fuse) — drives the "rescan to
                                  # refresh the report" hint.
                                  "report_run_ids": report_members,
                                  # True when this fuse left the report frozen (triage/
                                  # disposition re-fuse) → UI shows "report not up to date".
                                  "report_dirty": report_dirty})
    # Checklist: fill ONLY when the case still has none, and do it under the run lock.
    # It used to ride along in the bulk patch above, computed from a snapshot read at
    # the TOP of this function — ~33 s earlier on a real case (9 hosts / 18.7k
    # entities). disposition_checklist is the one details field both the fuse and the
    # operator write (decide_checklist_item), so a customer decision recorded while the
    # fuse was running was silently overwritten by the stale pre-fuse copy. Reading and
    # writing in one locked read-modify-write closes that window; `cur or ...` keeps the
    # "generate once, never clobber operator decisions" rule that was always intended.
    if fresh_checklist:
        _mutate_list_field(case_id, "disposition_checklist",
                           lambda cur: cur or fresh_checklist)
    log_case_event(case_id, "Refusion complete", "success",
                   f"triggered by {trig} — saved to database — {len(g.entities):,} entities, "
                   f"{len(g.relationships):,} links, {len(g.findings):,} findings "
                   f"across {len(members)} run(s) · 100%",
                   pct=100)
    return g


def _ever_fused(case_id, d) -> bool:
    """Has a graph ever been built for this case?

    Cheap by construction — this runs on every case GET, which the UI now polls,
    so it must never deserialize the graph (they reach 39 MB). `graph_counts` is
    precomputed at fuse time; `fusion_graph` covers cases fused before the sidecar
    split; the sidecar file itself covers the rest. Any one of them means a fuse
    has happened at least once.
    """
    if d.get("graph_counts") or d.get("fusion_graph"):
        return True
    try:
        return os.path.exists(_graph_path(case_id))
    except Exception:
        return False


def stale_member_runs(case_id, d=None) -> list:
    """Terminal member runs NOT reflected in the persisted graph — i.e. data
    added since the last fuse. "Terminal" includes cancelled/failed: a stopped
    collection still holds what it collected, and fusion ingests it. Returns their run_ids (empty when the graph is
    current, or when a LEGACY graph predates `fused_run_ids` tracking, so we never
    cry 'stale' on one). Cheap: no graph build, just a member scan."""
    d = d or get_case(case_id) or {}
    fused = d.get("fused_run_ids")
    if fused is None:
        # An absent key meant two very different things, and treating both as
        # "nothing to report" silenced the case that needs the prompt MOST: a
        # brand-new case has never been fused, so the key is absent, so importing
        # an offline collector into it reported 0 new runs and raised no banner.
        # Observed on case 'twe' — the operator had to know to click Refusion.
        #   - never fused (no graph at all) -> EVERY completed member run is new;
        #   - legacy (a graph exists, but we cannot know which runs built it)
        #     -> stay silent, which is what the original guard was for.
        if _ever_fused(case_id, d):
            return []
        fused = []
    fused = set(fused)
    # Only runs whose MODULE is enabled count as "new data to fold in" — a disabled
    # module's runs can never enter the graph via Refusion, so flagging them as
    # stale is misleading (the banner would prompt a Refusion that does nothing).
    ws = _ws()
    out = []
    for r in ws.get_automation_runs_by_case(case_id):
        # TERMINAL, not "completed". A run the operator STOPPED still holds
        # everything Velociraptor handed over before the stop, and
        # _members_for_case (above) applies no status filter at all — so that
        # data fuses perfectly well the moment someone presses Refusion. Only
        # this staleness check disagreed, and because auto-fuse re-checks it
        # before firing, a cancelled run's data could never reach the graph on
        # its own: pressing Fetch persisted the rows, dropped the run from
        # fused_run_ids, armed auto-fuse — and auto-fuse then saw nothing
        # stale and did nothing. Reproduced on case 'test2': a cancelled
        # collection holding 481,253 rows (446 entities) reported 0 stale runs
        # and 0 entities until Refusion was pressed by hand.
        #
        # Excluding running/pending is the real intent — those are still
        # collecting, and folding them in mid-flight would fuse a partial
        # snapshot. That is exactly the guard the recollect route already uses
        # (dashboard_routes.py: "still collecting — wait for it to finish").
        if (_run_passes_gate(r, d)
                and r.get("status") not in ("running", "pending")
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
        # Same distinction as stale_member_runs: no report written yet means every
        # member run is unreflected, whereas a legacy case that HAS a report simply
        # cannot say which runs it came from.
        if d.get("report_md"):
            return []
        rep = []
    rep = set(rep)
    ws = _ws()
    out = []
    for r in ws.get_automation_runs_by_case(case_id):
        # Terminal, not completed-only — must match what fuse_case actually
        # ingests, or a cancelled run's data lands in the graph while the
        # report never learns it is behind.
        if (_run_passes_gate(r, d)   # only enabled-module runs can reach the report
                and r.get("status") not in ("running", "pending")
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
        fuse_case(case_id, trigger=TRIGGER_AUTOMATIC_RUN_LANDED)
    except FusionBusy:
        # The case was already fusing, so this run's data will be picked up by the
        # fuse in flight or by the next one. Recorded rather than swallowed: a bare
        # `except: pass` here meant an automatic fuse could vanish with the graph
        # left stale, no banner and nothing in the log to explain it.
        log_case_event(case_id, "Refusion skipped", "warning",
                       f"automatic re-fuse for run {run_id} skipped — the case was "
                       f"already fusing; its data lands on the next Refusion")
    except Exception as e:
        log_case_event(case_id, "Refusion failed", "error",
                       f"automatic re-fuse for run {run_id} failed — "
                       f"{type(e).__name__}: {e}")


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
    # Evidence span (EARLIEST->latest finding time) as a real number, so the UI /
    # an altitude read doesn't need to deserialize the graph. Uses finding ts, not
    # the 10-year default window. keys.to_utc_dt parses the mixed ts formats.
    ts = sorted(t for t in ((f or {}).get("ts") for f in findings) if t)
    span_days = None
    if ts:
        lo, hi = keys.to_utc_dt(ts[0]), keys.to_utc_dt(ts[-1])
        if lo and hi:
            span_days = (hi - lo).days
    return {"hosts": sum(1 for e in ents.values() if (e or {}).get("type") == "asset"),
            "entities": len(ents),
            "links": len(fg.get("relationships") or []),
            "findings": len(findings),
            "cross_host": sum(1 for f in findings if (f or {}).get("kind") == "cross_host"),
            "evidence_first": ts[0] if ts else None,
            "evidence_last": ts[-1] if ts else None,
            "evidence_span_days": span_days}


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
    """Merge a patch into the case details without disturbing its status.

    Raises if the write did not actually land. This whole chain used to swallow
    failure end to end: save_workflow() catches every exception, prints to
    stdout and returns False, and update_run_status() dropped that bool -- so a
    database that could not be written was indistinguishable from a successful
    save. The report path logged "Report saved" over a write that never
    happened, and the report_generating flag-clear silently no-op'd on the way
    out too, leaving the operator on a spinner that could never finish, with no
    error anywhere in the UI. A persist that did not persist is an exception.
    """
    ws = _ws()
    cur = (ws.get_automation_run(case_id) or {}).get("status") or "completed"
    if not ws.update_run_status(case_id, cur, details=patch):
        raise RuntimeError(f"case details write failed for {case_id} "
                           f"(fields: {', '.join(sorted(patch))})")


def _mutate_list_field(case_id, field, mutator) -> None:
    """Atomically read-modify-write a single list-valued details field:
    `mutator(current_list) -> new_list`.

    Fixes the lost-update race in every identity-link / checklist /
    timeline-validation / manual-timeline-event decision: the old pattern
    was `d = get_case(case_id)` (unlocked read) -> compute a new list from
    that snapshot -> `_merge_case_details(case_id, {field: new_list})`
    (blind overwrite). Two concurrent writers — two operators triaging at
    once, or the watch_and_fuse background re-fuse thread saving in
    between — silently clobber each other because the second writer's
    "new list" was computed from a snapshot that didn't include the
    first writer's change yet. mutate_run_details() does the read +
    mutate + write under ONE lock, so this can't happen."""
    def _apply(details):
        details[field] = mutator(details.get(field) or [])
    if not _ws().mutate_run_details(case_id, _apply):
        raise RuntimeError(f"case details write failed for {case_id} (field: {field})")


def _now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")


# ---- Case Analysis activity log (audit trail — the case has no workflow row) ----
_CASE_LOG_CAP = 500


def log_case_event(case_id, action, status="ok", detail="", detail_max=500, **meta) -> None:
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
                 "status": lvl, "detail": str(detail)[:max(1, int(detail_max or 500))]}
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


_REPORT_GEN_LOCKS: dict = {}
_REPORT_GEN_LOCKS_GUARD = threading.Lock()


def _report_gen_lock(case_id):
    with _REPORT_GEN_LOCKS_GUARD:
        return _REPORT_GEN_LOCKS.setdefault(case_id, threading.Lock())


class ReportGenerationBusy(Exception):
    """A report is already being generated for this case."""


# A generation older than this is treated as dead no matter what the flag says.
# The worst legitimate run is three sequential model calls (narrative, advisory,
# checklist) at ONLINE_LLM_TIMEOUT_SECONDS each -- 30 minutes -- so this leaves
# real headroom above anything that could still be alive.
REPORT_GEN_STALE_SECONDS = 45 * 60


def report_generation_active(d) -> bool:
    """Is a report genuinely being generated for this case right now?

    Reads the flag but does not trust it on its own. `report_generating` is
    cleared by the worker's `finally`, which is itself a database write -- and
    when that write is the thing failing, the flag sticks True with nothing left
    running that could ever clear it, so the operator watches a spinner that can
    never finish and no error appears anywhere. The process-start sweep in
    case_routes only catches the restart case; this catches the rest.
    """
    if not d.get("report_generating"):
        return False
    started = d.get("report_generating_started_at")
    if not started:
        return True                       # in flight, and no stamp to judge it by
    from datetime import datetime, timezone
    try:
        ts = datetime.fromisoformat(str(started))
    except Exception:                     # noqa: BLE001 — unparseable stamp
        return True
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - ts).total_seconds() < REPORT_GEN_STALE_SECONDS


def regenerate_report_async(case_id, *, audience=None, use_llm=False) -> dict:
    """Kick off regenerate_report() on a background thread and return immediately.

    An LLM-narrated report used to be one synchronous request start to finish.
    A real case is TWO sequential LLM calls (narrative, then advisory) over the
    full distilled graph — measured live at 227K combined tokens through a
    subscription-CLI provider, 5 minutes 29 seconds end to end. nginx's /api/
    proxy_read_timeout is 300 seconds: the browser's connection dies right as
    the FIRST call was finishing, while the backend keeps working underneath,
    invisible to the operator. That run finished and saved correctly — the
    operator just had no way to know it, and was staring at a page that looked
    stuck for the back half of it.

    The deterministic path (use_llm=False) is fast — no LLM call — and stays
    synchronous; only the path that can genuinely run for minutes is
    backgrounded. Raises ReportGenerationBusy if one is already running for
    this case (the operator clicking Regenerate twice must not start two
    concurrent LLM calls against the same report).
    """
    if not get_case(case_id):
        raise ValueError("case not found")

    # The lock is taken for BOTH paths, not just the slow one. It used to guard
    # only the LLM branch, on the reasoning that a deterministic render is fast
    # enough not to collide with anything. That held while every regeneration was
    # a click; it stopped holding when the automatic fuse started regenerating on
    # its own, because a deterministic auto-report and an operator's LLM report
    # can now be in flight at the same moment — and the loser of that race
    # overwrites a real narrative with a template, or the reverse.
    lock = _report_gen_lock(case_id)
    if not lock.acquire(blocking=False):
        raise ReportGenerationBusy("a report is already being generated for this case")

    if not use_llm:
        # Fast (no model call) — answer from this thread rather than paying for a
        # thread and a poll cycle to deliver a render that has already finished.
        try:
            return regenerate_report(case_id, audience=audience, use_llm=False)
        finally:
            lock.release()

    started = _now_iso()
    try:
        _merge_case_details(case_id, {"report_generating": True,
                                      "report_generating_started_at": started,
                                      "report_phase": "narrative",
                                      "report_phase_started_at": started})
    except Exception:
        lock.release()
        raise

    def _worker():
        try:
            regenerate_report(case_id, audience=audience, use_llm=True)
        except Exception:
            pass                     # already logged to the case activity log
        finally:
            try:
                _merge_case_details(case_id, {"report_generating": False,
                                              "report_generating_started_at": None,
                                              "report_phase": None,
                                              "report_phase_started_at": None})
            except Exception:
                pass
            lock.release()

    threading.Thread(target=_worker, daemon=True,
                     name=f"report-gen-{case_id}").start()
    return {"status": "started", "case_id": case_id, "started_at": started}


def regenerate_report(case_id, *, audience=None, use_llm=False) -> dict:
    """Re-narrate report + advisory from the STORED graph (no re-collect/re-fuse),
    applying the case's audience + master_prompt + Timeline triage. Deterministic by
    default (free); pass use_llm=True (the 'Regenerate report' button) for the premium
    LLM narrative — the only place report generation spends tokens.

    There is no longer an "Air-gap analysis" tick overriding use_llm. On a box
    with no model, no key or no route the call fails and falls back to the
    deterministic report with a line saying which of those it was — so pressing
    Regenerate on an air-gapped appliance costs one connection timeout and then
    tells the operator the truth, rather than silently producing the same template
    a tick would have produced while looking like it did nothing.
    """
    if audience:
        set_branding(case_id, audience=audience)
    d = get_case(case_id)
    g = load_graph(case_id)
    window = d.get("time_window") or None
    min_sev = d.get("min_severity", "informational")
    gv = _filter_graph_by_hosts(g, d.get("excluded_hosts"))
    # masking (customer-facing): anonymize host/user/ip in the LLM payload + narrative.
    # This is the LLM path (use_llm=True) where masking actually matters — the first-scan
    # path is deterministic. Build it here too so anonymization is applied on Rescan.
    mask = None
    mk = d.get("masking") or {}
    if mk.get("enabled"):
        try:
            from services.data_anonymizer import DataAnonymizer
            mask = DataAnonymizer(custom_patterns=mk.get("patterns") or [])
        except Exception:
            mask = None
    llm_ent, llm_chars = _llm_payload_budget(d)
    llm_ident = _llm_identity_budget(d)
    llm_out = _effective_output_cap(d)
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
            master_prompt=d.get("master_prompt"), mask=mask,
            dispositions=d.get("dispositions") or None,
            validations=d.get("timeline_validations") or None,
            prefer_llm=use_llm, max_entities=llm_ent, budget_chars=llm_chars,
            max_output_tokens=llm_out, detail="explicit", max_identities=llm_ident)
        if use_llm and model:
            # generate_report swallows a failed call and returns the DETERMINISTIC
            # report with a "_Live LLM unavailable (...)_" line appended. Logging
            # success unconditionally here therefore reported "LLM responded" for
            # a call that 402'd, on a report the model never wrote — and the char
            # count reinforced it, since it measures the whole markdown including
            # the deterministic tables, not the narrative. Read the marker back
            # instead of assuming.
            _marker = "_Live LLM unavailable"
            if _marker in (report or ""):
                _why = (report.split(_marker, 1)[1].split("\n", 1)[0] or "").strip(" (_.")
                log_case_event(case_id, "Report · LLM call failed", "warning",
                               f"{_why or 'provider unavailable'} — deterministic report used instead")
            else:
                log_case_event(case_id, "Report · LLM responded", "success",
                               f"narrative generated ({len(report):,} chars)")
    except Exception as e:
        log_case_event(case_id, "Report generation", "error", f"LLM/render failed: {e}")
        raise

    # Persist the narrative THE MOMENT IT EXISTS, before anything else can fail.
    # It used to live only in this local variable until a single write at the very
    # end of the function -- behind two more LLM calls that can each run for
    # minutes, raise, or be killed with the container. A model would return a
    # complete report and the operator would never see it: the activity log's last
    # line was "LLM responded", and nothing was ever written. Everything after this
    # point is enrichment and is allowed to fail without costing the narrative.
    # The phase flips here, on the write that makes the narrative durable -- no
    # extra database round trip. Until this existed the case view could only see
    # "generating", so a finished, saved, readable report and a first model call
    # still in flight looked identical: the banner went on saying "sending case
    # data to the model" for the entire advisory, and the operator reasonably
    # read that as stuck.
    # The phase gets its OWN clock. Reporting the job's total elapsed beside
    # "now generating the advisory" reads as the advisory's elapsed and is wrong
    # by however long the narrative took -- measured on a live case: the banner
    # said the advisory was 13 minutes in when it had been running for two.
    _narrative_patch = {"report_md": report, "report_dirty": False,
                        "report_phase": "advisory",
                        "report_phase_started_at": _now_iso()}
    # Stamp WHICH runs this narrative describes. It was clearing report_dirty
    # and leaving report_run_ids alone, so report_stale_runs went on counting
    # every member as unreflected forever -- a report regenerated one second ago
    # still read as behind its own data. The graph this was rendered from is the
    # one load_graph returned at the top of this function, so its fused member
    # set is exactly what the report reflects. Absent on a legacy case (no
    # tracking) -- leave it absent rather than inventing one.
    _fused = d.get("fused_run_ids")
    if _fused is not None:
        _narrative_patch["report_run_ids"] = list(_fused)
    try:
        _merge_case_details(case_id, _narrative_patch)
        log_case_event(case_id, "Report saved", "success",
                       f"narrative written to the database ({len(report or ''):,} chars)")
    except Exception as e:
        log_case_event(case_id, "Report save", "error", f"database write failed: {e}")
        raise

    # Advisory: the SECOND model call, and the one that used to run in total
    # silence -- no entry line, no exit line, so a long advisory looked
    # indistinguishable from a hung backend. It is enrichment: a failure here
    # leaves the already-saved narrative (and any previously stored advisory)
    # exactly as it is, rather than aborting the whole regeneration.
    analysis = None
    if use_llm and model:
        log_case_event(case_id, "Advisory · sending request to the LLM", "info",
                       f"model {model} ({provider})")
    try:
        analysis = llm_sim.analyze(gv, window=window, min_severity=min_sev, run_id=case_id,
                                   dispositions=d.get("dispositions") or None,
                                   max_entities=llm_ent, budget_chars=llm_chars,
                                   max_output_tokens=llm_out, mask=mask,
                                   max_identities=llm_ident)
        log_case_event(
            case_id, "Advisory · complete", "success",
            f"{len((analysis or {}).get('incident_groups') or []):,} incident group(s), "
            f"{len((analysis or {}).get('hypotheses') or []):,} hypothesis(es)")
    except Exception as e:                       # noqa: BLE001
        log_case_event(case_id, "Advisory", "warning",
                       f"could not be generated ({type(e).__name__}: {e}); "
                       f"the report is unaffected")
    # The customer-confirmation checklist moved here from fuse_case, which
    # generated it regardless of allow_llm and so made every first automatic
    # fuse a billed, blockable call. This is the narration step — the one that is
    # allowed to be slow and to spend tokens — and it runs immediately after an
    # automatic fuse, so a case still gets a checklist without the graph rebuild
    # waiting on one. Generated once and never regenerated: it carries the
    # operator's decisions.
    if not d.get("disposition_checklist"):
        if use_llm and model:
            log_case_event(case_id, "Checklist · sending request to the LLM", "info",
                           f"model {model} ({provider})")
        try:
            fresh = llm_sim.generate_disposition_checklist(
                gv, window=window, min_severity=min_sev, run_id=case_id, mask=mask)
            if fresh:
                _mutate_list_field(case_id, "disposition_checklist",
                                   lambda cur: cur or fresh)
                log_case_event(case_id, "Checklist · complete", "success",
                               f"{len(fresh):,} item(s) generated")
        except Exception as e:                       # noqa: BLE001
            log_case_event(case_id, "Checklist", "warning",
                           f"could not be generated ({type(e).__name__}); "
                           f"the report is unaffected")
    # The narrative is already durable (saved above); only the advisory is
    # outstanding. `analysis is None` means the advisory pass failed and was
    # logged as a warning -- keep whatever advisory the case already had rather
    # than blanking it.
    if analysis is not None:
        try:
            _merge_case_details(case_id, {"analysis": analysis})
            log_case_event(case_id, "Advisory saved", "success",
                           "advisory written to the database")
        except Exception as e:
            log_case_event(case_id, "Advisory save", "error", f"database write failed: {e}")
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
                        customer_name=d.get("customer_name", ""),
                        include_workflows=False)   # operator: not needed in case reports
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
    "customer_logo_b64": "Customer logo", "report_detail": "Report detail",
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
        start = tw.get("start")
        if not start:
            # The 'from' bound is never empty — a concrete lower bound keeps the
            # window reproducible and timezone-safe. Fall back to 10 years before
            # creation. ('until' may be cleared to mean open-ended.)
            start = _default_window(_case_created_dt(case_id))["start"]
        patch["time_window"] = {"start": start, "end": tw.get("end")}
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
    if "auto_fuse" in cfg:                 # fold newly-landed runs into the graph by
                                           # itself, after a quiet period. NEVER calls
                                           # the model and never redraws anyone's view —
                                           # the narrative still waits for a Rescan.
        patch["auto_fuse"] = bool(cfg.get("auto_fuse"))
        if not patch["auto_fuse"]:
            try:                           # drop any armed timer immediately, so
                from . import autofuse     # unticking takes effect now, not in a minute
                autofuse.cancel(case_id)
            except Exception:
                pass
    if "max_identities" in cfg:            # identity rows in the LLM payload — a
                                           # ceiling INSIDE max_entities, not a separate
                                           # budget (see _llm_identity_budget); empty/0
                                           # means "tied to the Entity limit" (unset).
        try:
            v = cfg["max_identities"]
            patch["max_identities"] = max(0, int(v)) if v not in (None, "") else None
        except (TypeError, ValueError):
            pass
    # LOCKED platform-wide (operator can't change; UI shows them fixed/disabled):
    #   - chat ALWAYS sends full context — host-resolution mode makes chat robotic.
    #   - the report is ALWAYS explicit (real cmdline / path / hash per finding).
    #   - the payload budget is ALWAYS derived from the selected model's real
    #     context window — see _llm_payload_budget for why this stopped being a
    #     choice. A stored False on an existing case is overridden here.
    #   - the output cap is ALWAYS the selected model's max. The old per-case
    #     field capped at 64000 in the UI while models allow far more, so its
    #     only reachable effect was TRUNCATING a report mid-sentence. A cap is a
    #     ceiling, not a target: the model stops when the report is done, so
    #     removing it does not spend more, it just stops cutting reports short.
    #     A stored value on an existing case is cleared here.
    # Enforced here so no request can override, and again at every read site below.
    patch["chat_send_full_context"] = True
    patch["report_detail"] = "explicit"
    patch["llm_use_full_context"] = True
    patch["llm_max_output_tokens"] = None
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


def rescan(case_id, cfg=None, trigger=None) -> dict:
    """THE config-driven action: persist the rail's variables then re-correlate +
    regenerate. Replaces the bare re-fuse for the UI. Rescan is an explicit rebuild,
    so it DOES refresh the report (deterministically — reflecting the new masking /
    host-exclusion / severity); the premium LLM narrative is the Regenerate button."""
    if cfg:
        set_analysis_config(case_id, cfg)
    # Rebuild via the flag, NOT by blanking report_md first. Blanking happened
    # outside the fuse lock, so when the case was already fusing the FusionBusy
    # below left the report erased with nothing to regenerate it -- an operator
    # clicking Refusion while a fuse ran lost the narrative and got an error.
    # Reproduced on a live case: the report went from 75,402 chars to 0.
    g = fuse_case(case_id, force_report=True,
                  trigger=trigger or TRIGGER_MANUAL_REFUSION)
    # A manual Refusion is the operator's way back in after an automatic one was
    # killed mid-flight (see autofuse's crash-loop breaker). It got here, so the
    # case is fuseable — let the automatic path resume.
    _merge_case_details(case_id, {"auto_fuse_incomplete": False})
    return {"entities": len(g.entities), "relationships": len(g.relationships),
            "findings": len(g.findings),
            "cross_host_findings": sum(1 for f in g.findings if f.kind == "cross_host")}


# ---- Cross-infrastructure identity correlation (Identities tab) ----
# Human decisions persist in case details ('identity_links') and are RE-APPLIED on every
# fuse — never deleted by re-fusion, exactly like timeline_validations/dispositions. Only
# AUTO (non-human) links are recomputed each fuse; a stored human decision always wins.

def _identity_decisions(d) -> dict:
    """Stored analyst decisions keyed by stable link id (confirm/decline + manual)."""
    return {r["id"]: r for r in (d.get("identity_links") or []) if isinstance(r, dict) and r.get("id")}


def _apply_identity_links(g, d, log=None) -> None:
    """Add identity edges (same_identity / operates) to the fused graph: auto candidates
    (unless the analyst declined them) + human-confirmed + manual. Best-effort — a failure
    here must NEVER break the fuse (the whole feature is optional)."""
    try:
        from . import identities as _idf
        from .schema import Relationship
        decisions = _identity_decisions(d)

        def _add(a, b, kind, conf, reason, origin):
            if a in g.entities and b in g.entities:
                g.relate(Relationship(a, b, kind, sources=["identity"],
                                      attrs={"identity_link": True, "origin": origin,
                                             "confidence": conf, "reason": reason,
                                             "link_id": _idf.link_id(a, b, kind)}))
                return 1
            return 0

        applied, seen = 0, set()
        for c in (_idf.compute_candidates(g) or []):
            rec = decisions.get(c["id"])
            if rec and rec.get("decision") == "declined":
                continue                              # analyst said no — persists
            if (rec and rec.get("decision") == "confirmed") or c["auto"]:
                origin = ("manual" if rec and rec.get("origin") == "manual"
                          else "human" if rec else "auto")
                applied += _add(c["a_id"], c["b_id"], c["kind"], c["score"], c["reason"], origin)
                seen.add(c["id"])
        # confirmed/manual links the candidate pass didn't surface this fuse
        for r in decisions.values():
            if (r.get("decision") == "confirmed" and r["id"] not in seen
                    and r.get("a_id") and r.get("b_id")):
                applied += _add(r["a_id"], r["b_id"], r.get("kind", "same_identity"),
                                r.get("confidence", 1.0), r.get("reason", "analyst-confirmed"),
                                r.get("origin", "human"))
        if log and applied:
            log(f"Identity · applied {applied} link(s)", "info")
    except Exception as e:  # noqa: BLE001 — optional feature, never break a fuse
        if log:
            log(f"Identity correlation skipped: {e}", "warning")




def _refuse_after_identity(case_id) -> None:
    """F3 fix: an identity decision (link/group/split/undo/manual) now takes effect
    IMMEDIATELY — re-fuse with TRIGGER_IDENTITY so the merged/split identities show
    without waiting for the next unrelated fuse. Mirrors set_disposition. Best-effort
    and fully isolated: a re-fuse hiccup never fails the decision that was persisted."""
    try:
        fuse_case(case_id, trigger=TRIGGER_IDENTITY)
    except Exception as e:  # noqa: BLE001
        log_case_event(case_id, "Identity · re-fuse deferred", "warning", str(e)[:120])


def decide_identity_group(case_id, members, decision) -> dict:
    """Confirm/decline a whole grouped relationship (all its member links at once).
    Persists per-member so it survives re-fusion like any other decision."""
    d = get_case(case_id)
    if not d:
        return {"error": "not found"}
    decision = decision if decision in ("confirmed", "declined") else "confirmed"
    n = 0

    def _mutate(links):
        existing = {r["id"]: r for r in links if r.get("id")}
        nonlocal n
        for m in (members or []):
            if not m.get("id"):
                continue
            rec = {"id": m["id"], "decision": decision, "origin": "human"}
            for k in ("a_id", "b_id", "kind"):
                if m.get(k):
                    rec[k] = m[k]
            existing[m["id"]] = rec
            n += 1
        return list(existing.values())

    _mutate_list_field(case_id, "identity_links", _mutate)
    log_case_event(case_id, "Identity · group decision", "info", f"{n} link(s) → {decision}")
    _refuse_after_identity(case_id)
    return {"decision": decision, "count": n}


def split_account(case_id, account_id) -> dict:
    """Analyst removes an account from its resolved person ('not this person') — it
    becomes its own identity. Persisted; survives re-fusion."""
    d = get_case(case_id)
    if not d:
        return {"error": "not found"}
    if not account_id:
        return {"error": "account_id required"}
    lid = "split:" + account_id

    def _mutate(links):
        kept = [r for r in links if r.get("id") != lid]
        kept.append({"id": lid, "kind": "split", "account_id": account_id,
                     "decision": "split", "origin": "human"})
        return kept

    _mutate_list_field(case_id, "identity_links", _mutate)
    log_case_event(case_id, "Identity · account removed", "info", f"{account_id} split out")
    _refuse_after_identity(case_id)
    return {"id": lid}


def exclude_host(case_id, name, host_id) -> dict:
    """Analyst removes a host from a person's operated-hosts (wrong name match). Persisted."""
    d = get_case(case_id)
    if not d:
        return {"error": "not found"}
    if not name or not host_id:
        return {"error": "name and host_id required"}
    lid = f"hostexcl:{name}:{host_id}"

    def _mutate(links):
        kept = [r for r in links if r.get("id") != lid]
        kept.append({"id": lid, "kind": "host_exclude", "name": name, "host_id": host_id,
                     "decision": "exclude", "origin": "human"})
        return kept

    _mutate_list_field(case_id, "identity_links", _mutate)
    log_case_event(case_id, "Identity · host removed", "info", f"{host_id} removed from {name}")
    return {"id": lid}


def undo_identity_decision(case_id, decision_id) -> dict:
    """Remove any stored identity decision (merge / split / host-exclude / declined) — undo."""
    d = get_case(case_id)
    if not d:
        return {"error": "not found"}
    _mutate_list_field(case_id, "identity_links",
                       lambda links: [r for r in links if r.get("id") != decision_id])
    log_case_event(case_id, "Identity · undo", "info", str(decision_id))
    _refuse_after_identity(case_id)
    return {"removed": decision_id}


def identity_view(case_id) -> dict:
    """The Identities tab model — a unified IDENTITY PAGE (like UEBA/identity platforms):
    one card per resolved person (their accounts across AWS/Azure/Endpoint + the hosts
    they operate), resolved deterministically by name. Fuzzy/uncertain cross-name links
    surface as small per-identity SUGGESTIONS to confirm — not a candidate queue, and no
    global manual-link form. Best-effort: any failure returns an empty, non-breaking view."""
    d = get_case(case_id)
    if not d:
        return {"error": "not found"}
    try:
        from . import identities as _idf
        g = load_graph(case_id)
        buckets = _idf.case_buckets(g)
        cands = _idf.compute_candidates(g)
    except Exception as e:  # noqa: BLE001
        return {"case_id": case_id, "buckets": [], "multi_infra": False, "identities": [],
                "counts": {"identities": 0, "suggestions": 0}, "error": str(e)}
    decisions = _identity_decisions(d)
    _nz = _idf._norm_user

    def _dec(c):
        return decisions.get(c["id"], {}).get("decision")

    # fuzzy cross-name same-identity candidates (exact-name matches are already ONE card)
    fuzzy = [c for c in cands
             if c["kind"] == "same_identity" and _nz(c["a_label"]) != _nz(c["b_label"])]
    # MERGE (fold two people into one card) when: analyst CONFIRMED, OR the candidate is
    # evidence-corroborated (auto) and NOT analyst-declined. Name-only candidates are left
    # as suggestions. Everything is persisted / reversible.
    merges = [(c["a_id"], c["b_id"], c.get("score", 1.0)) for c in fuzzy
              if _dec(c) == "confirmed" or (c.get("auto") and _dec(c) != "declined")]
    splits = {r["account_id"] for r in decisions.values()
              if r.get("kind") == "split" and r.get("account_id")}
    hexcl = {(r["name"], r["host_id"]) for r in decisions.values()
             if r.get("kind") == "host_exclude" and r.get("name") and r.get("host_id")}
    idents = _idf.resolve_identities(g, merges=merges, splits=splits, host_excludes=hexcl)
    acct_card = {}
    for it in idents:
        it["suggestions"] = []
        it["merged_from"] = []
        for a in it["accounts"]:
            acct_card[a["id"]] = it

    # record HOW each merged card was formed (transparency + a reversible "Separate")
    mf: dict = {}
    for c in fuzzy:
        dec = _dec(c)
        if dec == "declined" or not (dec == "confirmed" or c.get("auto")):
            continue
        card = acct_card.get(c["a_id"]) or acct_card.get(c["b_id"])
        if not card:
            continue
        pk = (id(card), frozenset((_nz(c["a_label"]), _nz(c["b_label"]))))
        e = mf.setdefault(pk, {"card": card, "names": sorted({_nz(c["a_label"]), _nz(c["b_label"])}),
                               "reason": c.get("reason", ""), "score": c.get("score", 1.0),
                               "auto": bool(c.get("auto") and dec != "confirmed"), "members": []})
        e["members"].append({"id": c["id"], "a_id": c["a_id"], "b_id": c["b_id"], "kind": "same_identity"})
    for e in mf.values():
        e["card"]["merged_from"].append({"names": e["names"], "reason": e["reason"], "score": e["score"],
                                         "auto": e["auto"], "members": e["members"]})

    # PENDING fuzzy suggestions (NOT corroborated, NOT decided), grouped per identity pair
    pairs: dict = {}
    for c in fuzzy:
        if c.get("auto") or _dec(c):                    # corroborated -> already merged; decided -> done
            continue
        ca, cb = acct_card.get(c["a_id"]), acct_card.get(c["b_id"])
        if not ca or not cb or ca is cb:
            continue
        pk = frozenset((ca["key"], cb["key"]))
        e = pairs.setdefault(pk, {"cards": (ca, cb), "members": [], "reason": c["reason"],
                                  "score": c["score"], "ambiguous": c.get("ambiguous", False)})
        e["members"].append({"id": c["id"], "a_id": c["a_id"], "b_id": c["b_id"],
                             "kind": "same_identity"})
        e["score"] = max(e["score"], c["score"])
        e["ambiguous"] = e["ambiguous"] or c.get("ambiguous", False)
    for e in pairs.values():
        ca, cb = e["cards"]
        for src, dst in ((ca, cb), (cb, ca)):
            src["suggestions"].append({
                "id": e["members"][0]["id"], "other": dst["name"], "reason": e["reason"],
                "score": e["score"], "ambiguous": e["ambiguous"], "members": e["members"]})
    # people with a suggestion / more infrastructures / accounts first
    idents.sort(key=lambda it: (-len(it.get("suggestions") or []), -len(it["buckets"]),
                                -len(it["accounts"]), it["key"]))
    total_sug = sum(len(it["suggestions"]) for it in idents)
    # staleness: FUSEABLE member runs not yet folded into the graph this tab reads.
    try:
        fused = set(d.get("fused_run_ids") or [])
        stale = sum(1 for r in _ws().get_automation_runs_by_case(case_id)
                    if r.get("run_id") not in fused and _run_passes_gate(r, d))
    except Exception:  # noqa: BLE001
        stale = 0
    return {"case_id": case_id, "buckets": buckets, "multi_infra": len(buckets) >= 2,
            "identities": idents, "stale": stale,
            "counts": {"identities": len(idents), "suggestions": total_sug}}


def decide_identity_link(case_id, link_id, decision, *, a_id=None, b_id=None,
                         kind=None, reason=None) -> dict:
    """Persist an analyst confirm/decline. Survives re-fusion (stored in case details)."""
    d = get_case(case_id)
    if not d:
        return {"error": "not found"}
    decision = decision if decision in ("confirmed", "declined") else "confirmed"
    rec = {"id": link_id, "decision": decision, "origin": "human"}
    for k, v in (("a_id", a_id), ("b_id", b_id), ("kind", kind), ("reason", reason)):
        if v:
            rec[k] = v

    def _mutate(links):
        kept = [r for r in links if r.get("id") != link_id]
        kept.append(rec)
        return kept

    _mutate_list_field(case_id, "identity_links", _mutate)
    log_case_event(case_id, "Identity · decision", "info", f"{link_id} → {decision}")
    _refuse_after_identity(case_id)
    return {"id": link_id, "decision": decision}


def add_manual_identity_link(case_id, a_id, b_id, kind="same_identity") -> dict:
    """Analyst manually links two entities. Persisted + applied on every fuse."""
    d = get_case(case_id)
    if not d:
        return {"error": "not found"}
    if not a_id or not b_id or a_id == b_id:
        return {"error": "two distinct entities required"}
    kind = kind if kind in ("same_identity", "operates") else "same_identity"
    from . import identities as _idf
    lid = _idf.link_id(a_id, b_id, kind)

    def _mutate(links):
        kept = [r for r in links if r.get("id") != lid]
        kept.append({"id": lid, "decision": "confirmed", "origin": "manual",
                    "a_id": a_id, "b_id": b_id, "kind": kind, "reason": "manual link"})
        return kept

    _mutate_list_field(case_id, "identity_links", _mutate)
    log_case_event(case_id, "Identity · manual link", "info", f"{a_id} ⇄ {b_id} ({kind})")
    _refuse_after_identity(case_id)
    return {"id": lid, "decision": "confirmed"}


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
    decision = "accept" if decision == "accept" else "decline"
    new_status = "accepted" if decision == "accept" else "declined"
    found = {}

    def _mutate(items):
        item = next((x for x in items if x.get("id") == item_id), None)
        if item:
            item["status"] = new_status
            found["item"] = item
        return items

    _mutate_list_field(case_id, "disposition_checklist", _mutate)
    item = found.get("item")
    if not item:
        return {"error": "checklist item not found"}
    if decision == "accept" and item.get("finding_id"):
        # benign confirmation -> disposition + re-fuse. The re-fuse no longer rewrites the
        # checklist (it only fills an empty one), so this decision cannot be clobbered by it.
        set_disposition(case_id, item["finding_id"], verdict="benign",
                        attribution="customer",
                        reason=f"customer-confirmed benign: {item.get('question', '')}",
                        scope="case", trigger=TRIGGER_CHECKLIST)
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

    def _mutate(vals):
        kept = [v for v in vals if v.get("finding_id") != finding_id]
        if status != "pending":
            kept.append({"finding_id": finding_id, "status": status, "notes": notes,
                        "watermark": wm})
        return kept

    _mutate_list_field(case_id, "timeline_validations", _mutate)

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
    _mutate_list_field(case_id, "manual_timeline_events", lambda evs: list(evs) + [row])
    log_case_event(case_id, "Timeline · manual event added", "info",
                   f"{row['title']} @ {row['ts'] or 'no ts'} on {row['host']}")
    return row


def delete_manual_timeline_event(case_id, event_id) -> dict:
    _mutate_list_field(case_id, "manual_timeline_events",
                       lambda evs: [e for e in evs if e.get("finding_id") != event_id])
    log_case_event(case_id, "Timeline · manual event deleted", "info", event_id)
    return {"event_id": event_id, "deleted": True}


def _set_manual_event_status(case_id, event_id, status, notes="") -> dict:
    found = {}

    def _mutate(evs):
        hit = next((e for e in evs if e.get("finding_id") == event_id), None)
        if hit:
            hit["status"] = status
            if notes:
                hit["notes"] = notes
            found["hit"] = hit
        return evs

    _mutate_list_field(case_id, "manual_timeline_events", _mutate)
    if not found.get("hit"):
        return {"error": "manual event not found"}
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


def get_finding_detail(case_id, finding_id) -> dict | None:
    """On-demand detail for ONE timeline finding — fetched only when a row is clicked,
    so the timeline table itself stays lean. Returns the finding plus its per-occurrence
    events (timestamp, matched fields, raw 'details', source-artifact row) pulled from
    the already-fused graph — no extra collection read. entity_ids are capped per finding,
    so `shown_occurrences` may be < `occ_count` for very high-volume rules."""
    d = get_case(case_id)
    if not d:
        return None
    # Manual events have no graph finding — return the stored record.
    if str(finding_id).startswith("manual:"):
        ev = next((e for e in (d.get("manual_timeline_events") or [])
                   if e.get("finding_id") == finding_id), None)
        if not ev:
            return {"error": "not found"}
        return {"finding": {"id": finding_id, "title": ev.get("title"),
                            "severity": ev.get("severity"), "manual": True,
                            "ts": ev.get("ts"), "hosts": [ev.get("host")] if ev.get("host") else [],
                            "summary": ev.get("notes") or "", "occ_count": 1,
                            "shown_occurrences": 0, "mitre": [], "sources": ["manual"]},
                "occurrences": []}
    g = load_graph(case_id)
    f = next((x for x in g.findings if x.id == finding_id), None)
    if not f:
        return {"error": "not found"}

    def _attrs(e):
        out = {}
        for k, v in (e.attrs or {}).items():
            if k == "_assets" or k.startswith("_") or k.endswith("_observations"):
                continue
            if v in (None, "", []):
                continue
            out[k] = v
        return out

    occ = []
    for eid in (f.entity_ids or []):
        e = g.entities.get(eid)
        if not e:
            continue
        occ.append({"ts": e.first_seen, "label": e.label, "type": e.type,
                    "severity": e.severity, "anomaly": e.anomaly,
                    "attrs": _attrs(e),
                    "locator": (e.evidence[0].locator if e.evidence else None)})
    occ.sort(key=lambda o: o.get("ts") or "")
    hosts = [(g.entities.get(a).label if g.entities.get(a) else a) for a in (f.asset_ids or [])]
    return {"finding": {"id": f.id, "title": f.title, "severity": f.severity,
                        "confidence": f.confidence, "summary": f.summary,
                        "occ_count": f.occ_count, "occ_latest": f.occ_latest,
                        "shown_occurrences": len(occ), "mitre": f.mitre,
                        "sources": f.sources, "hosts": hosts},
            "occurrences": occ}


# 50 exchanges (user + assistant per exchange) — see _append_msgs below.
_CHAT_HISTORY_CAP = 100


def chat_case(case_id, question) -> str:
    d = get_case(case_id)
    g = load_graph(case_id)
    # Log the ACTION only (never the message content) so the audit trail stays useful
    # without leaking case Q&A into the log.
    log_case_event(case_id, "Chat · question received", "info", f"{len(question or '')} chars")
    # FP-triage via chat is PROPOSE-then-APPLY, never apply-on-guess.
    #
    # Intent used to be decided by substring matching BEFORE the model was called,
    # in an if/else where the LLM was only the else branch. A wrong guess therefore
    # did two harmful things at once: it silently suppressed a finding, and it
    # replaced the operator's answer with a canned "Noted —". Both are unacceptable
    # when most operators are not native English speakers: "the backup server was
    # compromised" reads as a benign verdict to a keyword matcher, and no amount of
    # keyword tuning fixes a sentence written in Hebrew.
    #
    # So the matcher can no longer decide anything. The model ALWAYS answers, and a
    # detected verdict is only offered for confirmation; it is applied on the next
    # turn if — and only if — the operator says yes.
    pending = d.get("pending_disposition") or None
    if pending:
        if llm_sim.is_affirmative(question):
            log_case_event(case_id, "Chat · disposition confirmed", "info",
                           f"{pending.get('label')} → {pending.get('verdict')} "
                           f"({pending.get('attribution')})")
            set_disposition(case_id, pending["target"], verdict=pending["verdict"],
                            attribution=pending["attribution"],
                            reason=pending.get("reason", ""),
                            scope=pending.get("scope", "case"))
            _set_pending_disposition(case_id, None)
            return (f"Marked **{pending['label']}** as {pending['verdict']} "
                    f"({pending['attribution']}). It is suppressed from active findings "
                    f"and no longer drives host risk; the case was re-fused. "
                    f"Say 'environment' to suppress it fleet-wide.")
        if llm_sim.is_negative(question):
            log_case_event(case_id, "Chat · disposition declined", "info",
                           str(pending.get("label"))[:80])
            _set_pending_disposition(case_id, None)
            return (f"Kept **{pending['label']}** as-is — nothing was changed.")
        # anything else: the offer simply lapses, the question is answered normally
        _set_pending_disposition(case_id, None)

    proposal = llm_sim.detect_disposition(g, question)
    model, provider, _m = _configured_fusion_model()
    log_case_event(case_id, "Chat · sending to LLM", "info",
                   f"model {model} ({provider})" if model else "no model configured")
    # masking (customer-facing): same anonymization generate_report()/analyze()
    # apply — chat sends the FULL graph every turn (full_context=True below),
    # so without this it bypassed masking entirely even when the case had it
    # enabled, leaking real hostnames/usernames/IPs to the LLM.
    mask = None
    mk = d.get("masking") or {}
    if mk.get("enabled"):
        try:
            from services.data_anonymizer import DataAnonymizer
            mask = DataAnonymizer(custom_patterns=mk.get("patterns") or [])
        except Exception:
            mask = None
    try:
        ans = llm_sim.chat(g, question, history=d.get("chat_messages") or [],
                           window=d.get("time_window") or None,
                           min_severity=d.get("min_severity", "informational"),
                           run_id=case_id, dispositions=d.get("dispositions") or None,
                           validations=d.get("timeline_validations") or None,
                           full_context=True,   # LOCKED: chat always sends full context
                           max_output_tokens=_effective_output_cap(d),
                           require_llm=True,    # no deterministic fallback: surface real errors
                           mask=mask, max_identities=_llm_identity_budget(d))
        log_case_event(case_id, "Chat · reply generated", "success", f"{len(ans or '')} chars")
        # A detected verdict rides ALONG WITH the answer as an offer. Worst case
        # for a misread is one extra sentence the operator ignores — never a
        # blocked answer, never a silent mutation.
        if proposal:
            _set_pending_disposition(case_id, proposal)
            log_case_event(case_id, "Chat · disposition proposed", "info",
                           f"{proposal.get('label')} → {proposal.get('verdict')} "
                           f"({proposal.get('attribution')}) — awaiting confirmation")
            ans = (f"{ans}\n\n---\n_Did you mean to mark_ **{proposal['label']}** "
                   f"_as {proposal['verdict']} ({proposal['attribution']})? "
                   f"Reply_ **confirm** _to apply it. Anything else — including_ "
                   f"_'yes' — leaves the finding exactly as it is._")
    except llm_sim.LLMUnavailable as e:
        # The model couldn't be reached (missing/outdated key, no connection,
        # timeout). Tell the operator EXACTLY why — never a canned pseudo-answer.
        # Not persisted to chat history, so a retry after the fix starts clean.
        log_case_event(case_id, "Chat · LLM unavailable", "error", e.reason)
        return llm_sim.llm_error_message(e.reason)
    except Exception as e:
        log_case_event(case_id, "Chat", "error", f"LLM failed: {e}")
        raise
    def _append_msgs(details):           # atomic, so concurrent turns don't clobber
        msgs = list(details.get("chat_messages") or [])
        msgs += [{"role": "user", "content": question},
                 {"role": "assistant", "content": ans}]
        # Cap retained history: llm_sim.chat() resends the ENTIRE history
        # verbatim on every turn (no budget/truncation there, unlike the
        # graph payload) — an unbounded conversation eventually pushes the
        # prompt past the model's context window and linearly increases
        # cost/latency per turn with no warning. Keep the most recent
        # exchanges; older turns are dropped from what gets resent (the
        # trimmed history is what's persisted, matching activity_log's cap).
        details["chat_messages"] = msgs[-_CHAT_HISTORY_CAP:] if len(msgs) > _CHAT_HISTORY_CAP else msgs
    _ws().mutate_run_details(case_id, _append_msgs)
    return ans


def append_chat_exchange(case_id, question, answer):
    """Persist a Q&A produced OUTSIDE llm_sim.chat (e.g. an agentic investigation)
    into the same capped chat history, so it survives reloads like any chat turn
    and gives later chat turns the context. Same atomic append + cap as chat()."""
    def _append(details):
        msgs = list(details.get("chat_messages") or [])
        msgs += [{"role": "user", "content": question},
                 {"role": "assistant", "content": answer}]
        details["chat_messages"] = (msgs[-_CHAT_HISTORY_CAP:]
                                    if len(msgs) > _CHAT_HISTORY_CAP else msgs)
    _ws().mutate_run_details(case_id, _append)


def get_chat(case_id) -> list:
    """The persisted conversation for a case (survives page refreshes)."""
    return list((get_case(case_id) or {}).get("chat_messages") or [])


def clear_chat(case_id) -> dict:
    _merge_case_details(case_id, {"chat_messages": []})
    return {"cleared": True}
