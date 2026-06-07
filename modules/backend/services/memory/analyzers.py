"""Three memory-analysis modes that share one LLM-call helper.

Each mode pulls a different mix of evidence from VolWeb, assembles a
trimmed JSON payload that fits comfortably in the model context, and
hands it to :func:`services.agentic.analyzers.call_llm` along with
the mode-specific system prompt from :mod:`services.memory.prompts`.

The agentic ``call_llm`` is reused so the memory module gets — for
free — provider selection (Claude / OpenRouter / Ollama),
online/offline mode switching, token-usage accumulation onto the
workflow row (``record_llm_metrics``), and the timeout / decode-error
handling that already covers the cases this same model exhibited on
the agentic side. No new LLM client code in this module.

The three entry points share their input/output contract:

  * Input: ``evidence_id`` (VolWeb), ``volweb_client``, ``llm_config``
    (the standard ``frontend_config`` shape — ``call_llm`` reaches in
    for the active mode).
  * Output: ``{"report_md": str, "user_message": str, "warnings": [...]}``
    — ``report_md`` is the final markdown; ``user_message`` is the
    LLM prompt body (useful for ``--dry-run`` / engagement audit
    trails).
"""

from __future__ import annotations

import json
import sys
from typing import Any, Callable

from .defaults import (
    CURATED_PLUGINS,
    DEFAULT_MAX_ROWS_PER_PLUGIN,
    DEFAULT_MAX_YARA_HITS,
    PROMPT_BYTE_GUARD,
)
from .prompts import system_prompt_for_mode
from .volweb_client import VolWebClient, VolWebError


# The columns Vol3 emits that an analyst would never quote in a
# report — kernel pointers, internal page offsets, Wow64 booleans,
# etc. Trimmed pre-prompt to keep the LLM input tight.
_NOISE_KEYS = {
    "__id", "__page_offset", "__children", "__type_name",
    "Object", "KernelBase", "PEB", "Wow64",
}


def _trim_artefacts(artefacts: Any, max_rows: int) -> list[dict]:
    if not isinstance(artefacts, list):
        return []
    out: list[dict] = []
    for row in artefacts[:max_rows]:
        if not isinstance(row, dict):
            continue
        clean = {
            k: v for k, v in row.items()
            if k not in _NOISE_KEYS and v not in (None, "", 0)
        }
        if clean:
            out.append(clean)
    return out


def _trim_hit(h: dict) -> dict:
    """Keep the columns useful for analyst-grade attribution.

    Different Vol3 yarascan emitters use different capitalizations
    (``rule`` vs ``Rule``); we accept both.
    """
    keep = {
        "rule", "tags", "meta", "pid", "process", "task", "offset",
        "matched_strings", "strings", "identifier", "process_name", "address",
    }
    clean: dict[str, Any] = {}
    for k, v in h.items():
        if k.startswith("__"):
            continue
        if v in (None, "", []):
            continue
        if k.lower() in keep:
            clean[k] = v
    return clean or {k: v for k, v in h.items() if not k.startswith("__")}


# ---------------------------------------------------------------------------
# Plugin payload assembly (shared by plugin-only and layered)
# ---------------------------------------------------------------------------


def _build_plugin_payload(
    client: VolWebClient,
    evidence_id: int,
    *,
    plugin_filter: set[str] | None = None,
    max_rows: int = DEFAULT_MAX_ROWS_PER_PLUGIN,
) -> tuple[dict[str, list[dict]], list[str]]:
    """Pull and trim every curated plugin's artefact rows.

    Returns ``(by_plugin, warnings)``. ``by_plugin`` only contains
    plugins that actually emitted at least one usable row. ``warnings``
    flags curated plugins that ran but trimmed to zero rows — useful
    operator signal in the workflow log.
    """
    wanted = plugin_filter or set(CURATED_PLUGINS)
    by_plugin: dict[str, list[dict]] = {}
    warnings: list[str] = []
    for p in client.list_plugins(evidence_id):
        name = p.get("name") or ""
        if not p.get("results"):
            continue
        # Strict match OR short-form suffix match (catalogs sometimes
        # use ``windows.pslist.PsList`` vs ``volatility3.plugins.windows.pslist.PsList``).
        if name not in wanted and not any(
            name.endswith("." + c.rsplit(".", 1)[-1]) for c in wanted
        ):
            continue
        full = client.fetch_plugin(evidence_id, name)
        if not full:
            continue
        artefacts = full.get("artefacts") or full.get("artefact") or []
        trimmed = _trim_artefacts(artefacts, max_rows)
        if trimmed:
            by_plugin[name] = trimmed
        else:
            warnings.append(
                f"{name}: 0 rows after trim "
                f"(was {len(artefacts) if isinstance(artefacts, list) else 'n/a'})"
            )
    return by_plugin, warnings


def _build_yara_payload(
    client: VolWebClient,
    evidence_id: int,
    *,
    max_hits: int = DEFAULT_MAX_YARA_HITS,
) -> tuple[list[dict], int]:
    """Pull and trim yarascan hits for an evidence.

    Returns ``(hits, total_count)``. ``total_count`` comes from the
    history endpoint and is the authoritative count even when we cap
    the returned list at ``max_hits``.

    A scan that ran with zero active rules (fresh install pre-seeding)
    or simply matched nothing returns no history row + a 404 from
    /yarascan/results/. Both are valid "0 hits" states — we return
    ``([], 0)`` rather than letting the 404 crash the pipeline. The
    analyzer's prompt builder will then produce a clean report
    explaining that no rules were active.
    """
    from .volweb_client import VolWebError
    history = client.yarascan_history(evidence_id)
    total = int((history[0] if history else {}).get("count", 0)) if history else 0
    try:
        raw = client.yarascan_results(evidence_id, max_hits=max_hits)
    except VolWebError as e:
        # 404 / "No YARA scan found" is the expected shape when zero
        # rules were active — treat as a clean empty result.
        if "404" in str(e) or "No YARA scan" in str(e):
            return [], total
        raise
    hits = [_trim_hit(h) for h in raw if isinstance(h, dict)]
    return hits, total


# ---------------------------------------------------------------------------
# User-message builders — assemble what the LLM actually reads
# ---------------------------------------------------------------------------


def _truncate_for_guard(text: str, log: Callable[[str, str], None]) -> str:
    if len(text) > PROMPT_BYTE_GUARD:
        log(
            f"analyzer: prompt truncated to {PROMPT_BYTE_GUARD} bytes "
            f"(was {len(text):,})",
            "warning",
        )
        return text[:PROMPT_BYTE_GUARD] + "\n... [truncated at PROMPT_BYTE_GUARD] ..."
    return text


def _user_message_plugin_only(evidence_id: int, plugins: dict[str, list[dict]]) -> str:
    parts: list[str] = [
        f"Evidence ID: {evidence_id}",
        f"Curated plugins included: {', '.join(sorted(plugins.keys()))}",
        "",
        "Plugin output JSON follows (one block per plugin):",
        "",
    ]
    for name, rows in plugins.items():
        parts.append(f"### {name} ({len(rows)} rows)")
        parts.append("```json")
        parts.append(json.dumps(rows, indent=2, default=str)[:30000])
        parts.append("```")
        parts.append("")
    return "\n".join(parts)


def _user_message_yara_only(evidence_id: int, hits: list[dict], total: int) -> str:
    return "\n".join([
        f"Evidence ID: {evidence_id}",
        f"YARA hits in this scan: {total}",
        f"Hits included in this analysis: {len(hits)}",
        "",
        "YARA hits (one JSON object per hit):",
        "",
        "```json",
        json.dumps(hits, indent=2, default=str),
        "```",
    ])


def _user_message_layered(
    evidence_id: int,
    plugins: dict[str, list[dict]],
    hits: list[dict],
    total_hits: int,
) -> str:
    parts: list[str] = [
        f"Evidence ID: {evidence_id}",
        f"Tier 1 (YARA): {len(hits)} hits included (of {total_hits} total)",
        f"Tier 2 (Plugins): {', '.join(sorted(plugins.keys())) or 'none'}",
        "",
        "=== Tier 1 — YARA hits ===",
        "",
    ]
    if hits:
        parts.append("```json")
        parts.append(json.dumps(hits, indent=2, default=str))
        parts.append("```")
    else:
        parts.append("(no YARA hits — Tier 1 is empty for this evidence)")
    parts.append("")
    parts.append("=== Tier 2 — Plugin output ===")
    parts.append("")
    for name, rows in plugins.items():
        parts.append(f"### {name} ({len(rows)} rows)")
        parts.append("```json")
        parts.append(json.dumps(rows, indent=2, default=str)[:30000])
        parts.append("```")
        parts.append("")
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# LLM dispatch — single helper that delegates to the agentic shared call
# ---------------------------------------------------------------------------


def _call_llm_for_memory(
    *,
    system_prompt: str,
    user_message: str,
    llm_config: dict,
    run_id: str | None = None,
) -> str:
    """Call the shared agentic LLM helper and return its markdown.

    Imported locally so this module can be smoke-tested without the
    full agentic dependency graph (grpc, anthropic SDK, etc.) loaded.
    """
    from services.agentic.analyzers import call_llm  # local import — avoid boot ordering

    resp = call_llm(user_message, system_prompt, llm_config, run_id=run_id)
    # The agentic helper returns provider-shaped responses; the caller
    # in agentic_routes.py extracts ``.content[0].text`` for Anthropic
    # SDK and ``choices[0].message.content`` for the OpenAI/OpenRouter
    # SDK. Centralize the unpacking here so we don't repeat it for
    # each mode.
    return _extract_markdown_from_llm_response(resp)


def _extract_markdown_from_llm_response(resp: Any) -> str:
    """Unify Claude SDK + OpenAI/OpenRouter SDK + Ollama dict shapes.

    ``services.agentic.analyzers.call_llm`` ALREADY extracts the final
    markdown string for the online providers (Anthropic, OpenAI,
    OpenRouter, Gemini all return ``str``). This function only needs
    to fall back to SDK-object extraction when call_llm hands us a raw
    response object — that path exists for future provider additions
    and unit tests.
    """
    # Fast path: call_llm returned plain text directly.
    if isinstance(resp, str):
        return resp
    # Anthropic SDK: response.content is a list of content blocks.
    content = getattr(resp, "content", None)
    if isinstance(content, list) and content:
        block = content[0]
        text = getattr(block, "text", None)
        if isinstance(text, str):
            return text
        if isinstance(block, dict) and "text" in block:
            return str(block["text"])
    # OpenAI / OpenRouter SDK shape.
    choices = getattr(resp, "choices", None) or (
        resp.get("choices") if isinstance(resp, dict) else None
    )
    if choices:
        msg = getattr(choices[0], "message", None) or (
            choices[0].get("message") if isinstance(choices[0], dict) else None
        )
        if msg is not None:
            text = getattr(msg, "content", None)
            if text is None and isinstance(msg, dict):
                text = msg.get("content")
            if isinstance(text, str):
                return text
    # Ollama-style dict.
    if isinstance(resp, dict):
        msg = resp.get("message") or {}
        if isinstance(msg, dict) and isinstance(msg.get("content"), str):
            return msg["content"]
        if isinstance(resp.get("response"), str):
            return resp["response"]
    raise RuntimeError(f"unsupported LLM response shape: {type(resp).__name__}")


# ---------------------------------------------------------------------------
# Public entry points — three modes
# ---------------------------------------------------------------------------


def run_plugin_only(
    *,
    evidence_id: int,
    client: VolWebClient,
    llm_config: dict,
    run_id: str | None = None,
    logger: Callable[[str, str], None] | None = None,
    max_rows: int = DEFAULT_MAX_ROWS_PER_PLUGIN,
) -> dict:
    """Plugin-only analysis. Cheapest LLM bill of the three when YARA
    hits are absent. Best for hosts where a signature corpus would add
    no signal (e.g. zero-day or living-off-the-land suspected).
    """
    log = logger or (lambda msg, level="info": None)
    log(f"analyzer[plugin]: pulling curated plugins for evidence={evidence_id}", "info")
    plugins, warnings = _build_plugin_payload(client, evidence_id, max_rows=max_rows)
    for w in warnings:
        log(f"analyzer[plugin]: {w}", "warning")
    if not plugins:
        raise VolWebError(
            f"plugin-only analysis: no curated plugin output for evidence={evidence_id}"
        )
    user_msg = _truncate_for_guard(_user_message_plugin_only(evidence_id, plugins), log)
    md = _call_llm_for_memory(
        system_prompt=system_prompt_for_mode("plugin"),
        user_message=user_msg,
        llm_config=llm_config,
        run_id=run_id,
    )
    return {"report_md": md, "user_message": user_msg, "warnings": warnings}


def run_yara_only(
    *,
    evidence_id: int,
    client: VolWebClient,
    llm_config: dict,
    run_id: str | None = None,
    logger: Callable[[str, str], None] | None = None,
    max_hits: int = DEFAULT_MAX_YARA_HITS,
) -> dict:
    """Yarascan-only analysis. ~20× cheaper than plugin/layered on
    typical inputs; the right default for scale-out triage where you
    just want "is this host hosting known evil yes/no" before paying
    for a layered deep-analysis.
    """
    log = logger or (lambda msg, level="info": None)
    log(f"analyzer[yara]: pulling yarascan hits for evidence={evidence_id}", "info")
    hits, total = _build_yara_payload(client, evidence_id, max_hits=max_hits)
    if total == 0 and not hits:
        # Honest empty-result path: still let the LLM emit the
        # "necessary but not sufficient" disclaimer the prompt asks
        # for. Don't raise — clean attestation is itself a deliverable.
        log("analyzer[yara]: 0 hits — emitting clean-attestation report", "info")
    user_msg = _truncate_for_guard(_user_message_yara_only(evidence_id, hits, total), log)
    md = _call_llm_for_memory(
        system_prompt=system_prompt_for_mode("yara"),
        user_message=user_msg,
        llm_config=llm_config,
        run_id=run_id,
    )
    return {"report_md": md, "user_message": user_msg, "warnings": []}


def run_layered(
    *,
    evidence_id: int,
    client: VolWebClient,
    llm_config: dict,
    run_id: str | None = None,
    logger: Callable[[str, str], None] | None = None,
    max_rows: int = DEFAULT_MAX_ROWS_PER_PLUGIN,
    max_hits: int = DEFAULT_MAX_YARA_HITS,
) -> dict:
    """Default mode — both signals fed to one LLM with a tiered prompt.

    Validated in the PoC against operator-planted artifacts: the
    layered run was the only one that attributed Cobalt Strike /
    SharpHound / SafetyKatz YARA hits to the planted PID 7740 AND
    caught a late-starting svchost the other two modes missed.
    """
    log = logger or (lambda msg, level="info": None)
    log(f"analyzer[layered]: pulling both signals for evidence={evidence_id}", "info")

    plugins, warnings = _build_plugin_payload(client, evidence_id, max_rows=max_rows)
    for w in warnings:
        log(f"analyzer[layered]: {w}", "warning")

    hits, total = _build_yara_payload(client, evidence_id, max_hits=max_hits)
    log(
        f"analyzer[layered]: tier1={len(hits)}/{total} yara hits, "
        f"tier2={len(plugins)} plugins ({sum(len(r) for r in plugins.values())} rows)",
        "info",
    )

    if not plugins and not hits:
        raise VolWebError(
            f"layered analysis: both tiers empty for evidence={evidence_id}"
        )

    user_msg = _truncate_for_guard(
        _user_message_layered(evidence_id, plugins, hits, total), log
    )
    md = _call_llm_for_memory(
        system_prompt=system_prompt_for_mode("layered"),
        user_message=user_msg,
        llm_config=llm_config,
        run_id=run_id,
    )
    return {"report_md": md, "user_message": user_msg, "warnings": warnings}


# Mode dispatcher — used by the pipeline orchestrator.
_MODE_FUNCS: dict[str, Callable[..., dict]] = {
    "yara": run_yara_only,
    "plugin": run_plugin_only,
    "layered": run_layered,
}


def run(
    mode: str,
    *,
    evidence_id: int,
    client: VolWebClient,
    llm_config: dict,
    run_id: str | None = None,
    logger: Callable[[str, str], None] | None = None,
) -> dict:
    """Run the analyzer for ``mode`` against an evidence_id.

    ``mode`` is one of ``"yara"``, ``"plugin"``, ``"layered"``.
    Unknown values raise ``ValueError`` (typos in the dispatch path
    should fail loud).
    """
    fn = _MODE_FUNCS.get(mode)
    if fn is None:
        raise ValueError(f"unknown memory analysis mode: {mode!r}")
    return fn(
        evidence_id=evidence_id,
        client=client,
        llm_config=llm_config,
        run_id=run_id,
        logger=logger,
    )


__all__ = ["run", "run_yara_only", "run_plugin_only", "run_layered"]
