"""LLM engine for the fusion layer — CURRENTLY SIMULATED.

Per the operator's instruction, the real LLM API call is commented out and
the narration is produced deterministically in-code (acting as the LLM
ourselves). This is viable precisely because the fusion graph already holds
the structured findings + timeline; the LLM's only job is narration, which
here is templating + retrieval.

To switch to a real model: uncomment ``_real_llm`` below, ensure the LLM
config/API key is set, and route ``generate_report`` / ``chat`` through it.
No graph/correlation code changes — only this boundary swaps.
"""

from __future__ import annotations

import json
import re
import threading
import time

from . import render, budget, severity as sev
from .correlate import _assets_of, _host_label

# FP-triage intent detection (deterministic, grounded).
# NOTE "is the"/"was the" were removed: they appear in ordinary questions, so
# "who is the most malicious user" was read as a benign verdict, grounded on the
# word "malicious" against a finding titled "SIGMA: Malicious PowerShell ...",
# and silently suppressed that finding and re-fused the case. A question must
# never mutate the case — see the interrogative guard in detect_disposition.
_DISP_BENIGN = ("benign", "false positive", "false-positive", "ignore", "expected",
                "legitimate", "sanctioned", "is fine", "is our",
                "was our", "backup", "not malicious", "authorized", "authorised", "approved",
                "that's it", "that was it", "known good")
_DISP_MAL = ("confirmed malicious", "is malicious", "real attack", "true positive",
             "actually malicious")
# Tokens too generic to ground a disposition on. The verdict words themselves
# belong here: the word that TRIGGERS the verdict must not also be the anchor
# that grounds it, or any sentence mentioning "malicious" grounds to every
# finding with "Malicious" in its title.
_GENERIC_TITLE_TOK = {"sigma", "host", "suspicious", "activity", "detection", "coordinated",
                      "alert", "process", "service", "indicator", "account", "driver",
                      "malicious", "benign", "attack", "threat", "user", "users"}

_STRIP_CHARS = '.!?"\u2019\'` '

# Confirmation vocabulary for the propose-then-apply triage loop. Hebrew is
# included because most operators here are native Hebrew speakers who type a
# short affirmative in their own language even mid-English conversation.
# Deliberately NOT "yes"/"ok"/"sure"/"כן". The model routinely ends its answer
# with a question of its own ("What would you like to investigate next?"), so a
# bare yes is overwhelmingly likely to mean "yes, continue" rather than "yes,
# suppress that finding". Confirmation therefore requires a word nobody types by
# accident, and the offer always names it.
_AFFIRM = ("confirm", "confirmed", "confirm benign", "confirm it",
           "אשר", "אישור", "מאשר", "מאשרת")
_NEGATE = ("no", "nope", "not", "don't", "dont", "cancel", "keep it", "wrong",
           "mistake", "לא", "בטל", "טעות", "לא נכון")


def is_affirmative(msg: str) -> bool:
    """True only for an explicit, unambiguous confirmation of a triage offer.

    Strict on purpose, twice over: the reply must be SHORT (so a sentence that
    merely contains the word cannot confirm), and the vocabulary excludes every
    casual affirmative — a "yes" in this chat almost always answers the model's
    own closing question, not a suppression offer.
    """
    q = (msg or "").strip().strip(_STRIP_CHARS).lower()
    if not q or len(q) > 24:
        return False
    return any(q == a or q.startswith(a + " ") for a in _AFFIRM)


def is_negative(msg: str) -> bool:
    q = (msg or "").strip().strip(_STRIP_CHARS).lower()
    if not q or len(q) > 24:
        return False
    return any(q == n or q.startswith(n + " ") for n in _NEGATE)


# A message that ASKS something is never a triage command, however many verdict
# words it happens to contain.
_QUESTION_OPENERS = ("who", "what", "which", "where", "when", "why", "how",
                     "is there", "are there", "do i", "does ", "did ", "can ",
                     "could ", "should ", "list ", "show ", "tell me", "explain",
                     "summarize", "summarise", "describe")


def _disp_attribution(q: str) -> str:
    if "service account" in q:
        return "service_account"
    if "it admin" in q or "sysadmin" in q or " it " in q or "helpdesk" in q or "admin" in q:
        return "it_admin"
    if "employee" in q or "staff" in q or "user" in q:
        return "employee"
    if any(k in q for k in ("backup", "sanctioned", "approved tool", "our tool", "software")):
        return "sanctioned_tool"
    return "other"


def is_question(question: str) -> bool:
    q = (question or "").lower().strip().strip('"\u2019\'` ')
    return q.endswith("?") or any(q.startswith(op) for op in _QUESTION_OPENERS)


def detect_disposition(graph, question: str, verdict_hint=None):
    """If the message attributes activity as benign/IT/etc AND grounds to a real finding or
    entity, return a disposition dict; else None (caller falls back to normal chat). Grounding
    is mandatory — the same anti-hallucination discipline as the analyst pass.

    `verdict_hint` ('malicious' | 'benign' | 'none') is Jev's confident reading of the
    message, when the operator enabled it; it replaces the keyword guess, which cannot
    read Hebrew or "the backup server was compromised". Grounding, attribution and the
    confirm-to-apply step are unchanged either way."""
    q = (question or "").lower().strip().strip('"\u2019\'` ')
    # Questions are read-only by definition. Applying a disposition to one lets
    # a plain enquiry suppress a finding and re-fuse the case behind the
    # operator's back, which is exactly what "who is the most malicious user"
    # did before this guard existed.
    if is_question(question):
        return None
    if verdict_hint is not None:
        verdict = None if verdict_hint == "none" else verdict_hint
    else:
        verdict = ("malicious" if any(k in q for k in _DISP_MAL)
                   else ("benign" if any(k in q for k in _DISP_BENIGN) else None))
    if not verdict:
        return None
    scope = ("environment" if any(k in q for k in ("environment", "everywhere", "always",
                                                   "fleet", "all hosts", "every host"))
             else "case")
    target = label = None
    for f in graph.findings:                       # ground to a finding by a distinctive token
        toks = [w for w in re.findall(r"[a-z0-9]{4,}", f.title.lower())
                if w not in _GENERIC_TITLE_TOK]
        if any(t in q for t in toks):
            target, label = f.id, f.title.split(" on ")[0]
            break
    if not target:                                 # or to an entity by its label
        for e in graph.entities.values():
            if e.type in ("ioc", "account", "process", "service", "module") and e.label \
                    and len(str(e.label)) >= 4 and str(e.label).lower() in q:
                target, label = e.id, e.label
                break
    if not target:
        return None
    return {"target": target, "label": label, "verdict": verdict,
            "attribution": _disp_attribution(q), "scope": scope}

SIMULATED = True   # default; per-call mode resolves from frontend_config (see _use_real)


# ---------------------------------------------------------------------------
# Real-LLM boundary — the ONLY place the model API is touched. Enabled by simply
# CONFIGURING a model (see _use_real): the old extra `fusion_llm_mode='real'`
# opt-in is gone, and that key now only does the opposite — set it to 'simulated'
# to pin a box to the deterministic narrator. Any failure falls back to that
# narrator with a note saying which failure it was (see _classify_llm_error).
# ---------------------------------------------------------------------------
def _agentic_cfg() -> dict:
    try:
        from services.memory.pipeline import _llm_config_from_runtime
        return (_llm_config_from_runtime() or {}).get("agentic", {}) or {}
    except Exception:
        return {}


def _chat_full_context() -> bool:
    """ESCAPE HATCH (config `agentic.chat_send_full_context`, default OFF).

    When ON, the case chat SKIPS entity resolution/clarify entirely and sends the
    FULL distilled graph on every message — so no question can ever be 'blocked'
    by a clarify, at the price of much higher token cost per message (the
    question-scoped subgraph is ~20 entities/12k chars; the full graph is up to
    ~60 entities/32k chars and is re-sent every turn). Leave OFF unless an
    operator explicitly wants maximum recall over cost."""
    return bool(_agentic_cfg().get("chat_send_full_context", False))


def _use_real() -> bool:
    """Should the report/analyst narrative use a live model?

    Yes whenever one is CONFIGURED. This used to require an extra
    `fusion_llm_mode='real'` opt-in on top of configuring a model, which meant
    the default experience was the deterministic template -- an operator who set
    up a provider, a key and a model still got string-interpolated prose and no
    indication why. Configuring a model IS the opt-in.

    `fusion_llm_mode` is still honoured when explicitly set to 'simulated', so a
    box that deliberately pinned the deterministic path keeps it.

    The per-case "Air-gap analysis" tick is applied by the CALLER (store.py), not
    here: it is a property of the case being worked, not of the process.

    Reachability is NOT probed here: a pre-flight network check costs a round
    trip on every fuse and still races the real call. The call is simply made,
    and generate_report() falls back to the deterministic report with a visible
    note if the provider cannot be reached.
    """
    cfg = _agentic_cfg()
    if str(cfg.get("fusion_llm_mode", "")).lower() == "simulated":
        return False              # explicit opt-out, kept for existing boxes
    # need a usable transport: online needs an api_key (or a connected
    # subscription CLI, which has no key), offline (ollama) is self-hosted
    if str(cfg.get("llm_mode", "online")).lower() == "offline":
        return True
    online = cfg.get("online_llm") or {}
    if _subscription_ready(online.get("provider")):
        return True
    return bool(online.get("api_key"))


def _subscription_ready(provider) -> bool:
    """True iff provider is a CLI-subscription provider that is ready to use."""
    try:
        from services.agentic.analyzers import subscription_provider_ready
        return bool(subscription_provider_ready(provider))
    except Exception:  # noqa: BLE001
        return False


def _llm_available() -> bool:
    """A usable LLM transport is configured (online API key OR offline Ollama URL),
    INDEPENDENT of the fusion_llm_mode flag. The case CHAT uses this so that simply
    configuring a model turns it into a real, generic conversation — no extra toggle.
    (The per-fuse report/analyst narrative still respects _use_real for cost control.)"""
    try:
        from services.agentic.analyzers import is_llm_configured
        from services.memory.pipeline import _llm_config_from_runtime
        return bool(is_llm_configured(_llm_config_from_runtime() or {}))
    except Exception:
        return False


def _real_llm(system_prompt: str, user_message: str, *, run_id=None,
              max_output_tokens=None, reasoning_effort=None) -> str:
    """Production path. The distilled graph is KB-sized, so this is cheap. Token
    counts land on the run's llm_metrics automatically via call_llm's recorder.
    `max_output_tokens` (the case 'Output token cap') overrides the global
    agentic max_response_tokens for THIS call only — caps output cost per rescan."""
    from services.agentic.analyzers import call_llm
    from services.memory.pipeline import _llm_config_from_runtime
    cfg = _llm_config_from_runtime()
    if max_output_tokens:
        cfg = dict(cfg)
        ag = dict(cfg.get("agentic") or {})
        ag["max_response_tokens"] = int(max_output_tokens)
        cfg["agentic"] = ag
    return call_llm(user_message, system_prompt, cfg, run_id=run_id,
                    reasoning_effort=reasoning_effort)


import re as _re
_SHA256_RE = _re.compile(r"\b[a-f0-9]{64}\b")


def _ungrounded_hashes(text, src):
    """sha256 values present in the narrative but NOT in the evidence payload — the
    one unambiguous hallucination signal (unlike timestamps, which include legit
    proposed zoom-window bounds). Returns a sorted list (empty = clean)."""
    return sorted({h for h in _SHA256_RE.findall(text or "") if h not in (src or "")})


REPORT_SYSTEM_PROMPT = (
    "You are a senior DFIR consultant writing the analytical body of an incident report "
    "from a CORRELATED incident graph — evidence already fused across every host in the "
    "environment. Your job is the part correlation exists for: reconstruct ONE coherent "
    "intrusion story spanning hosts, accounts and time. A per-host list of alerts is a "
    "failure; the deterministic tables already do that.\n"
    "\n"
    "PAYLOAD (JSON). Use these keys by name:\n"
    "  assets       — hosts, each with severity.\n"
    "  findings     — each has summary, hosts[], mitre, ts, kind. A finding with "
    "kind=='cross_host' is evidence the SAME activity, account or tooling touched more "
    "than one host. These are the spine of the story, not footnotes.\n"
    "  timeline     — time-ordered events. Use real timestamps; never invent or round "
    "one that is not there.\n"
    "  top_entities — accounts/processes/IOCs with anomaly scores and flags.\n"
    "  identities   — ONE identity is ONE person, clustering that person's accounts "
    "across hosts. Attribute activity to the IDENTITY and say which host each account "
    "acted on, so 'one actor on five machines' never reads as five unrelated users.\n"
    "  host_coverage — every host once, with severity, finding_count, first/last "
    "activity and (where the name implies one) a role_hint such as 'domain "
    "controller' or 'certificate authority'.\n"
    "\n"
    "COVERAGE — read host_coverage before writing, and obey it:\n"
    "  * Every host in it must be ACCOUNTED FOR somewhere in your text. A host you "
    "judge peripheral still gets a sentence saying so and why.\n"
    "  * Rank by severity and ROLE, not by finding_count. Volume follows noisy "
    "workstations; a domain controller or certificate authority with a handful of "
    "findings outranks a workstation with dozens.\n"
    "  * role_hint is inferred from the hostname — a lead to confirm against that "
    "host's own findings, never an established fact.\n"
    "  * NAME HISTORY — host_coverage.name_history lists names a host's own logs recorded before its current name, in order. A finding with before_current_name=true happened while the machine had an EARLIER name (usually the image it was built from, or provisioning). Report such findings in a short separate paragraph, never as part of this incident or as an earlier compromise, unless the evidence itself links them to it.\n"
    "  * If the case contains certificate, Kerberos-ticket or ADCS activity "
    "ANYWHERE, explicitly check whether it reaches a certificate-authority host and "
    "state what you conclude either way. A CA drawn into that activity changes the "
    "containment answer entirely.\n"
    "\n"
    "Write these sections as clean markdown, in this order:\n"
    "\n"
    "## Executive Summary\n"
    "What happened, over what period, how many hosts, who (identity) did it, how it "
    "likely began, what the adversary was after, and where it got to. Plain business "
    "language, no jargon. Length follows the incident — do not pad, do not truncate a "
    "real story to hit a sentence count.\n"
    "\n"
    "## Critical Findings\n"
    "The findings that actually drive the verdict, most severe first — NOT all of them. "
    "For each, a bolded title then three short parts:\n"
    "  the observation — what was seen, with the exact host, account, process, path, "
    "hash and timestamp from the graph;\n"
    "  **Why it matters** — the consequence for THIS environment, not a textbook "
    "definition of the technique;\n"
    "  **Evidence** — the finding's own summary/mitre/ts values that ground it.\n"
    "Where one finding corroborates another, say so explicitly and name it.\n"
    "\n"
    "## Attack Narrative\n"
    "The intrusion as a story, in PHASES with date ranges as headings "
    "(e.g. '### Phase 1: Initial Access (May 3-7)'). Derive the phases from the "
    "timeline; do not force a fixed number. Each phase: what the adversary did, on "
    "which hosts, as which identity/accounts, with times — and how it led to the next "
    "phase. End with a short Attack Chain Summary: the single most likely path from "
    "entry to current state, and your confidence in it.\n"
    "\n"
    "## Cross-Host Correlation\n"
    "The evidence tying the hosts together — every kind=='cross_host' finding, shared "
    "accounts, reused tooling or infrastructure, and repeated timing. State what each "
    "link proves about spread (direction of movement where the timeline supports it). "
    "If the environment genuinely has no cross-host evidence, say that plainly and say "
    "what it would take to rule spread in or out.\n"
    "\n"
    "## Identities and Attribution\n"
    "Per identity that matters: which accounts they hold, which hosts they touched, "
    "what they did, and whether the behaviour reads as the legitimate owner, a "
    "compromised account, or an adversary-created one — with your reasoning.\n"
    "\n"
    "## Impact Assessment\n"
    "What this means for the organisation, not a restatement of the findings: what "
    "data or systems are exposed, whether domain-wide control is plausible, whether "
    "the adversary still has access, and what is at stake if nothing is done. Say "
    "which of these the evidence SHOWS versus what it merely permits.\n"
    "\n"
    "## Root Cause and Initial Access\n"
    "How the adversary most likely got in, with the evidence for it. If the data "
    "cannot establish it, say so plainly and name what is missing (which log, which "
    "host, which period) rather than implying a cause the evidence does not carry. "
    "An honest 'undetermined, and here is why' is worth more than a guess.\n"
    "\n"
    "## Containment and Recovery\n"
    "Three ordered lists, each item naming the specific host, account or artefact:\n"
    "  **Immediate containment** — what to do now to stop active access.\n"
    "  **Eradication** — what must be removed or rebuilt, and what cannot be "
    "trusted again (credentials, certificates, hosts requiring reimage).\n"
    "  **Investigation priorities** — the open questions in the order they should "
    "be answered, each with the specific evidence that would answer it.\n"
    "\n"
    "## Limitations\n"
    "What this assessment could NOT determine and why: gaps in coverage, hosts with "
    "no data, the severity floor excluding lower findings, activity predating the "
    "evidence. A reader must be able to tell absence of evidence from evidence of "
    "absence.\n"
    "\n"
    "DISCIPLINE\n"
    "Grade every assessment: state HIGH, MODERATE or LOW confidence and what drives "
    "it. High = multiple independent artefacts agree. Low = a single detection, or "
    "an inference across a gap. Never leave a conclusion ungraded.\n"
    "Keep OBSERVATION (in the graph) separate from INFERENCE (your analysis), and label "
    "inference as such. Cite hosts, accounts, hashes and timestamps verbatim; never "
    "When you cite a file hash, pair it with its filename: write `name.exe` "
    "(`<hash>`) — never a bare hash (the evidence supplies it as `file=<name>`). "
    "invent an entity, event, time, threat-actor name or campaign that is not in the "
    "payload. Where evidence is ambiguous (authorised admin work vs adversary), say so "
    "and give the test that would settle it rather than guessing.\n"
    "Reflect the analyst's triage: treat validated-real findings as fact, and do not "
    "dwell on ones dispositioned benign or known-to-IT beyond noting they were cleared.\n"
    "The system APPENDS deterministic tables after your text (timeline, hosts, IOCs, "
    "MITRE, recommendations) — do not reproduce them.\n"
    "No preamble. Start at '## Executive Summary'."
)

# --- ALTITUDE-ADAPTIVE report prompts (selected by render._resolve_altitude) -------
# MACRO: broad scope (many hosts / big volume / long evidence span) -> a high-level
# triage MAP — ranked candidate scenarios with confidence + zoom targets + a
# suspicious-timeframe heat-map, NOT one forced intrusion story. Validated in
# scratch_eval: 24-25 vs 13-14 over the frozen single-story prompt at 3->100 hosts,
# ~4.5x cheaper output.
REPORT_SYSTEM_PROMPT_MACRO = (
    "You are a senior DFIR consultant triaging a BROAD, correlated incident graph — "
    "many hosts and/or a long timeframe, fused across the environment. At this altitude "
    "you do NOT force one intrusion story. You give the lead analyst a high-level map: "
    "the shape of what's in scope, the few candidate scenarios worth pursuing, and "
    "exactly where to zoom in next. Write like a senior consultancy triage note — "
    "concise, high-signal, calibrated. No filler.\n"
    "\n"
    "PAYLOAD (JSON) keys: scope (host/finding counts + evidence span + altitude); assets "
    "(hosts+severity); findings (summary, hosts[], mitre, ts, kind — kind=='cross_host' "
    "means the SAME activity/account/tooling touched >1 host); timeline (time-ordered, "
    "real timestamps only); top_entities (accounts/processes/IOCs + anomaly/flags); "
    "identities (one identity = one person's accounts across hosts); host_coverage (each "
    "host once: severity, finding_count, first/last activity, role_hint — role_hint is "
    "inferred from the hostname, a lead to confirm, never an established fact).\n"
    "NAME HISTORY — host_coverage.name_history lists names a host's own logs recorded before its current name, in order. A finding with before_current_name=true happened while the machine had an EARLIER name (usually the image it was built from, or provisioning). Report such findings in a short separate paragraph, never as part of this incident or as an earlier compromise, unless the evidence itself links them to it.\n"
    "\n"
    "Write clean markdown, concise, in this order:\n"
    "\n"
    "## Assessment\n"
    "2-4 sentences: how many hosts over what period, the dominant activity, and whether "
    "this reads as ONE campaign, SEVERAL unrelated issues, or mostly benign/administrative "
    "noise. Business language. Give overall confidence (HIGH/MODERATE/LOW).\n"
    "\n"
    "## Timeframes\n"
    "The payload's `timeframes` list is the case's distinct activity windows: NUMBERED, "
    "ranked by risk, each with its window, hosts, finding count and the finding titles "
    "inside it. These windows are FIXED. Write one section per entry, in the given order "
    "and no others, each headed EXACTLY `### Timeframe N — <short name for what this "
    "window IS>` with N copied from the payload. Under each:\n"
    "  - **What happened** — 1-3 sentences on the activity in THIS window only, from the "
    "findings listed under it. Name the hosts and accounts.\n"
    "  - **Why it matters** — one line: what it would mean if confirmed.\n"
    "  - **Investigate?** — YES or NO, and the single question a focused analysis of "
    "this window should answer.\n"
    "Do NOT put dates in the heading and do NOT write a table: the deterministic "
    "timeframe table (window, hosts, counts) is inserted under this section for you. "
    "Never write a Timeframe number that is not in the payload; never merge or split "
    "windows. This is how the analyst decides where to zoom — be decisive.\n"
    "\n"
    "## Candidate Scenarios\n"
    "The 2-4 most plausible intrusion/abuse scenarios the evidence supports, highest risk "
    "first. For each: a bolded title, then\n"
    "  - **What** — the hypothesis in one line (the story it would be if true).\n"
    "  - **Where/When** — the specific hosts (or host-role cluster) and the Timeframe "
    "number(s) it lives in.\n"
    "  - **Evidence** — the findings / cross_host links / identities that suggest it, cited.\n"
    "  - **Confidence** — HIGH/MODERATE/LOW and what drives it.\n"
    "  - **Zoom** — the exact scope to narrow to (which hosts + which time window) to confirm "
    "or kill it.\n"
    "Rank by risk to the organisation, not finding volume. If the evidence genuinely shows "
    "only benign/administrative activity, say so and STOP — never manufacture scenarios.\n"
    "\n"
    "(The deterministic timeframe table is inserted under ## Timeframes for you — do "
    "NOT write a table or a 'Suspicious Timeframes' section yourself.)\n"
    "\n"
    "## Other severe findings\n"
    "Account for EVERY finding whose severity is high or above that the scenarios "
    "above did not already mention. Group them — one line per technique or per host, "
    "naming the host(s) — rather than restating each finding. If the scenarios "
    "already covered them all, write a single line saying so. This exists because a "
    "narrative built from 2-4 scenarios silently drops severe activity that does not "
    "fit those stories: measured, the scenarios alone carried 95% of critical "
    "findings but only 57% of high ones. Severity decides what belongs here — never "
    "a fixed list of techniques. Do NOT include anything below high.\n"
    "\n"
    "## Priority actions\n"
    "Two short lists, each item naming the specific host/account:\n"
    "  **Contain now** — the few steps that stop active access or protect tier-zero right "
    "now (isolate a host, disable/rotate a shared account, protect the CA/DCs), each "
    "justified by a cited finding. If nothing warrants immediate containment, say so.\n"
    "  **Investigate next** — the scenario to zoom into first, the host(s) to pull deeper "
    "(memory / timeline), and the single question that most changes the picture.\n"
    "\n"
    "DISCIPLINE\n"
    "Grade every assessment HIGH/MODERATE/LOW and what drives it. Keep OBSERVATION (in the "
    "graph) separate from INFERENCE. Cite hosts, accounts, hashes and timestamps verbatim; "
    "When you cite a file hash, pair it with its filename: write `name.exe` "
    "(`<hash>`) — never a bare hash (the evidence supplies it as `file=<name>`). "
    "never invent an entity, event, time, actor or campaign not in the payload. An honest "
    "'undetermined, and here is what's missing' beats a guess. Ground every aggregate / "
    "environment-wide claim in specific hosts + a cited finding and time; never assert broad "
    "reach without naming the evidence. This is a triage MAP, not the full report — be "
    "brief. No preamble. Start at '## Assessment'."
)

# FOCUSED: narrow scope (few hosts / short window) -> ONE explicit theory in detail,
# proportional to the evidence (not the frozen 9-section template that bloated a
# 3-host/14-finding case to 30k chars). Validated 20 vs 17 on a narrow case.
REPORT_SYSTEM_PROMPT_FOCUSED = (
    "You are a senior DFIR consultant writing the analytical body of an incident report "
    "from a CORRELATED incident graph for a CONTAINED case — few hosts, short window. "
    "Give ONE explicit, well-grounded theory of what happened, in concrete detail, and "
    "stop. This is the DEEP view — you were zoomed into a narrow scope precisely to go "
    "further than the macro triage map: reconstruct the actual sequence, do not summarise "
    "it. Length follows the evidence — go as deep as the evidence supports; still no "
    "padding. Do not restate the deterministic tables (timeline, "
    "hosts, IOCs, MITRE) — the system appends them after you.\n"
    "\n"
    "scope.findings / .entities / .identities are the case TOTALS; the matching "
    "*_shown values are how many reached you. When a *_shown is lower, you hold a "
    "SAMPLE: answer 'how many' from the TOTAL, never by counting the list you were "
    "given. top_entities is ranked by anomaly, so it is a selection regardless.\n"
    "PAYLOAD (JSON) keys: scope; assets; findings (summary, hosts[], mitre, ts, kind — "
    "kind=='cross_host' spans hosts); timeline (real timestamps only); top_entities "
    "(accounts/processes/IOCs + anomaly/flags); identities (one identity = one person's "
    "accounts across hosts); file_hashes (hash -> filename lookup; use it to name any hash you cite). host_coverage (each host once; role_hint is inferred from the "
    "hostname — a lead to confirm, never an established role).\n"
    "NAME HISTORY — host_coverage.name_history lists names a host's own logs recorded before its current name, in order. A finding with before_current_name=true happened while the machine had an EARLIER name (usually the image it was built from, or provisioning). Report such findings in a short separate paragraph, never as part of this incident or as an earlier compromise, unless the evidence itself links them to it.\n"
    "\n"
    "Write clean markdown — ONLY the sections the evidence supports, in this order:\n"
    "\n"
    "## Executive Summary\n"
    "2-5 sentences: what happened, on which hosts, as which identity, over what window, how "
    "it began and what the adversary was after. Plain language. Overall confidence "
    "(HIGH/MODERATE/LOW). End with a line of exactly this form:\n"
    "  **Risk: CRITICAL|HIGH|MEDIUM|LOW** — one clause saying what drives it.\n"
    "Choose that level from the evidence and justify it. Reserve CRITICAL for active "
    "adversary access or tier-zero compromise; do not inflate it on finding volume, and "
    "do not deflate it because the evidence is partial — state the uncertainty instead.\n"
    "\n"
    "## What happened\n"
    "The single most likely intrusion story, reconstructed STEP BY STEP in order — deeper "
    "than a candidate-scenario summary. For each step give the exact host, account, "
    "process, path, file as `name` (`hash`), and timestamp from the graph, and quote the "
    "specific command line behind it (DECODE any -EncodedCommand / base64 the evidence "
    "provides). Follow the parent->child process ancestry wherever the graph supplies it; "
    "where a link is inferred across a gap, say the gap out loud. If several hosts are in "
    "scope, walk each host's part of the sequence. Where one finding "
    "corroborates another, say so. Commit to the MOST LIKELY reading, but grade confidence "
    "HONESTLY at the decisive steps — do not inflate to HIGH without independent "
    "corroboration; a single detection, an inferred role, or an inference across a gap is "
    "MODERATE or LOW. If the evidence genuinely supports two readings (adversary vs "
    "authorised admin), name both and give the test that settles it.\n"
    "\n"
    "## Key Findings\n"
    "Every finding at high severity or above, as a structured BLOCK so the reader can "
    "scan and grep them. Order by severity (Critical first). Number F-1, F-2, F-3. "
    "Format EXACTLY — the renderer styles this shape, so the bullets and their labels "
    "are not optional:\n"
    "\n"
    "### F-N: <one-line title>\n"
    "- **Severity:** Critical / High / Medium / Low\n"
    "- **Confidence:** High / Medium / Low\n"
    "- **Detected:** ISO timestamp (or '-' when undated)\n"
    "- **Source:** the detection / SIGMA rule name behind it\n"
    "\n"
    "**Description.** One or two sentences — what was seen.\n"
    "**Evidence.** The concrete artifacts: file names as `name.exe` (`<hash>`), command "
    "lines, event IDs, accounts, hosts, timestamps. Be specific.\n"
    "**Impact.** One sentence — what the adversary gains, or what it puts at risk.\n"
    "**Recommendation.** One sentence — the remediation that would close it. Do NOT "
    "cross-reference the next-steps section from here; the citation runs one way, from "
    "the actions back to the findings.\n"
    "\n"
    "## Impact & Root Cause\n"
    "What is exposed / at risk, whether access likely persists, and how it most likely "
    "began — with the evidence, or an honest 'undetermined, missing X'.\n"
    "\n"
    "## Recommended Next Steps\n"
    "Three bulleted subsections. Each action starts with a bold label, then one sentence "
    "naming the specific host / account / artifact, then the findings it answers as "
    "`*(Responds to: F-N, F-M)*`:\n"
    "  - **Immediate (next 24 hours)** — what stops active access or protects tier-zero "
    "today. If nothing warrants it, say so plainly.\n"
    "  - **Short-term (next week)** — investigative or remediation work that benefits "
    "from a few days' planning.\n"
    "  - **Long-term (next quarter)** — structural, policy or monitoring changes this "
    "incident argues for.\n"
    "\n"
    "DISCIPLINE\n"
    "Grade every assessment HIGH/MODERATE/LOW and what drives it. Keep OBSERVATION (in the "
    "graph) separate from INFERENCE. Cite hosts/accounts/hashes/timestamps verbatim; never "
    "When you cite a file hash, pair it with its filename: write `name.exe` "
    "(`<hash>`) — never a bare hash (the evidence supplies it as `file=<name>`). "
    "invent an entity, event, time, actor or campaign not in the payload. An honest "
    "'undetermined, here is what's missing' beats a guess. OMIT any section with nothing "
    "real to say rather than padding it. No preamble. Start at '## Executive Summary'."
)
CHAT_SYSTEM_PROMPT = (
    "Never show internal identifiers or data field names: no finding ids (f_...), entity "
    "ids, watermarks, row numbers or JSON keys. Refer to a finding by what happened, "
    "when and on which host, and name the binary, path, user or command from its "
    "evidence_details when present. Write verdicts as True Positive, False Positive, "
    "Known or Pending.\n"
    "You are a senior DFIR / SOC analyst embedded in this investigation, talking with "
    "another analyst about their environment. The attached correlated incident graph "
    "(JSON: hosts, accounts, processes, IOCs, findings, cross-host links, timeline) is "
    "your evidence about the whole infrastructure.\n"
    "Answer ANY question they ask — overviews, risk ranking, the attack path, lateral "
    "movement, a specific host/account/IP, what's suspicious vs expected, what to do "
    "next. Be direct, conversational and genuinely helpful; synthesise across hosts and "
    "modules to give insight, not just lookups.\n"
    "Ground every CONCRETE claim (a host, account, hash, IP, finding) in the graph and "
    "cite it. You may reason, correlate, prioritise and recommend — just keep OBSERVATION "
    "(in the graph) distinct from INFERENCE (your analysis). Never invent hosts, accounts, "
    "hashes or events that aren't present; if the graph can't answer, say so and suggest "
    "what to collect next.\n"
    "If the payload has `resolved_focus`, the analyst named that specific host/identity — "
    "OPEN your answer by stating which one you're answering on (e.g. \"On DESKTOP-566AT85:\") "
    "so a mis-resolved name is caught, then answer scoped to it."
)

# The grounded analyst pass. Anti-hallucination discipline mirrors the agentic HARD
# RULES (FACT vs INFERENCE, cite only what's in the graph). The deterministic findings
# are authoritative; this pass is ADVISORY.

# WHY a report came out deterministic. The old tag said "Set
# agentic.fusion_llm_mode='real' to use a live model", which stopped being true
# when configuring a model became the opt-in — so an operator on a box with no
# API key was told to flip a flag that would not have helped. Worse, the tag was
# identical whether they had ticked Air-gap analysis, had no key, or had a key the
# box could not reach: three different problems, one unhelpful sentence.
#
# Reason CODES and operator-facing MESSAGES are deliberately the same vocabulary
# chat already uses — _classify_llm_error + _LLM_ERR_MESSAGES, further down this
# file. Those were hardened against real incidents (a funded-out account arriving
# as a 429 and being told to "wait a moment"; OpenRouter refusing to route a model
# under a data policy and the operator being told to check their key). Writing a
# second classifier here would have thrown all of that away — and did, briefly:
# the duplicate was silently shadowed by the real one, so the codes it returned
# never matched the ones it compared against.
_SIM_TAG_PREFIX = "\n\n---\n_Deterministic report — "

# Reasons a report cannot be narrated that are visible from CONFIG ALONE, i.e.
# before any call is attempted. Anything only a failed call can tell us
# (no_internet, invalid_key, no_credit …) comes back from _classify_llm_error.
LLM_OK = "ok"
LLM_PINNED = "pinned"
LLM_NO_MODEL = "no_model"
LLM_MISSING_KEY = "missing_key"          # same code chat uses

# Every message is a (problem, fix) PAIR, written for the operator: the problem
# in one plain sentence, then exactly what to do and where. The Analysis banner
# shows them on separate lines; chat, the report's closing note and Settings'
# Test Connection join them. tests/test_llm_status.py holds every message to
# those rules, and tests/test_air_gap_banner.py renders each one in the banner.
_LLM_CONFIG_REASONS = {
    LLM_PINNED: ("This appliance is set to never use an AI model.",
                 # Set on purpose, in config.yaml, with no UI switch: only
                 # support can undo it (clear agentic.fusion_llm_mode).
                 "Ask Support to turn AI reports back on for this appliance, then try again."),
    LLM_NO_MODEL: ("No AI model is selected.",
                   "Choose one in Settings ▸ Agentic, then try again."),
    LLM_MISSING_KEY: ("No API key is set for the AI model.",
                      "Until then, reports use the case data alone, which needs no "
                      "network. Add a key in Settings ▸ Agentic, then try again."),
}


def _llm_reason_text(code) -> tuple:
    """(reason, fix) for a code from EITHER vocabulary.

    Config-only reasons carry their own wording; everything else reuses the
    message chat already shows for that code, so an operator never sees the same
    condition described two different ways in two parts of the product.
    """
    if code in _LLM_CONFIG_REASONS:
        return _LLM_CONFIG_REASONS[code]
    return _LLM_ERR_MESSAGES.get(code) or _LLM_ERR_MESSAGES["llm_error"]


def _subscription_gap(provider):
    """For a subscription provider that is NOT ready: which step is missing
    ("cli_not_installed" / "cli_not_authenticated"). None for any other provider,
    or when that cannot be told, so the caller falls through to the usual checks."""
    try:
        from services.agentic import subscription_cli as _sub
        if not _sub.is_subscription_provider(provider):
            return None
        return "cli_not_installed" if not _sub.is_installed(provider) else "cli_not_authenticated"
    except Exception:  # noqa: BLE001
        return None


def llm_status() -> dict:
    """Can a report be narrated, and if not, WHY — in the operator's terms.

    There is no per-case "air-gap" tick any more. It was a setting nobody could
    usefully decide: on an appliance with no model configured the report came out
    deterministic whether it was ticked or not, so it read as broken. An appliance
    with no route to a provider now simply gets the deterministic report and is
    told why — which is what the tick was for.

    Deliberately does not probe the network: a pre-flight check costs a round trip
    on every fuse and still races the real call. So this answers only what
    configuration can answer; a dead route is reported by generate_report after a
    call actually fails.
    """
    cfg = _agentic_cfg()
    if str(cfg.get("fusion_llm_mode", "")).lower() == "simulated":
        code = LLM_PINNED
    elif str(cfg.get("llm_mode", "online")).lower() == "offline":
        code = LLM_OK                         # self-hosted; nothing to key or reach
    else:
        online = cfg.get("online_llm") or {}
        provider = online.get("provider")
        if _subscription_ready(provider):
            # Checked BEFORE the model name. A subscription needs no key, and a
            # blank Model field means "the plan's default" (Settings says so).
            # The model check used to come first, so a connected Codex
            # subscription with the field blank was reported as "No AI model is
            # selected" -- while _use_real() and the call itself worked fine.
            code = LLM_OK
        elif _subscription_gap(provider):
            code = _subscription_gap(provider)    # not installed / not signed in
        elif not (online.get("model") or cfg.get("model")):
            code = LLM_NO_MODEL
        elif online.get("api_key"):
            code = LLM_OK
        else:
            code = LLM_MISSING_KEY
    if code == LLM_OK:
        return {"available": True, "code": code, "reason": "", "fix": ""}
    reason, fix = _llm_reason_text(code)
    return {"available": False, "code": code, "reason": reason, "fix": fix}


# ---------------------------------------------------------------------------
# Live reachability — a THIN, cached layer over llm_status() for the Analysis
# tab. llm_status() answers "is a model/key configured" for free, from config
# alone; it deliberately never makes a network call, so a configured key that
# is dead (revoked, no credit, no route to the provider) still reads as
# "available". The Case Analysis page calls this on every navigation into the
# case and every tab switch — cheap when there is nothing to check (no
# model/key: the answer is already known), and cached per config fingerprint
# when there is, so clicking through several tabs in a few seconds does not
# turn into a stream of real provider calls.
# ---------------------------------------------------------------------------
_REACH_CACHE: dict = {}
_REACH_LOCK = threading.Lock()
_REACH_TTL = 25.0     # feels "live" on normal navigation; bounds provider cost
# The last live answer per config, kept past the TTL. Never used to SKIP a probe;
# only to stop the case payload claiming "available" for a config the provider
# rejected moments ago (see llm_status_known).
_REACH_LAST = {}


def _reach_fingerprint(cfg) -> str:
    """Identity of what WOULD be called. A saved-config change (new key, new
    model, switched provider) must bust the cache immediately — an operator
    who just fixed their key should see it on the very next tab click, not
    wait out the TTL."""
    mode = str(cfg.get("llm_mode", "online")).lower()
    on = (cfg.get("offline_llm") if mode == "offline" else cfg.get("online_llm")) or {}
    # A digest of the key, not just whether one is set. With bool() alone,
    # replacing a rejected key with a working one kept the same fingerprint, so
    # the stale "rejected" answer survived exactly the change this promises to
    # notice. The digest never leaves this process and is not the key.
    import hashlib
    key = str(on.get("api_key") or "")
    return "|".join([mode, str(on.get("provider")),
                     str(on.get("model") or cfg.get("model")),
                     hashlib.sha256(key.encode()).hexdigest()[:16] if key else "-"])


def _config_id(cfg) -> str:
    """A short, opaque id for the AI settings in use: changes whenever the mode,
    provider, model or key does. Safe to hand to the browser -- a hash of the
    fingerprint, which itself holds only a digest of the key. The Analysis tab
    keys its one automatic regeneration per case on it, so changing the settings
    earns a fresh try instead of being blocked by a failure under the old ones."""
    import hashlib
    try:
        return hashlib.sha256(_reach_fingerprint(cfg).encode()).hexdigest()[:12]
    except Exception:                                 # noqa: BLE001
        return ""


def llm_reachability() -> dict:
    """llm_status(), plus a live probe when config says a model/key ARE set.

    Returns the same {available, code, reason, fix} shape with one added key,
    `checked_live` — False when the answer came from config alone (nothing to
    probe, or a cached probe), True when a real call was just made.
    """
    status = llm_status()
    cfg = _agentic_cfg()
    if not status["available"]:
        return {**status, "checked_live": False,          # already known, for free
                "config_id": _config_id(cfg)}

    fp = _reach_fingerprint(cfg)
    now = time.time()
    with _REACH_LOCK:
        cached = _REACH_CACHE.get(fp)
        if cached and (now - cached[0]) < _REACH_TTL:
            return {**cached[1], "config_id": _config_id(cfg)}

    try:
        # No connection at all: answer in seconds. The model call below would wait
        # out the client's timeout, and meanwhile an air-gapped box went on reading
        # "The AI model is connected now" from config alone (QA TASK-12664).
        if not provider_route()["ok"]:
            raise LLMUnavailable("no_internet")
        from services.agentic.analyzers._llm import call_llm
        probe_cfg = dict(cfg)
        probe_cfg["max_response_tokens"] = 1        # one token: auth + routing, ~free
        call_llm("Reply with exactly: OK", "You are a connectivity probe.",
                {"agentic": probe_cfg})
        result = {"available": True, "code": LLM_OK, "reason": "", "fix": "",
                 "checked_live": True}
    except Exception as e:                            # noqa: BLE001 — every failure is reportable
        code = _classify_llm_error(e)
        reason, fix = _llm_reason_text(code)
        result = {"available": False, "code": code, "reason": reason, "fix": fix,
                 "checked_live": True}

    with _REACH_LOCK:
        _REACH_CACHE[fp] = (now, result)
        _REACH_LAST[fp] = result
    return {**result, "config_id": _config_id(cfg)}


# Where each online provider is reached, for provider_route(). The OpenAI-shaped
# ones come from the transport's own table so the two cannot drift apart.
_PROVIDER_HOSTS = {
    "claude": "https://api.anthropic.com",
    "openai": "https://api.openai.com",
    "gemini": "https://generativelanguage.googleapis.com",
    "codex-subscription": "https://chatgpt.com",
}
_ROUTE_TIMEOUT = 4.0


def provider_route(timeout: float = _ROUTE_TIMEOUT) -> dict:
    """Can the appliance open a connection to the configured AI provider RIGHT NOW?

    A TCP connect to the provider's host: no request, no tokens, bounded by
    `timeout` including the DNS lookup. Asked once at the start of every report
    generation, before the Log or the banner say anything about a model. On an
    air-gapped appliance the report used to announce "Sending case data to the
    model" and then wait out a connection timeout it could never win (QA
    TASK-12656: "airgapped vm, why saying llm?"). Not remembered between runs:
    the next Regenerate or Refusion asks again, so a link that comes back is used
    at once.

    Returns {ok, code, reason, fix, target}. Anything it cannot judge (a proxy in
    the environment, an unknown provider, a URL it cannot parse) is ok=True: the
    real call then decides, exactly as before this existed.
    """
    import os
    import socket
    from urllib.parse import urlparse
    ok = {"ok": True, "code": LLM_OK, "reason": "", "fix": "", "target": ""}
    try:
        cfg = _agentic_cfg()
        if str(cfg.get("llm_mode", "online")).lower() == "offline":
            url = (cfg.get("offline_llm") or {}).get("url") or "http://localhost:11434"
        else:
            if any(os.environ.get(k) for k in ("HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy")):
                return ok                    # the proxy decides the route, not us
            prov = str((cfg.get("online_llm") or {}).get("provider") or "claude")
            from services.agentic.analyzers._llm import OPENAI_COMPATIBLE_BASE_URLS as _oai
            url = _oai.get(prov) or _PROVIDER_HOSTS.get(prov)
            if not url:
                return ok
        u = urlparse(url if "://" in url else f"http://{url}")
        host = u.hostname
        port = u.port or (443 if u.scheme == "https" else 80)
        if not host:
            return ok
    except Exception:                                 # noqa: BLE001
        return ok

    result = {}

    def _connect():
        try:
            socket.create_connection((host, port), timeout=timeout).close()
            result["ok"] = True
        except Exception as e:                        # noqa: BLE001
            result["err"] = e

    # getaddrinfo has no timeout of its own; with no DNS server answering it can
    # hang for far longer than `timeout`, so the whole attempt runs on a thread.
    t = threading.Thread(target=_connect, daemon=True, name="provider-route")
    t.start()
    t.join(timeout + 0.5)
    target = f"{host}:{port}"
    if result.get("ok"):
        _forget_no_route(cfg)
        return {**ok, "target": target}
    reason, fix = _llm_reason_text("no_internet")
    res = {"ok": False, "code": "no_internet", "reason": reason, "fix": fix, "target": target}
    try:
        # So the Analysis tab's payload stops calling this config "available" --
        # and so its auto-regenerate does not fire for a route just proved dead.
        with _REACH_LOCK:
            _REACH_LAST[_reach_fingerprint(cfg)] = {
                "available": False, "code": "no_internet", "reason": reason, "fix": fix,
                "checked_live": True}
    except Exception:                                 # noqa: BLE001
        pass
    return res


def _forget_no_route(cfg) -> None:
    """A route that works again must not stay remembered as dead (a rejected key
    is a different answer and is kept)."""
    try:
        fp = _reach_fingerprint(cfg)
        with _REACH_LOCK:
            last = _REACH_LAST.get(fp)
            if last and last.get("code") in _NO_ROUTE_CODES:
                _REACH_LAST.pop(fp, None)
                _REACH_CACHE.pop(fp, None)
    except Exception:                                 # noqa: BLE001
        pass


def llm_status_known() -> dict:
    """llm_status(), corrected by the last live probe of this exact config.

    Makes no call. The case payload uses it so the Analysis tab can act at once:
    config alone says "available" for a key the provider rejected a minute ago,
    and the page would otherwise have to wait ~10s for a fresh probe to learn
    that. A config that changed has a new fingerprint and no remembered answer,
    so it reads as available until the page's own probe says otherwise.
    """
    cfg = _agentic_cfg()
    st = {**llm_status(), "config_id": _config_id(cfg)}
    if not st["available"]:
        return st
    try:
        last = _REACH_LAST.get(_reach_fingerprint(cfg))
    except Exception:                                 # noqa: BLE001
        last = None
    if last and not last.get("available"):
        return {**last, "checked_live": False, "config_id": st["config_id"]}
    return st


def _sim_tag() -> str:
    st = llm_status()
    if st["available"]:                        # narration was possible but not taken
        return _SIM_TAG_PREFIX + "the AI model was not used for this automatic report._\n"
    tail = st["reason"] + (f" {st['fix']}" if st["fix"] else "")
    return _SIM_TAG_PREFIX + tail + "_\n"


# Masking model: protect CUSTOMER-IDENTIFYING values in transit to the LLM
# provider (hosts, users, the org/AD domain, internal IPs) and REVERT them in the
# LLM's output — the operator always gets the real report back. THREAT-INTEL IOCs
# (file hashes, external/malicious domains) are deliberately kept: they're the
# attacker's infrastructure, not the customer's identity, and the LLM correlates +
# recognises them far better unmasked. Everything is derived dynamically from the
# data (the org domain is read from the accounts/FQDNs), so it works for ANY company.

# Public infra domains that may show up in a UPN — never treat these as the org domain.
_MASK_KEEP_DOMAINS = {
    "microsoft.com", "windows.com", "windowsupdate.com", "office.com",
    "office365.com", "google.com", "gmail.com", "outlook.com", "azure.com",
    "windows.net", "amazonaws.com", "cloudflare.com",
}
# Windows built-in "domains" — part of system accounts, not org-identifying.
_MASK_SKIP_DOMAINS = {
    "nt authority", "nt service", "nt virtual machine", "font driver host",
    "window manager", "azuread", "local", "localhost", "workgroup", "iis apppool",
}
# Per-FORM pseudonym prefix for an identity. The NUMBER is the identity — every
# form of the same person shares it, so USER1/UPN1/SAM1/SID1 are one identity.
_IDENT_PREFIX = {"nt": "USER", "upn": "UPN", "sam": "SAM", "sid": "SID"}

# Prepended to the LLM system prompt when masking is on, so the model can connect
# the forms of one identity by the shared number (we don't pass an alias table).
_MASK_IDENTITY_LEGEND = (
    "IDENTITY KEY (this data is anonymised): pseudonyms that share a NUMBER are the "
    "SAME identity in different forms — USER<n> = a Windows DOMAIN\\user, UPN<n> = "
    "user@domain, SAM<n> = a bare account name, SID<n> = a security identifier. So "
    "USER1, UPN1, SAM1 and SID1 are ONE and the same person; likewise Hostname<n>, "
    "Domain<n> and IP_*<n> are consistent per real value. Correlate and reason over "
    "these as if they were the real entities.\n\n"
)


def _norm_domain(d: str) -> str:
    return (d or "").strip().strip(".").lower()


# Free-text evidence scanners (explicit-detail reports surface real cmdlines/paths).
# Conservative by construction so they don't mangle benign Windows paths:
#  - IPv4 / UPN are specific enough to match directly.
#  - DOMAIN\user is only accepted when its domain root is a KNOWN org domain (so
#    'Users\Public' in a path is never mistaken for an account).
#  - UNC '\\HOST\share' yields a host (lateral-movement targets that aren't entities).
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_UPN_RE = re.compile(r"\b[A-Za-z0-9._-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_DOMUSER_RE = re.compile(r"([A-Za-z0-9][A-Za-z0-9._-]+)\\([A-Za-z0-9._$-]+)")
_UNC_RE = re.compile(r"\\\\([A-Za-z0-9][A-Za-z0-9._-]+)\\")


# Per-event char cap for the evidence free-text scan. Real cmdlines/paths carrying
# identifiers are short; anything past this is a serialized blob that only adds regex
# backtracking cost. Generous enough to cover any explicit-detail evidence the payload
# would actually surface.
_EVIDENCE_SCAN_CAP = 4000

# Generic words / OS path components that are NOT customer identity. Masking them only
# CORRUPTS the payload ("root cause" -> "SAM cause", C:\Windows -> C:\Hostname) and
# clutters the audit with wrong identities. Filtered from BOTH the host and account
# mask paths. (These leak in as bad account labels like "user"/"null" or as path
# segments the UNC/path scan mistakes for hostnames.) Match is case-insensitive.
_MASK_STOPWORDS = frozenset({
    "", "-", "n/a", "na", "null", "none", "nul", "unknown", "root", "user", "users",
    "admin", "administrator", "guest", "system", "system32", "localsystem",
    "localhost", "local", "public", "default", "defaultuser", "temp", "tmp",
    "windows", "winnt", "appdata", "programdata", "program files",
    "program files (x86)", "programfiles", "desktop", "documents", "downloads",
    "perflogs", "inetpub", "recycler", "boot",
})


def _mask_noise(lbl) -> bool:
    """A label that must NOT be masked: empty, or a generic word / OS path component
    that isn't customer-identifying (masking it over-masks the payload)."""
    return (lbl or "").strip().lower() in _MASK_STOPWORDS


def _build_mask_mapping(graph, mask):
    """Populate the anonymizer mapping from the graph's CUSTOMER-IDENTIFYING values
    (hosts, users, internal IPs, and the org/AD domain) so they can be masked before
    the LLM call and reverted after. DYNAMIC — the org domain is read from the data
    (NT DOMAIN\\user, UPN user@domain, host FQDN suffix), nothing hardcoded.

    IOC hashes + external/malicious domains are intentionally NOT masked: they're
    threat intel (the attacker's infra), not the customer's identity, and the LLM
    needs them unmasked to recognise and correlate. They're reverted-safe regardless.

    Built over the WHOLE graph (not just payload entities): an identifier can appear
    in the payload as a SUBSTRING of a finding title/summary (e.g. a username inside
    "State: User bob has admin…") without being its own payload leaf, and it still
    must be masked. _apply_mask then substitutes every mapping key across the payload
    text. Speed comes from the bounded evidence sweep below, not from skipping entities."""
    try:
        from services.data_anonymizer import SYSTEM_ACCOUNTS
    except Exception:
        SYSTEM_ACCOUNTS = set()
    rows = []
    accounts = []
    org_roots: set = set()        # known org-domain netbios roots (evidence DOMAIN\user gate)
    ident_num: dict = {}          # (user-stem, domain-root) -> identity number
    stem_nums: dict = {}          # user-stem -> {numbers} (for bare-SAM stem linking)
    nseq = [0]

    def _add_org_domain(d):
        d = _norm_domain(d)
        if (not d or len(d) < 2 or d in _MASK_SKIP_DOMAINS or d in _MASK_KEEP_DOMAINS):
            return
        org_roots.add(d.split(".", 1)[0])
        if d not in mask.mapping:
            try:                                  # reuse the anonymizer's domain pool +
                mask._get_or_create_pseudo(d, "domain")   # reverse registration
            except Exception:
                pass

    def _parts(lbl):
        if "\\" in lbl:
            return "nt", lbl.split("\\", 1)[1], lbl.split("\\", 1)[0]
        if "@" in lbl:
            return "upn", lbl.split("@", 1)[0], lbl.split("@", 1)[1]
        return "sam", lbl, ""

    def _assign_account(lbl):
        """Number each IDENTITY and mask every FORM with a typed pseudonym sharing
        that number (USER<n>/UPN<n>/SAM<n>). A bare SAM with no domain LINKS to an
        existing identity when its username uniquely matches one (so 'almogs' joins
        adatumlab\\almogs); ambiguous or unknown -> its own number."""
        form, user, dom = _parts(lbl)
        if _norm_domain(dom) in _MASK_SKIP_DOMAINS or \
                any(sa in lbl.upper() for sa in SYSTEM_ACCOUNTS):
            return                                # Windows built-in / system account
        stem = user.strip().lower()
        if stem in _MASK_STOPWORDS:
            return                                # generic word (user/null/root/...), not an identity
        root = _norm_domain(dom).split(".", 1)[0]
        if form == "sam" and not root and len(stem_nums.get(stem, set())) == 1:
            n = next(iter(stem_nums[stem]))       # unambiguous stem -> same identity
        else:
            key = (stem, root)
            if key not in ident_num:
                nseq[0] += 1
                ident_num[key] = nseq[0]
            n = ident_num[key]
        stem_nums.setdefault(stem, set()).add(n)
        mask.mapping[lbl] = f"{_IDENT_PREFIX[form]}{n}"
        mask.reverse_mapping[mask.mapping[lbl]] = lbl
        if dom:
            _add_org_domain(dom)

    for e in graph.entities.values():
        lbl = (e.label or "").strip()
        if not lbl:
            continue
        if e.type == "asset":
            if not _mask_noise(lbl):
                rows.append({"hostname": lbl})
            if "." in lbl:                        # AD FQDN -> org domain suffix
                _add_org_domain(lbl.split(".", 1)[1])
        elif e.type == "account":
            accounts.append(lbl)
        elif e.type == "netconn":
            rows.append({"ipaddress": lbl})
        elif e.type == "ioc" and (e.attrs or {}).get("ioc_kind") == "ip":
            rows.append({"ipaddress": lbl})       # IOC domains/hashes: kept (threat intel)
    # Accounts: domain'd forms FIRST (establish identities), then bare SAMs so they
    # can stem-link to an already-numbered identity.
    for lbl in accounts:
        if "\\" in lbl or "@" in lbl:
            _assign_account(lbl)
    for lbl in accounts:
        if "\\" not in lbl and "@" not in lbl:
            _assign_account(lbl)
    # Evidence free-text scan: explicit-detail reports surface real cmdlines/paths to
    # the LLM, which can carry customer identifiers that are NOT their own graph entity
    # (a lateral-movement target host in a UNC path, a DOMAIN\user inside a command).
    # Feed those tokens through the SAME identity-numbering masker so the explicit
    # payload never leaks. Runs AFTER accounts so org domains are already established.
    # PERF: the findall sweep dominates on big cases (it was ~100% of a multi-minute
    # build), so (a) cap each event's text — identifiers live in short cmdlines, long
    # blobs only add regex backtracking — and (b) dedupe identical evidence, which
    # recurs verbatim across thousands of same-type events.
    _ev_seen: set = set()
    for e in graph.entities.values():
        if e.type != "event":
            continue
        a = e.attrs or {}
        if a.get("ev_user"):
            _assign_account(str(a["ev_user"]))        # structured principal — reliable
        tip = str(a.get("ev_tgtip") or "").strip()
        if tip and _IPV4_RE.fullmatch(tip):
            rows.append({"ipaddress": tip})
        text = " ".join(str(a.get(k) or "") for k in ("ev_cmdline", "details"))
        if not text.strip():
            continue
        text = text[:_EVIDENCE_SCAN_CAP]
        if text in _ev_seen:
            continue
        _ev_seen.add(text)
        for upn in _UPN_RE.findall(text):
            _assign_account(upn)
        for dom, usr in _DOMUSER_RE.findall(text):
            if _norm_domain(dom).split(".", 1)[0] in org_roots:   # gate vs benign paths
                _assign_account(f"{dom}\\{usr}")
        for host in _UNC_RE.findall(text):
            if not _mask_noise(host):
                rows.append({"hostname": host})
        for ip in _IPV4_RE.findall(text):
            rows.append({"ipaddress": ip})
    if rows:
        try:
            mask.mask_data(rows)
        except Exception:
            pass
    # Collapse case-variant duplicates (e.g. asset 'DESKTOP-566AT85' and the local
    # account domain 'desktop-566at85' from DESKTOP-566AT85\\user) onto ONE pseudonym,
    # preferring the asset-label casing — so case-insensitive masking reverts to the
    # real value cleanly instead of producing two pseudonyms for one machine.
    asset_labels = {e.label for e in graph.entities.values()
                    if e.type == "asset" and e.label}
    groups: dict[str, list] = {}
    for orig in list(mask.mapping):
        groups.setdefault(orig.lower(), []).append(orig)
    for origs in groups.values():
        if len(origs) < 2:
            continue
        canon = next((o for o in origs if o in asset_labels), max(origs, key=len))
        cp = mask.mapping[canon]
        for o in origs:
            old = mask.mapping.get(o)
            mask.mapping[o] = cp
            if old and old != cp:
                mask.reverse_mapping.pop(old, None)
        mask.reverse_mapping[cp] = canon


# Identifier characters that are part of ONE token, so a match can't run across
# them. Dash/underscore/@/\\ are token-internal (so 'WS-01' never matches inside
# 'WS-011', 'corp' never inside 'corp_backup', and DOMAIN\\user stays whole). DOT
# and $ are intentionally NOT here: DOT acts as a label delimiter so a domain/host
# label is still masked when embedded in an FQDN ('adatumlab' in 'srv.adatumlab.local'),
# and $ as a delimiter so a machine account 'HOST$' still masks the host. Both are
# the leak-safe choice. re.escape() handles any special chars in the value itself.
# Identifier chars that bind a token (a match can't run across them): alnum + _ @ -
# keep 'WS-01' out of 'WS-011' and 'corp' out of 'corp_backup'. DOT and $ are
# delimiters (so a label is masked inside an FQDN / a machine account 'HOST$'), and
# BACKSLASH is ALSO a delimiter: a UNC host '\\HOST\share' or DOMAIN\user inside a
# cmdline must mask (DOMAIN\user keys still mask whole — longest-first runs first).
_MASK_BOUNDARY = r"A-Za-z0-9_@-"


def _mask_pattern(token: str, ignorecase: bool):
    flags = re.IGNORECASE if ignorecase else 0
    # Tolerate JSON-doubled backslashes: a key 'DOMAIN\user' must match the serialized
    # payload form 'DOMAIN\\user' too (json.dumps escapes every backslash).
    esc = re.escape(token).replace("\\\\", r"\\+")
    return re.compile(rf"(?<![{_MASK_BOUNDARY}]){esc}(?![{_MASK_BOUNDARY}])", flags)


def _apply_mask(text, mask):
    """Replace originals→pseudonyms (longest-first), CASE-INSENSITIVE and identifier-
    boundary aware (see _MASK_BOUNDARY), so lowercase/uppercase/FQDN/path variants
    are caught without matching inside a larger identifier. LLM INPUT only; no-op off."""
    if not mask:
        return text
    mapping = getattr(mask, "mapping", {}) or {}
    for orig in sorted((k for k in mapping if k), key=len, reverse=True):
        ps = mapping[orig]
        text = _mask_pattern(orig, True).sub(lambda _m, _p=ps: _p, text)
    return text


def _revert_mask(text, mask):
    """Restore real values in the LLM's RETURNED text (pseudonyms → originals),
    boundary-aware + longest-first. Masking only protected the data in transit; the
    operator always gets the real report back. No-op when off."""
    if not mask:
        return text
    rev = getattr(mask, "reverse_mapping", {}) or {}
    for ps in sorted((k for k in rev if k), key=len, reverse=True):
        orig = rev[ps]
        text = _mask_pattern(ps, False).sub(lambda _m, _o=orig: _o, text)
    return text


def _mask_audit_lines(mapping) -> str:
    """Human-readable mapping for the audit log, ONE value per line so the operator
    can scan it. Identity FORMS (NT / UPN / bare SAM of the SAME person) are grouped
    onto that identity's row; hosts / IPs / domains each get their own row.
    e.g. 'identity #1: adatumlab\\almogs = USER1, almogs@adatumlab.local = UPN1'."""
    idents: dict = {}
    others = []
    for orig, ps in (mapping or {}).items():
        m = re.match(r"^(USER|UPN|SAM|SID)(\d+)$", str(ps))
        if m:
            idents.setdefault(m.group(2), []).append(f"{orig} = {ps}")
        else:
            others.append(f"{orig} = {ps}")
    parts = [f"identity #{n}: " + ", ".join(sorted(idents[n]))
             for n in sorted(idents, key=lambda x: int(x))]
    parts += sorted(others)
    return "\n".join(parts)


def _log_mask_audit(run_id, mask, text=None):
    """Write the mask mapping to the case log BEFORE anything is sent to the LLM — an
    audit trail of exactly what was anonymised (and how to read it back). Runs ONLY
    when masking is enabled. Operator-side only.

    The mask is BUILT over the whole graph (substring safety), but most keys never
    occur in the ~payload actually sent; when ``text`` (the pre-mask payload) is given
    we report ONLY the values that truly appear in it — an accurate, non-inflated list
    of what was masked, not the whole graph's identity table."""
    if not run_id or not mask:
        return
    mapping = getattr(mask, "mapping", {}) or {}
    if text is not None:                         # report only what really appears in the payload
        mapping = {k: v for k, v in mapping.items()
                   if k and _mask_pattern(k, True).search(text)}
    if not mapping:
        return
    try:
        from .store import log_case_event
        # Override the default 500-char log-detail cap so the whole list survives
        # (it otherwise truncated all but the first handful). ~20k chars covers
        # hundreds of values; the "N value(s) masked" count flags any rare overflow.
        # One value per line (see _mask_audit_lines) for readability.
        log_case_event(run_id, "Masking · pre-LLM mapping", "info",
                       f"{len(mapping)} value(s) masked before LLM send (reverted in "
                       f"the returned report):\n{_mask_audit_lines(mapping)}",
                       detail_max=20000)
    except Exception:
        pass


PHASE_SYSTEM_PROMPT = (
    "You are a senior DFIR analyst describing ONE PHASE of a larger incident. You are "
    "given only this phase's evidence — a contiguous slice of the case — and you write "
    "only about it. Another pass writes the case-wide assessment; do not attempt it.\n"
    "\n"
    "PAYLOAD (JSON): scope (counts for THIS phase); findings (title, severity, hosts[], "
    "mitre, ts, summary); timeline; top_entities (accounts/processes/IOCs); assets. "
    "Where `scope.*_shown` is below `scope.*`, you hold a SAMPLE — cite the total, "
    "never the length of the list you were given.\n"
    "\n"
    "Return EXACTLY this markdown, nothing before or after. The two bullets come "
    "FIRST, on their own lines, because the report renders them as a labelled card:\n"
    "\n"
    "**Name:** a 3-7 word label for what this phase IS (e.g. 'Credential theft on the "
    "workstation fleet', 'Toolkit staged on ALClient01'). Not a date, not a count.\n"
    "- **Severity:** Critical / High / Medium / Low — the worst thing actually "
    "evidenced in THIS phase. Write one of those four words exactly.\n"
    "- **Confidence:** High / Medium / Low — in your reading of this phase. A single "
    "detection with no corroboration is not High.\n"
    "\n"
    "**What happened:** name the hosts, accounts, tools and times from the evidence "
    "and say what was done here, in order. Go as far as the evidence supports — "
    "decode any -EncodedCommand or base64 it gives you, follow parent->child process "
    "ancestry where present, and say out loud where a link is inferred across a gap. "
    "Do not pad, and do not stop short of what the evidence shows.\n"
    "**Why it matters:** what it would mean if confirmed, and what it puts at risk.\n"
    "**Investigate:** YES or NO, then the single question a deeper look at this phase "
    "should answer. Say NO when the evidence is thin or already conclusive, and say why "
    "in the same line. Be decisive — this is what the analyst acts on.\n"
    "\n"
    "DISCIPLINE: cite only hosts, accounts, hashes and timestamps present in the "
    "payload; never invent one. When you cite a hash, pair it with its filename. Keep "
    "OBSERVATION (in the evidence) separate from INFERENCE. Grade honestly — a single "
    "detection is not HIGH confidence. No preamble, no headings of your own."
)

SYNTHESIS_SYSTEM_PROMPT = (
    "You are a senior DFIR consultant writing the EXECUTIVE LAYER of an incident "
    "report. The case has already been split into PHASES and each analysed; you are "
    "given those phase summaries plus the case totals, not the raw evidence. Your job "
    "is what no single phase can see: the shape of the whole, and where to start.\n"
    "\n"
    "Your reader is the LEAD ANALYST who has to decide where to spend today. Name "
    "hosts, accounts and tooling directly — they know what Mimikatz is. Do not write "
    "for a boardroom.\n"
    "\n"
    "Write clean markdown, exactly these four sections, in this order:\n"
    "\n"
    "## Executive Summary\n"
    "Two or three short paragraphs. What happened, across how many hosts, over what "
    "period, as which accounts, with what tooling; what it reached that matters "
    "(domain controllers, certificate services, management infrastructure); and "
    "whether this reads as ONE campaign, SEVERAL unrelated issues, or mostly benign "
    "administrative activity. End with a line of exactly this form:\n"
    "  **Risk: CRITICAL|HIGH|MEDIUM|LOW** — one clause saying what drives it.\n"
    "Choose that level yourself from the evidence and JUSTIFY it. Reserve CRITICAL "
    "for active adversary access or tier-zero compromise; do not inflate it because "
    "the finding counts are large, and do not deflate it because the evidence is "
    "partial — say the uncertainty instead.\n"
    "\n"
    "## Key Judgements\n"
    "Three to five bullets: the things that would change what the reader does. Each "
    "is one sentence, names the specific hosts/accounts, cites the phase number(s) it "
    "rests on, and ends with a confidence in parentheses — (HIGH), (MODERATE) or "
    "(LOW). These are judgements, not a finding list: 'credentials for `srv` must be "
    "treated as compromised' is a judgement; 'mimikatz was detected' is a finding.\n"
    "\n"
    "## Where to start\n"
    "RANK EVERY PHASE you were given, best first, as a numbered list. For each: the "
    "phase number and name in bold, one line of why it earns that rank, and the "
    "single question that opening it would answer. Rank on what most changes the "
    "picture — active access, tier-zero reach, and unresolved questions outrank "
    "volume. It is correct and useful to rank a phase last and say it only "
    "corroborates what another already establishes. This section is why the report "
    "exists: commit.\n"
    "\n"
    "## Other severe findings\n"
    "The payload's `outside_phases` list is high-severity-or-above activity that NO "
    "phase above covers — it fell outside every analysed window. Account for ALL of "
    "it. GROUP it: one line per technique or per host, naming the host(s) and the "
    "count, not a restatement of each finding. If the list is empty, write a single "
    "line saying every severe finding is covered by a phase and move on. This section "
    "exists because narrating only the phases silently drops severe activity that "
    "sits between them — measured on a live case, that was 40% of the findings, "
    "including renamed AdFind, procdump and procdump64 drops that appeared nowhere in "
    "the prose. Severity decides what belongs here, never a fixed technique list.\n"
    "\n"
    "## Leads for verification\n"
    "Two to four patterns the deterministic rules did NOT produce as findings but "
    "that the phase evidence suggests — tooling used in an unusual way, a technique "
    "implied by what is present, an account behaving unlike its peers. Each is one "
    "line, names the specific hosts, and is explicitly UNCONFIRMED. Write nothing "
    "here rather than padding: if the evidence supports no such lead, say so in one "
    "line. These are for an analyst to verify, never a determination.\n"
    "\n"
    "## Recommended Next Steps\n"
    "Three bulleted subsections. Each action starts with a bold label, then one "
    "sentence, then the phase(s) it answers in parentheses — EVERY action carries a "
    "`(Phase N)`, and an action with no phase behind it does not belong here:\n"
    "  - **Immediate (next 24 hours)** — what stops active access or protects "
    "tier-zero today. If nothing warrants immediate action, say so plainly.\n"
    "  - **Short-term (next week)** — investigative or remediation work that benefits "
    "from a few days' planning.\n"
    "  - **Long-term (next quarter)** — structural, policy or monitoring changes this "
    "incident argues for.\n"
    "\n"
    "DISCIPLINE: reference only hosts, accounts and PHASE NUMBERS you were actually "
    "given — a phase number that does not exist is the one unrecoverable error here. "
    "Do not re-describe each phase; the reader has the phase sections below. Keep "
    "OBSERVATION separate from INFERENCE. An honest 'undetermined, and here is what "
    "is missing' beats a guess. No preamble. Start at '## Executive Summary'."
)


class GenerationStopped(Exception):
    """The generation this call belongs to was stopped (AI settings changed, or it
    was written off as stuck). Raised BEFORE the next model call, never after one."""


def _case_event(run_id, action, status, detail):
    """Write to the case activity log from inside the model layer. Best effort."""
    if not (isinstance(run_id, str) and run_id.startswith("case_")):
        return
    try:
        from . import store
        store.log_case_event(run_id, action, status, detail)
    except Exception:                                  # noqa: BLE001
        pass


def _note_progress(run_id):
    """Stamp that the model just answered SOMETHING. The report watchdog measures
    silence from here, so a slow broad case whose phases keep answering is never
    mistaken for a stuck one."""
    if not (isinstance(run_id, str) and run_id.startswith("case_")):
        return
    try:
        from . import store
        store._merge_case_details(run_id, {"report_last_progress_at": store._now_iso()})
    except Exception:                                  # noqa: BLE001
        pass


def _ctx_size(payload) -> str:
    """How much context a single call carries, for the case log. Tokens are the usual
    ~4-characters-per-token estimate, not the provider's count."""
    n = len(payload or "")
    return f"context {n:,} chars (~{max(1, n // 4):,} tokens)"


def analyst_context(dispositions=None, validations=None, manual_events=None, graph=None,
                    checklist=None) -> dict:
    """What the analyst has told the case, for every model call that writes about it:
    triage verdicts (False Positive / Known), Timeline validations, and the events they
    added by hand ("IT pushed a GPO at 14:05"). The segmented report used to drop all
    of it -- its phase and synthesis payloads were rebuilt without the triage -- and
    manual events reached no model at all.

    Each verdict names its finding the way the analyst sees it (title, time, hosts),
    not by internal id: given ids and watermarks, the model answered with
    "f_b69307719720 ... status: real, watermark 1|2024-05-24T17:49:46Z"."""
    by_id = {f.id: f for f in (graph.findings if graph is not None else [])}

    def _about(fid):
        f = by_id.get(fid)
        if f is None:
            return {}
        return {"finding": f.title, "time": f.ts,
                "hosts": [render._host_label(graph, a) for a in (f.asset_ids or [])]}

    out = {}
    if validations:
        out["analyst_verdicts"] = [
            {**_about(v.get("finding_id")), "verdict": v.get("status"),
             **({"notes": v["notes"]} if v.get("notes") else {})}
            for v in validations]
    if dispositions:
        out["operator_dispositions"] = [
            {**_about(x.get("target")), "verdict": x.get("verdict"),
             **{k: x[k] for k in ("attribution", "reason", "scope") if x.get(k)}}
            for x in dispositions]
    # Only items the customer has ANSWERED. A declined "is this expected?" is recorded
    # nowhere else (an accepted one also becomes a benign disposition).
    answered = [x for x in (checklist or []) if x.get("status") in ("accepted", "declined")]
    if answered:
        out["customer_confirmations"] = [
            {"question": x.get("question"),
             "answer": ("yes, expected / authorised" if x["status"] == "accepted"
                        else "no, not expected")}
            for x in answered]
    if manual_events:
        out["analyst_timeline_events"] = [
            {k: e.get(k) for k in ("ts", "host", "title", "severity", "status", "notes") if e.get(k)}
            for e in manual_events]
    return out


# A phase that failed for one of these reasons is worth asking once more: the model
# was reached and simply answered badly. A rate limit, a rejected key, no credit, no
# route or a model the provider does not offer would fail the same way again, and a
# timeout has already cost the call's whole allowance.
_PHASE_RETRYABLE = ("empty_reply", "bad_response", "provider_error", "llm_error", "timeout")
PHASE_RETRIES_DEFAULT = 1
# How long one report call may take before WE stop waiting. The provider client's
# own timeout cannot be relied on: measured live, a phase carrying 5k tokens went
# silent for 15 minutes against a 600s client timeout that never fired (the
# connection stayed open), and the run was written off as stuck with five other
# phases already answered and thrown away.
PHASE_DEADLINE_DEFAULT = 300.0
# Entity rows ONE phase call may carry. The payload budget follows the model's
# context window, so a 1M-context model let a 41-finding phase ship 2,230 entity
# rows -- 483k of its 561k chars, 86% of the call -- while every other phase on the
# same case needed under 400. It fits the context; it is simply slow, and the slow
# call is the one that hangs. Measured on that phase: 800 rows is 255k chars with
# the SAME 44 findings, and leaves the other five phases untouched.
PHASE_ENTITIES_DEFAULT = 800


def _phase_entities(me) -> int:
    """Entity rows for one phase call (AI settings key `report_phase_entities`)."""
    try:
        v = _agentic_cfg().get("report_phase_entities")
        cap = int(PHASE_ENTITIES_DEFAULT if v is None else v)
    except Exception:                                   # noqa: BLE001
        cap = PHASE_ENTITIES_DEFAULT
    return max(50, min(int(me or PHASE_ENTITIES_DEFAULT), cap))


def _phase_deadline() -> float:
    """Seconds one report call may take (AI settings key `report_call_seconds`)."""
    try:
        v = _agentic_cfg().get("report_call_seconds")
        return max(30.0, float(PHASE_DEADLINE_DEFAULT if v is None else v))
    except Exception:                                   # noqa: BLE001
        return PHASE_DEADLINE_DEFAULT


HEDGE_SECONDS_DEFAULT = 90.0


def _hedge_seconds() -> float:
    """When a call is this slow, send a SECOND copy and take whichever answers
    first (AI settings key `report_hedge_seconds`; 0 turns hedging off).

    Measured on one case, two runs, identical payloads: a 31k-char phase answered
    in 20s and then in 220s; a 104k-char phase in 179s and then in 227s. The
    provider's latency, not the payload, sets how long a report takes, and six
    parallel calls finish with the slowest one."""
    try:
        v = _agentic_cfg().get("report_hedge_seconds")
        return max(0.0, float(HEDGE_SECONDS_DEFAULT if v is None else v))
    except Exception:                                   # noqa: BLE001
        return HEDGE_SECONDS_DEFAULT


def _with_deadline(fn, seconds, what):
    """Run `fn`, hedge it if it is slow, and give up after `seconds` whatever the
    provider's client does. Abandoned calls are left to die on their own (they
    hold no lock); the first usable answer wins."""
    import concurrent.futures as _cf
    hedge = _hedge_seconds()
    pool = _cf.ThreadPoolExecutor(max_workers=2, thread_name_prefix=f"llm-{what}")
    futs = [pool.submit(fn)]
    try:
        deadline = time.time() + seconds
        while True:
            wait_for = (hedge if (hedge and len(futs) == 1) else max(0.0, deadline - time.time()))
            done, _ = _cf.wait(futs, timeout=max(0.0, min(wait_for, max(0.0, deadline - time.time()))),
                               return_when=_cf.FIRST_COMPLETED)
            for f in done:                              # first ANSWER wins; a failure
                try:                                    # does not cancel its twin
                    return f.result()
                except Exception as e:                  # noqa: BLE001
                    futs = [x for x in futs if x is not f]
                    if not futs:
                        raise
            if time.time() >= deadline:
                raise LLMUnavailable("timeout") from None
            if hedge and len(futs) == 1:
                futs.append(pool.submit(fn))            # the straggler gets a twin
    finally:
        pool.shutdown(wait=False)


def _phase_retries() -> int:
    """How many times a failed report phase is retried (AI settings key
    `report_phase_retries`, default 1, 0-3)."""
    try:
        v = _agentic_cfg().get("report_phase_retries")
        return max(0, min(3, int(PHASE_RETRIES_DEFAULT if v is None else v)))
    except Exception:                                   # noqa: BLE001
        return PHASE_RETRIES_DEFAULT


def _phase_sections(graph, zt, *, window, min_severity, me, bc, max_identities,
                    eff_detail, run_id, max_output_tokens, mask, master_prompt,
                    log=None, should_continue=None, analyst=None):
    """One LLM call PER PHASE, in parallel, each over that phase's evidence only.

    Why not one call for the whole case (what this replaces): the payload was 258K
    tokens and the model had to narrate every window plus scenarios plus actions in
    one response. Measured live, it billed 54,051 output tokens and returned NOTHING
    -- the operator got a report with no narrative in it. Per phase, 5 of 6 payloads
    are 1-3% of that (3K-10K tokens), total input across all calls is 0.89x the
    single call, and they run concurrently so wall-clock is the slowest phase.

    Failure is isolated: a phase whose call fails renders as failed and the rest of
    the report is unaffected. Returns {n: {"name", "body"} or {"error"}}.
    """
    import concurrent.futures as _cf
    from . import budget as _b

    def _one(z):
        # FILL THE WINDOW. Splitting the case into phases turned one whole-case call
        # into N independent calls -- each of which has the model's ENTIRE context
        # available to it. Inheriting the whole-case `detail` threw that away:
        # measured on a live case, five of six phases at full explicit detail were
        # under 11K tokens, against a 272K window, yet all six were sent the
        # collapsed summary. `explicit` is what carries the real command lines,
        # decoded -EncodedCommand and per-event evidence into a phase section.
        #
        # So: richest detail that FITS, decided per phase. `bc` is already the
        # per-call ceiling derived from this model's context window
        # (store._llm_payload_budget -> budget.adaptive_budget, clamped by
        # budget.transport_cap_chars), so this is model-agnostic by construction --
        # a 1M-context model takes explicit everywhere, a 128K one falls back only
        # on the phase that genuinely does not fit.
        # RICHEST DETAIL THAT FITS THIS MODEL'S WINDOW, decided per phase.
        #
        # `bc` is already the per-CALL ceiling derived from the configured model
        # (store._llm_payload_budget -> budget.adaptive_budget, clamped by
        # budget.transport_cap_chars), and a phase IS one call -- so this is
        # model-agnostic: a big-context model takes explicit everywhere, a small one
        # falls back only where it genuinely does not fit.
        #
        # Two things measured on a live 49-finding phase, both of which shaped this:
        #   * `findings_shown` is useless as a fit test -- _trim_findings never drops
        #     anything >= high, so it reads 52/52 at every budget.
        #   * when the payload is over budget the LAST-RESORT collapse dominates and
        #     explicit/summary come out within ONE character of each other, so the
        #     choice is moot there. Where there IS room, explicit costs ~23% more and
        #     buys the per-event evidence -- real command lines, decoded
        #     -EncodedCommand -- that a phase section lives on.
        _pme = _phase_entities(me)

        def _build(det):
            return render.distilled(graph, window=z["window"],
                                    min_severity=min_severity, max_entities=_pme,
                                    budget_chars=bc, detail=det,
                                    max_identities=max_identities)

        p, chosen = _build("explicit"), "explicit"
        if _b.over_budget(p, bc) and eff_detail != "explicit":
            alt = _build(eff_detail)
            if len(json.dumps(alt)) < len(json.dumps(p)):
                p, chosen = alt, eff_detail
        z["_detail"] = chosen          # reported, so a thin section is never ambiguous
        if analyst:
            p = {**p, **analyst}
        body = json.dumps(p)
        if mask:
            body = _apply_mask(body, mask)
        sys_p = PHASE_SYSTEM_PROMPT
        if master_prompt:
            sys_p = ("## OPERATOR CONTEXT — treat as ground truth:\n"
                     f"{master_prompt.strip()}\n\n---\n\n") + sys_p
        if mask:
            sys_p = _MASK_IDENTITY_LEGEND + sys_p
        # The SAME output allowance as the report, not a low per-phase cap. A phase
        # answer is short, but a reasoning model draws its thinking from this
        # allowance first: capped at 4,000 tokens, DeepSeek on OpenRouter came back
        # empty on 3 and 4 of 6 phases in two live runs, and cut one answer off at
        # 71 characters -- while the synthesis, sent with the full allowance,
        # answered both times. The cap is a ceiling, not a spend: a phase that
        # answers in 800 tokens is billed for 800.
        # A STOPPED run makes no further calls. Each call reads the AI settings at
        # the moment it is made, so a run stopped because the settings changed was
        # otherwise free to carry on against the NEW provider — measured: a retired
        # run's synthesis went to the operator's real subscription.
        if should_continue and not should_continue():
            raise GenerationStopped()
        _w = z.get("window") or {}
        _case_event(run_id, f"Report · phase {z['n']} of {_total} — sending", "info",
                    f"{_w.get('start') or '?'} → {_w.get('end') or '?'} · "
                    f"{z.get('finding_count', 0)} finding(s) · {_ctx_size(body)}")
        _t0 = time.time()
        attempt, retries = 0, _phase_retries()
        while True:
            try:
                out = _with_deadline(
                    lambda: _real_llm(sys_p, body, run_id=run_id,
                                      max_output_tokens=max_output_tokens,
                                      reasoning_effort="low"),
                    _phase_deadline(), f"phase{z['n']}")
                out = _revert_mask(out, mask)
                if not (out or "").strip():
                    raise LLMUnavailable("empty_reply")
                z["_seconds"] = round(time.time() - _t0)
                return out.strip()
            except GenerationStopped:
                raise
            except Exception as e:                       # noqa: BLE001
                code = _classify_llm_error(e)
                if (attempt >= retries or code not in _PHASE_RETRYABLE
                        or (should_continue and not should_continue())):
                    raise
                attempt += 1
                _case_event(run_id, f"Report · phase {z['n']} of {_total} — retrying", "info",
                            f"{_llm_reason_text(code)[0]} Trying again ({attempt} of {retries}).")

    phases = render.analysable(zt)
    results = {}
    if not phases:
        return results
    # EVERY phase is visible in the Log. A broad case used to show one "sending
    # request" line over five parallel calls, so when one hung there was no way to
    # tell which, or that the other four had already answered.
    _total = len(phases)
    _case_event(run_id, "Report · analysing the case phase by phase", "info",
                f"{_total} phase call(s) in parallel, then a synthesis call")
    with _cf.ThreadPoolExecutor(max_workers=min(6, len(phases))) as pool:
        futs = {pool.submit(_one, z): z for z in phases}
        for fut in _cf.as_completed(futs):
            z = futs[fut]
            try:
                text = fut.result()
                name = ""
                m = _re.search(r"\*\*Name:\*\*\s*(.+)", text)
                if m:
                    name = m.group(1).strip().strip("*").strip()
                    text = text[:m.start()] + text[m.end():]
                results[z["n"]] = {"name": name, "body": text.strip()}
                if not should_continue or should_continue():   # a stopped run's lines are not this run's
                    _case_event(run_id, f"Report · phase {z['n']} of {_total} — answered", "success",
                                f"{z.get('_seconds', '?')}s · {len(text):,} chars")
            except Exception as e:                       # noqa: BLE001
                _r, _f = _llm_reason_text(_classify_llm_error(e))
                # The reason in the operator's words (it is printed in the report), and
                # the exception itself, so a run where EVERY phase failed can fall back
                # with the provider's own reason and retry time.
                results[z["n"]] = {"error": _r + provider_retry_hint(e), "exc": e}
                if isinstance(e, GenerationStopped):
                    continue
                if not should_continue or should_continue():
                    _case_event(run_id, f"Report · phase {z['n']} of {_total} — failed", "warning",
                                f"{_r}{provider_retry_hint(e)} The other phases are unaffected.")
                if log:
                    log(f"phase {z['n']} failed: {type(e).__name__}")
            _note_progress(run_id)
    return results


def generate_report(graph, *, window=None, min_severity="informational",
                    initial_access=None, case_name="Case", run_id=None,
                    audience="both", language="en", master_prompt=None, mask=None,
                    altitude_mode="auto",
                    dispositions=None, validations=None, prefer_llm=True,
                    max_entities=None, budget_chars=None, max_output_tokens=None,
                    detail="auto", max_identities=None, grouping="time", log=None,
                    should_continue=None, manual_events=None, checklist=None) -> str:
    """Case report. Real path = LLM narrative over distilled() + deterministic
    fact tables appended verbatim. `audience` (exec/technical/both) + `language`
    tailor the narrative (reusing the engagement directive); `master_prompt` is the
    operator's "remove X / focus Y" steering, prepended as ground truth. `mask` is an
    optional DataAnonymizer — when set, the distilled LLM payload AND the rendered
    markdown are anonymized (customer-facing). `max_entities`/`budget_chars` size the
    LLM payload (the case 'LLM payload' knob); None = the default fixed budget. Falls
    back to the deterministic narrator on any failure (or when mode='simulated')."""
    me = max_entities or budget.REPORT_MAX_ENTITIES
    bc = budget_chars or budget.REPORT_BUDGET_CHARS
    # Use a real model only when asked (prefer_llm) AND one is configured. The FIRST
    # scan generates a fast, free, deterministic report (prefer_llm=False); the
    # premium LLM narrative is produced ONLY on an explicit Rescan/Regenerate
    # (regenerate_report passes prefer_llm=True). Keeps tokens fully on-demand.
    if prefer_llm and (_use_real() or _llm_available()):
        try:
            # ALTITUDE: broad scope -> a macro triage map (ranked candidate scenarios
            # + zoom targets); narrow -> one focused explicit theory. Macro also forces
            # summary detail (no per-event evidence dump at scale) — cheaper and the
            # right altitude. Validated in scratch_eval (macro 24-25 vs 13-14 broad,
            # focused-tight 20 vs 17 narrow, 3.4-4.5x cheaper output).
            altitude, _alt_reason = render._resolve_altitude(
                graph, window=window, min_severity=min_severity, mode=altitude_mode)
            # Forcing Macro means "map this anyway": relax the per-window volume floor
            # so a quiet or short case still yields phases instead of a map of nothing.
            _force_ph = (altitude == "macro" and (altitude_mode or "auto") == "macro")
            eff_detail = "summary" if altitude == "macro" else detail
            payload = render.distilled(graph, window=window, min_severity=min_severity,
                                       max_entities=me, budget_chars=bc, detail=eff_detail,
                                       max_identities=max_identities,
                                       include_timeframes=True,
                                       altitude_mode=altitude_mode)
            # give the model the analyst's triage so the narrative reflects it
            _analyst = analyst_context(dispositions, validations, manual_events, graph, checklist)
            payload.update(_analyst)
            _, _scoped_r = render.scope(graph, window=window, min_severity=min_severity)
            # MICRO for the report: critical findings and the ones the analyst confirmed.
            _crit = render.critical_details(graph, _scoped_r, also_ids=[v.get("finding_id") for v in (validations or []) if v.get("status") == "true_positive"])
            if _crit:
                payload["key_finding_details"] = _crit
            payload_str = json.dumps(payload)
            _unmasked_payload = payload_str           # keep for the grounding guard (pre-mask)
            if mask:                                  # anonymize the LLM input too
                _build_mask_mapping(graph, mask)
                _log_mask_audit(run_id, mask, payload_str)   # audit BEFORE the send; only what's in the payload
                payload_str = _apply_mask(payload_str, mask)
            # SEGMENTED PATH: a broad case is analysed phase by phase, then
            # synthesised -- instead of one call trying to narrate everything, which
            # measured live returned an empty narrative on a 258K-token payload.
            _zt, _phase_out, _mode = [], {}, (grouping or "time")
            if altitude == "macro":
                _zt = render.zoom_targets(graph, window=window,
                                          min_severity=min_severity, mode=_mode,
                                          force_phases=_force_ph)
                _phase_out = _phase_sections(
                    graph, _zt, window=window, min_severity=min_severity, me=me, bc=bc,
                    max_identities=max_identities, eff_detail=eff_detail, run_id=run_id,
                    max_output_tokens=max_output_tokens, mask=mask,
                    master_prompt=master_prompt, log=log, should_continue=should_continue,
                    analyst=_analyst)
                _analysable = render.analysable(_zt)
                _failed = [z for z in _analysable if (_phase_out.get(z["n"]) or {}).get("error")]
                if _analysable and len(_failed) == len(_analysable):
                    # Nothing was analysed: a synthesis would be written from blank
                    # phases. Measured live: all 6 phases rate-limited and the synthesis
                    # was sent anyway. Fall back to the offline report with the reason.
                    _case_event(run_id, "Report · synthesis skipped", "warning",
                                "no phase could be analysed, so the report is written "
                                "offline from the case evidence. "
                                + (_phase_out.get(_failed[0]["n"]) or {}).get("error", ""))
                    raise (_phase_out.get(_failed[0]["n"]) or {}).get("exc") or LLMUnavailable("llm_error")
                _outside = render.outside_phases(graph, _zt, window=window,
                                                 min_severity=min_severity)
                payload = {"case_totals": payload.get("scope", {}),
                           "phases": [{"n": z["n"], "window": z["window"],
                                       "hosts": z.get("host_labels") or [],
                                       "findings": z["finding_count"],
                                       "critical": z.get("critical_count", 0),
                                       **({"not_analysed": _phase_out[z["n"]]["error"]}
                                          if (_phase_out.get(z["n"]) or {}).get("error")
                                          else {"analysis": _phase_out.get(z["n"], {}).get("body", "")})}
                                      for z in render.analysable(_zt)],
                           # High+ activity NO phase covers. Without this the
                           # synthesis cannot mention it, and 40% of the case went
                           # unnarrated on a live run.
                           "outside_phases": render.outside_phases_digest(graph, _outside),
                           **({"key_finding_details": _crit} if _crit else {}),
                           **_analyst}
                payload_str = json.dumps(payload)
                if mask:
                    payload_str = _apply_mask(payload_str, mask)
            system = (SYNTHESIS_SYSTEM_PROMPT if altitude == "macro"
                      else REPORT_SYSTEM_PROMPT_FOCUSED)
            if altitude == "macro" and _zt and any((_phase_out.get(z["n"]) or {}).get("error")
                                                   for z in render.analysable(_zt)):
                system += ("\n\nSome phases carry `not_analysed` instead of an analysis: the "
                           "model could not analyse them. Say plainly which phases were not "
                           "analysed and why, and do not describe what happened in them "
                           "beyond their window, hosts and finding counts.")
            if (audience and audience != "both") or (language and language != "en"):
                try:                              # reuse engagement audience/language tailoring
                    from services.engagement.templates import audience_language_directive
                    system = system + "\n\n" + audience_language_directive(audience, language)
                except Exception:
                    pass
            if master_prompt:
                system = ("## OPERATOR CONTEXT (from interactive validation) — treat as "
                          "ground truth; apply the removals/focus described:\n"
                          f"{master_prompt.strip()}\n\n---\n\n") + system
            if mask:                              # teach the model the identity-number key
                system = _MASK_IDENTITY_LEGEND + system
            if should_continue and not should_continue():
                raise GenerationStopped()
            if altitude == "macro":
                _case_event(run_id, "Report · synthesis — sending", "info",
                            "combining the phase analyses into the report · "
                            + _ctx_size(payload_str))
                _note_progress(run_id)
            else:
                # One call for the whole case (a focused report): say how much it carries.
                _case_event(run_id, "Report · sending the case to the model", "info",
                            _ctx_size(payload_str))
            _synth_failed = ""

            def _keep_phases(exc):
                """THE PHASE ANALYSES ARE NOT THROWN AWAY. Measured live twice: six
                phases answered over 8-15 minutes, the overview call then failed --
                once with a dropped connection, once by answering NOTHING -- and the
                whole run fell back to the offline report, losing every analysis.
                Returns the placeholder overview, or re-raises when there is nothing
                worth keeping (a focused report is one call; a stopped run is not a
                failure)."""
                nonlocal _synth_failed
                if isinstance(exc, GenerationStopped) or altitude != "macro" \
                        or not any((_phase_out.get(z["n"]) or {}).get("body")
                                   for z in render.analysable(_zt)):
                    raise exc
                _synth_failed = _llm_reason_text(_classify_llm_error(exc))[0] + provider_retry_hint(exc)
                _case_event(run_id, "Report · overview not written", "warning",
                            f"{_synth_failed} The phase analyses below were written and are kept.")
                return ("> ⚠️ **Overview not written** — the model could not combine the "
                        f"phases into a summary: {_synth_failed} Each phase's own analysis "
                        "is below, and Regenerate report will try the summary again.")

            try:
                narrative = _with_deadline(
                    lambda: _real_llm(system, payload_str, run_id=run_id,
                                      max_output_tokens=max_output_tokens,
                                      reasoning_effort="low"),
                    _phase_deadline(), "synthesis")
                if not (narrative or "").strip():
                    # An empty answer is a failed call (see the note below) -- and it
                    # is the one that actually happened on the live run.
                    raise LLMUnavailable("empty_reply")
            except Exception as _se:                     # noqa: BLE001
                narrative = _keep_phases(_se)
            narrative = _revert_mask(narrative, mask)   # un-mask the LLM's output
            # AN EMPTY NARRATIVE IS A FAILED CALL, NOT A REPORT.
            #
            # A reasoning model draws its thinking from the same output allowance as
            # its answer, so on a large payload it can spend the whole budget and
            # return nothing. Measured live: 54,051 output tokens billed, zero
            # characters back. Nothing below noticed -- the deterministic tables are
            # appended regardless, so the operator got a report with no narrative in
            # it, logged as "LLM responded — narrative generated (12,046 chars)"
            # because that count measures the whole markdown, tables included.
            #
            # Raise instead: the except below already renders the deterministic
            # report AND names the reason, which is exactly the right outcome.
            if not (narrative or "").strip():
                raise LLMUnavailable("empty_reply")      # focused path: nothing to keep
            # Keeps the "_Narrative by live LLM" prefix: the page and
            # store._narration_outcome read it to tell an AI-written report from an
            # offline one, and this IS AI-written — only its overview is missing.
            _tail = ("_Narrative by live LLM — phase analyses only, the overview could not "
                     f"be written ({_synth_failed.strip()}); fact tables deterministic._"
                     if _synth_failed else
                     "_Narrative by live LLM; fact tables deterministic._")
            # GROUNDING GUARD: a report must never carry a sha256 that isn't in the
            # evidence (an analyst would chase a nonexistent IOC). Hashes are the one
            # unambiguous fabrication signal (timestamps include legit proposed zoom
            # bounds). Flag, don't strip — stripping mid-sentence breaks the prose.
            _bad_h = _ungrounded_hashes(narrative, _unmasked_payload)
            gnote = ("\n\n> ⚠️ **Grounding note:** these hash value(s) in the narrative are "
                     "NOT present in the case evidence and may be model artifacts — verify "
                     "before acting: " + ", ".join(f"`{h[:16]}…`" for h in _bad_h) + "\n"
                     if _bad_h else "")
            # In a segmented report the phases carry their own timelines, so the
            # case-wide one is scoped to what they did NOT cover.
            _tl_kw = {}
            if altitude == "macro" and _zt:
                _rest = render.outside_phases(graph, _zt, window=window,
                                              min_severity=min_severity)
                _tl_kw = {"timeline_findings": _rest,
                          "timeline_heading": "## Activity outside the analysed phases",
                          "timeline_note": (f"{len(_rest)} finding(s) that fall outside "
                                            f"every phase above, in order")}
            facts = render.facts_md(graph, window=window, min_severity=min_severity,
                                    initial_access=initial_access,
                                    dispositions=dispositions, validations=validations,
                                    detail=eff_detail, narrated=True,
                                    detail_reason=("segmented report — depth is in "
                                                   "the per-phase sections above"
                                                   if altitude == "macro" else None),
                                    **_tl_kw)
            # Deterministic heat-map for a macro report (the LLM was told NOT to write
            # this section) — always grounded, always matches the zoom cards.
            heatmap, tfnote = "", ""
            if altitude == "macro":
                _, _all_f = render.scope(graph, window=window, min_severity=min_severity)
                banner = render.report_mode_banner(altitude, _zt, mode=_mode,
                                                   total_findings=len(_all_f),
                                                   altitude_mode=altitude_mode)
                # ORDER IS THE DESIGN. The executive layer (Executive Summary, Key
                # Judgements, Where to start) comes first, then the glance table, then
                # the phases it refers to. The old order put "Priority actions" ABOVE
                # the phases, so the reader was told to open Phase 3 before learning
                # what Phase 3 was.
                _names = {z["n"]: (_phase_out.get(z["n"]) or {}).get("name") or ""
                          for z in render.analysable(_zt)}
                parts = [banner, "", narrative.strip(), "",
                         render.phases_at_a_glance_md(_zt, _names)]
                for z in render.analysable(_zt):
                    got = _phase_out.get(z["n"]) or {}
                    nm = got.get("name") or z.get("title") or f"Phase {z['n']}"
                    parts.append(f"### Phase {z['n']} — {nm}\n")
                    # Deterministic facts as BULLETS immediately under the heading:
                    # that shape is what the PDF renderer turns into a bordered card,
                    # and it is where the model's own Severity/Confidence lines land.
                    hs = ", ".join((z.get("host_labels") or [])[:6])
                    parts.append(
                        f"- **Window:** `{z['window']['start']}` → `{z['window']['end']}`\n"
                        f"- **Hosts:** {hs or '—'}\n"
                        f"- **Findings:** {z['finding_count']} "
                        f"({z.get('critical_count', 0)} critical)")
                    if got.get("error"):
                        parts.append(f"> ⚠️ This phase was not analysed by the AI model: "
                                     f"{got['error']} Its evidence is below and in the "
                                     f"case timeline — the rest of the report is "
                                     f"unaffected.\n")
                    else:
                        parts.append(got.get("body", "") + "\n")
                    # THIS PHASE'S timeline, not the whole case's -- the operator's
                    # "the timeline of events should be separate to each timeframe".
                    _, _pf = render.scope(graph, window=z["window"],
                                          min_severity=min_severity)
                    parts.append(render.timeline_md(
                        graph, _pf, window=z["window"], eff_detail=eff_detail,
                        # No divisor. Dividing the cap by phase count traded value
                        # for length -- "I don't wanna lose value because of static
                        # length". Each phase gets the same budget; the collapse
                        # already states repeats once, so a quiet phase costs little.
                        max_groups=render.TIMELINE_MAX_GROUPS,
                        heading="**Timeline — this phase**",
                        note=f"{len(_pf)} finding(s) in this phase, in order"))
                # The old "Suspicious Timeframes & Clusters" table is NOT appended:
                # it is the same rows, windows and counts as "Phases at a glance",
                # which now carries its ATT&CK column too. Printing both was the same
                # table twice -- exactly the padding the repo's own report rubric
                # marks down under efficiency.
                narrative = "\n".join(parts)
                heatmap = ""                      # already placed inside the narrative
            else:
                narrative = (render.report_mode_banner(altitude, [], mode=_mode,
                                                       altitude_mode=altitude_mode)
                             + "\n\n" + narrative)
            # Real values throughout: masking protected the data only in transit to
            # the LLM; the operator's report is reverted (narrative) + never-masked facts.
            md = (f"# Incident Case Report — {case_name}\n\n"
                  f"{render.report_header(graph, window=window, min_severity=min_severity)}\n\n"
                  f"{narrative}\n\n"
                  + gnote + tfnote
                  + (heatmap + "\n" if heatmap else "")
                  + f"{facts}"
                  + f"\n\n---\n{_tail}\n")
            return md
        except Exception as e:  # noqa: BLE001 — never let LLM failure break a case
            if isinstance(e, GenerationStopped):
                raise                 # not a model failure: the caller stopped wanting this run
            md = render.report(graph, window=window, min_severity=min_severity,
                               initial_access=initial_access, case_name=case_name,
                               dispositions=dispositions, validations=validations,
                               detail=detail)
            # Say WHICH problem: "no route to the provider", "the key was
            # rejected" and "the account is out of credit" need completely
            # different actions. Reuses chat's classifier + messages so the same
            # condition is never described two ways in two places.
            reason, fix = _llm_reason_text(_classify_llm_error(e))
            tail = f"{reason}" + (f" {fix}" if fix else "") + provider_retry_hint(e)
            return md + (f"\n\n---\n_Deterministic report — {tail}_\n")
    # Deterministic (no-LLM) path: nothing is sent to a provider, so no masking —
    # the operator gets the real report directly.
    md = render.report(graph, window=window, min_severity=min_severity,
                       initial_access=initial_access, case_name=case_name,
                       dispositions=dispositions, validations=validations,
                       detail=detail) + _sim_tag()
    return md


def _parse_json(text):
    """Tolerant extraction of the first JSON object from an LLM response.

    Tolerant INCLUDES no response at all. A reasoning model can return
    `content: null` -- not "" -- when it spends its whole output allowance
    thinking, and this crashed on None with AttributeError. analyze()'s blanket
    except then dressed that crash up as a deterministic host-grouping, so a
    transport-level failure arrived looking like an advisory. Measured live.
    """
    if not isinstance(text, str):
        return {}
    try:
        return json.loads(text)
    except Exception:
        pass
    s, e = text.find("{"), text.rfind("}")
    if 0 <= s < e:
        try:
            return json.loads(text[s:e + 1])
        except Exception:
            return {}
    return {}


CHECKLIST_SYSTEM_PROMPT = (
    "You are a DFIR consultant preparing a CUSTOMER-CONFIRMATION checklist. For each "
    "notable finding in the provided case graph, write ONE plain-language yes/no question "
    "asking the customer to confirm whether the activity is EXPECTED / AUTHORISED (benign) "
    "— e.g. scheduled IT work, a sanctioned tool, a known service account. Every item MUST "
    "cite the exact finding_id from the graph. Return STRICT JSON only: "
    '{"checklist":[{"finding_id":"...","question":"...","suggestion":"benign"}]}'
)


def _checklist_id(finding_id, question):
    import hashlib
    return "chk_" + hashlib.sha1(f"{finding_id}|{question}".encode()).hexdigest()[:12]


def _simulated_checklist(findings) -> list:
    return [{"id": _checklist_id(f.id, f.title), "finding_id": f.id,
             "question": f"Is “{f.title}” expected / authorised activity (benign)?",
             "suggestion": "benign", "status": "pending"} for f in findings]


def generate_disposition_checklist(graph, *, window=None, min_severity="high",
                                   run_id=None, mask=None, outcome=None, allow_llm=True) -> list:
    """Customer-confirmation checklist: per high finding, a likely-benign yes/no question
    the customer accepts (=> dispositioned benign) or declines (=> kept). Grounded to real
    finding_ids; deterministic fallback when no real LLM. Never raises.
    `mask` (optional DataAnonymizer) anonymizes the LLM payload the same way
    generate_report() does — previously this pass sent the graph to the LLM
    unmasked even when the case had masking enabled."""
    # `outcome`, when given, is filled with what ACTUALLY happened. This never
    # raises and falls back to a template checklist, so a failed model call used to
    # be indistinguishable from a successful one: the Log said "Checklist ·
    # complete — 0 item(s)" for a rejected key.
    if outcome is None:
        outcome = {}
    outcome.update({"used_llm": False, "error": None, "error_text": ""})
    _, findings = render.scope(graph, window=window, min_severity=min_severity)
    high = [f for f in findings if sev.at_least(f.severity, "high")] or findings
    # allow_llm=False: the caller promised "no model call" (a deterministic
    # regeneration logs "no LLM tokens spent"). It used to make one anyway whenever
    # the case had no checklist yet — inside the HTTP request, blocking it for the
    # model's whole timeout.
    if not allow_llm or not _use_real():
        return _simulated_checklist(high)
    outcome["used_llm"] = True
    try:
        payload = render.distilled(graph, window=window, min_severity=min_severity,
                                   max_entities=budget.REPORT_MAX_ENTITIES,
                                   budget_chars=budget.REPORT_BUDGET_CHARS)
        payload_str = json.dumps(payload)
        system = CHECKLIST_SYSTEM_PROMPT
        if mask:                                  # anonymize the LLM input too
            _build_mask_mapping(graph, mask)
            _log_mask_audit(run_id, mask, payload_str)
            payload_str = _apply_mask(payload_str, mask)
            system = _MASK_IDENTITY_LEGEND + system
        raw = _real_llm(system, payload_str, run_id=run_id)
        # An EMPTY reply is a failed call, not "the model found nothing to confirm":
        # it parsed to {} and was logged as a successful, empty checklist.
        if not (raw or "").strip():
            raise LLMUnavailable("empty_reply")
        raw = _revert_mask(raw, mask)
        data = _parse_json(raw)
        valid = {f.id for f in graph.findings}
        out = []
        for it in (data.get("checklist") or []):
            fid = it.get("finding_id")
            q = (it.get("question") or "").strip()
            if fid in valid and q:                    # grounding: only real findings
                out.append({"id": _checklist_id(fid, q), "finding_id": fid, "question": q,
                            "suggestion": it.get("suggestion", "benign"), "status": "pending"})
        outcome["empty"] = not out
        return out or _simulated_checklist(high)
    except Exception as e:  # noqa: BLE001
        outcome["error"] = _classify_llm_error(e)
        _r, _f = _llm_reason_text(outcome["error"])
        outcome["error_text"] = f"{_r}{provider_retry_hint(e)}"
        return _simulated_checklist(high)


class LLMUnavailable(Exception):
    """Raised by chat(require_llm=True) when the case chat cannot get a real model
    answer. `reason` is a machine code consumed by llm_error_message():
    missing_key / invalid_key / no_internet / timeout / rate_limited /
    missing_offline_url / llm_error."""
    def __init__(self, reason: str):
        self.reason = str(reason or "llm_error")
        super().__init__(self.reason)


_LLM_ERR_MESSAGES = {
    "missing_key": ("No API key is set for the AI model.",
                    "Add one in Settings ▸ Agentic, then try again."),
    "invalid_key": ("The AI provider rejected the API key.",
                    "Enter a valid key in Settings ▸ Agentic, then try again."),
    "no_internet": ("The appliance cannot reach the AI provider.",
                    "Check the appliance's internet connection, then try again."),
    "timeout": ("The AI model took too long to answer.",
                "Try again. If it keeps happening, check the connection or choose "
                "a faster model in Settings ▸ Agentic."),
    # The provider WAS reached and answered — badly. None of these is a key or a
    # network problem, and saying "check the API key and the internet connection"
    # (what all three used to fall through to) sends the operator to fix things
    # that work.
    "empty_reply": ("The AI model answered with nothing.",
                    "Choose a different model in Settings ▸ Agentic, then try again."),
    "bad_response": ("The AI provider sent back a reply that could not be read.",
                     "Check the model address in Settings ▸ Agentic, then try again."),
    "provider_error": ("The AI provider reported an internal error.",
                       "Wait a moment, or choose another model in Settings ▸ Agentic, then try again."),
    "rate_limited": ("The AI provider is limiting requests right now.",
                     "Wait, or switch provider in Settings ▸ Agentic, then try again."),
    "missing_offline_url": ("Local model mode is on, but no local model address is set.",
                            "Set the Ollama URL in Settings ▸ Agentic, or switch to an "
                            "online model, then try again."),
    "llm_error": ("The AI model did not answer.",
                  "Check the API key and the internet connection in Settings ▸ Agentic, "
                  "then try again."),
    "cli_not_installed": ("The subscription app (CLI) is not installed.",
                          "Install it in Settings ▸ Agentic (needs internet), then try again."),
    "cli_not_authenticated": ("The subscription is not signed in.",
                              "Sign in from Settings ▸ Agentic (needs internet), then try again."),
    # NOT the same as "not signed in", and the difference is the whole point: the
    # sign-in was valid and worked for days. Single-use refresh tokens are what
    # ended it -- the CLI spent the stored one, and the replacement it was handed
    # could not be saved (the appliance reads ~/.codex read-only). Saying "not
    # signed in" sends the operator looking for a setting they never changed, and
    # the vendor's own "log out and sign in again" points at a screen that does
    # not exist here: signing in happens on the HOST, in a shell.
    "cli_credential_expired": (
        "The subscription sign-in expired: its refreshed token could not be saved, so the old one is spent.",
        "On the appliance HOST run `codex login` (or `codex login --device-auth` without a browser), then try again."),
    # Covers both a subscription plan that does not include the model and a model
    # id the provider does not have at all — the operator's action is the same.
    "model_unsupported": ("The provider does not offer the selected model to this account.",
                          "Choose a different model in Settings ▸ Agentic — or clear the "
                          "Model field to use the default — then try again."),
    # Billing and routing both arrive looking like auth failures; saying the key
    # is fine stops the operator replacing a key that works.
    "no_credit": ("The AI provider account is out of credit. The API key itself is fine.",
                  "Add credit with the provider, or switch provider in Settings ▸ Agentic, "
                  "then try again."),
    "model_not_routable": ("The provider will not run this model for your account, usually "
                           "because of its privacy settings. The API key itself is fine.",
                           "Choose a different model in Settings ▸ Agentic, or relax the "
                           "provider's privacy settings (OpenRouter: "
                           "openrouter.ai/settings/privacy), then try again."),
}


# A provider that could not be REACHED at all — as opposed to one that answered
# and refused. Within a single fuse there is no point calling it a second time:
# the report's attempt has just proved there is no route, and the checklist call
# that follows spends another full timeout learning the same thing. On an
# air-gapped box with a provider still configured that was ~65s of dead waiting
# per Refusion, with "generating report (this waits on the model)" on screen.
#
# Deliberately NOT remembered between fuses: every Refusion gets a fresh attempt,
# so a connection that comes back is used immediately, with no cooldown to wait
# out and no state to go stale.
_NO_ROUTE_CODES = ("no_internet", "timeout")


def provider_retry_hint(text) -> str:
    """The provider's own "try again at/in …", as a sentence to append, or ''.

    A usage cap that resets in four days and a burst limit that clears in a
    minute are the same reason code with completely different answers, and only
    the provider knows which — so say what it said.
    """
    m = _re.search(r"try again (at|in|after) ([^.\n]{3,60})", str(text or ""), _re.I)
    return f" The provider says to try again {m.group(1).lower()} {m.group(2).strip()}." if m else ""


def reason_code_of(why: str) -> str:
    """The reason CODE behind a rendered failure sentence, or ''.

    generate_report classifies its own failure and then renders it into the
    report's closing note, keeping the code to itself — so the only thing a
    caller can see is the sentence. Rather than change that signature, map the
    sentence back through the same table that produced it: self-consistent by
    construction, and a test pins it.
    """
    text = (why or "").strip()
    if not text:
        return ""
    for code in list(_LLM_CONFIG_REASONS) + list(_LLM_ERR_MESSAGES):
        reason, _fix = _llm_reason_text(code)
        if reason and text.startswith(reason):
            return code
    return ""


def provider_unreachable(why: str) -> bool:
    """Did this failure mean "no route to the provider"? See _NO_ROUTE_CODES."""
    return reason_code_of(why) in _NO_ROUTE_CODES


def llm_error_message(reason: str) -> str:
    """Operator-facing message for an LLMUnavailable reason code."""
    problem, fix = _LLM_ERR_MESSAGES.get(reason, _LLM_ERR_MESSAGES["llm_error"])
    return f"⚠️ {problem} {fix}"


def classify_llm_failure(exc) -> dict:
    """Public wrapper: a transport exception -> {code, reason, fix}, the same
    triple llm_status()/llm_reachability() use — the one place outside this
    module that needs to classify a LIVE call failure (Settings' Test
    Connection button) should not reach past the underscore into
    _classify_llm_error/_llm_reason_text directly."""
    code = _classify_llm_error(exc)
    reason, fix = _llm_reason_text(code)
    return {"code": code, "reason": reason, "fix": fix}


def _llm_unavailable_reason():
    """Why no LLM transport is usable (config-time), or None if one is configured.
    Distinguishes an empty key from an unset offline URL so the chat can say which."""
    try:
        from services.memory.pipeline import _llm_config_from_runtime
        ag = (_llm_config_from_runtime() or {}).get("agentic") or {}
    except Exception:
        return "missing_key"
    if str(ag.get("llm_mode", "online")).lower() == "offline":
        return None if (ag.get("offline_llm") or {}).get("url") else "missing_offline_url"
    online = ag.get("online_llm") or {}
    provider = online.get("provider")
    # A subscription provider is configured by installing + connecting its CLI,
    # so report which of those two steps is still missing rather than the
    # api-key message, which would send the operator hunting for a key.
    try:
        from services.agentic import subscription_cli as _sub
        if _sub.is_subscription_provider(provider):
            if not _sub.is_installed(provider):
                return "cli_not_installed"
            return None if _sub.has_credentials(provider) else "cli_not_authenticated"
    except Exception:  # noqa: BLE001
        pass
    return None if online.get("api_key") else "missing_key"


def _classify_llm_error(exc) -> str:
    """Map a transport exception to a reason code (auth vs connection vs timeout …)."""
    # A failure that ALREADY knows what it is keeps that answer. The subscription CLI
    # classifies its own output (it is the only layer that sees the vendor's exact
    # wording) and raises with `.reason`; re-deriving the code here from the message
    # text threw that away — "You've hit your usage limit … try again at Sep 20" went
    # out as "the AI model did not answer, check the API key and internet".
    r = getattr(exc, "reason", None)
    if isinstance(r, str) and r != "llm_error" and (r in _LLM_ERR_MESSAGES or r in _LLM_CONFIG_REASONS):
        return r
    s = f"{type(exc).__name__} {exc}".lower()
    # A usage cap is not billing and not "wait a minute": the ChatGPT plan answers
    # "You've hit your usage limit. Visit … to purchase more credits or try again at
    # <date>". Checked FIRST, because "purchase … credits" would otherwise read as
    # an empty account.
    if any(t in s for t in ("usage limit", "hit your limit", "you've hit your", "rate limit reached")):
        return "rate_limited"
    # The model never answered because it was never REACHED. A connect timeout is
    # worded "…timed out", and the timeout branch below used to claim it — telling
    # an operator whose box has no route out that "the model took too long".
    # Answered, but not with anything usable. Verbatim from requests/json on a proxy
    # that returned an HTML error page with HTTP 200: "Expecting value: line 1
    # column 1 (char 0)".
    if any(t in s for t in ("jsondecodeerror", "expecting value", "invalid json",
                            "not valid json", "unexpected token")):
        return "bad_response"
    # The provider's own server failed (5xx). A 504 is deliberately NOT here: a
    # gateway timeout is the "took too long" case below.
    if any(t in s for t in ("500 server error", "internal server error", "502 server error",
                            "bad gateway", "503 server error", "service unavailable")):
        return "provider_error"
    if any(t in s for t in ("connecttimeout", "connect timeout", "newconnectionerror",
                            "failed to establish a new connection", "name or service not known",
                            "temporary failure in name resolution", "nodename nor servname",
                            "network is unreachable", "no route to host", "connection refused",
                            "getaddrinfo")):
        return "no_internet"
    # Checked FIRST, before the auth patterns. A routing refusal is a 404 whose
    # body often mentions "api"/"policy", and the auth branch below is broad
    # enough to swallow it — which is exactly what happened: OpenRouter refused
    # to route qwen/qwen3.7-flash under the account's data policy and the
    # operator was told to "check the API key and internet connection", both of
    # which were fine. The key authenticated and the same key worked on five
    # other models.
    # Billing before BOTH the auth and rate-limit branches. A funded-out account
    # still authenticates, so "check your API key" is wrong; and OpenAI returns
    # insufficient_quota as a 429, which the rate-limit branch would otherwise
    # claim and turn into "wait a moment and try again" -- advice that never
    # comes true. Observed: Anthropic replying 400 "Your credit balance is too
    # low", surfaced to the operator as "check the API key and internet
    # connection" while the key was listing models fine.
    # OpenRouter phrases the same condition three ways and matched NONE of the
    # patterns below, so a funded-out account surfaced as a bare "APIStatusError"
    # and the report just said the LLM was unavailable:
    #   "Insufficient credits. Add more using .../settings/credits"
    #   "This request requires more credits, or fewer max_tokens"
    #   metadata.limit_source: "openrouter_credits"
    # The last one is the reliable signal — it is a machine field rather than
    # prose, so it survives upstream rewording.
    if any(t in s for t in ("credit balance is too low", "insufficient_quota",
                            "exceeded your current quota", "billing",
                            "purchase credits", "payment required",
                            "insufficient credits", "requires more credits",
                            "openrouter_credits", "settings/credits")):
        return "no_credit"
    if any(t in s for t in ("no endpoints available", "no allowed providers",
                            "data policy", "guardrail")):
        return "model_not_routable"
    # A model id the provider does not have. OpenRouter, verbatim:
    #   "openai/does-not-exist-9f3 is not a valid model ID" (HTTP 400)
    # which matched nothing and reached the operator as "check the API key and the
    # internet connection" — both of which were fine.
    if any(t in s for t in ("not a valid model", "model_not_found", "model not found",
                            "no such model", "unknown model", "invalid model",
                            "model does not exist", "is not supported when using",
                            "model is not supported")):
        return "model_unsupported"
    if any(t in s for t in ("401", "403", "unauthor", "user not found", "invalid api",
                            "authentication", "invalid_api_key", "no api key", "api key")):
        return "invalid_key"
    if any(t in s for t in ("timed out", "timeout", "read timed out")):
        return "timeout"
    if any(t in s for t in ("429", "rate limit", "ratelimit", "too many requests")):
        return "rate_limited"
    if any(t in s for t in ("connection", "connect", "getaddrinfo", "name or service not known",
                            "temporary failure in name resolution", "network is unreachable",
                            "max retries", "failed to establish", "unreachable", "refused",
                            "no route to host", "dns")):
        return "no_internet"
    return "llm_error"


def chat(graph, question: str, history=None, *, window=None, min_severity="informational",
         run_id=None, dispositions=None, validations=None, full_context=None,
         max_output_tokens=None, require_llm=False, mask=None, max_identities=None,
         excluded_hosts=None, master_prompt=None, manual_events=None, checklist=None) -> str:
    """Grounded Q&A. Real path narrates the distilled graph; simulated = deterministic
    retrieval. Surfaces operator dispositions (what's been triaged as benign/IT).
    `mask` (optional DataAnonymizer) anonymizes the LLM payload the same way
    generate_report() does — previously chat ALWAYS sent the full, real graph
    (hostnames/usernames/IPs/cmdlines) to the LLM regardless of the case's
    masking setting, since chat_case() hardcodes full_context=True."""
    # --- entity resolution + safety clarify (BEFORE any LLM call, so an ambiguous
    # or typo'd host name is never silently answered on the wrong machine). The
    # clarify reply reads as the assistant asking back; it costs no LLM tokens.
    # The operator can DISABLE all of this via `chat_send_full_context` (see
    # _chat_full_context) — the escape hatch: never clarifies, always sends the
    # full graph. More expensive (see the warning on the flag).
    from . import resolve as _resolve
    # per-case toggle (Case Analysis → Configuration) wins; else the global default.
    full_ctx = bool(full_context) if full_context is not None else _chat_full_context()
    pinned = []
    if not full_ctx:
        pinned = _resolve.resolve_followup(graph, question, history)
        if pinned is None:
            _res = _resolve.resolve(graph, question)
            _clar = _resolve.clarify_text(_res)
            if _clar:
                return _clar
            pinned = _res["resolved"]
    pin_ids = [e.id for e in pinned]
    focus = [e.label for e in pinned]

    # PRIMARY: whenever a model is configured, this is ONE generic, grounded
    # conversation over the whole infrastructure graph — no prepared intents. Just
    # configuring an LLM (online key or offline Ollama) turns it on; no extra flag.
    _configured = _use_real() or _llm_available()
    if require_llm and not _configured:
        # The case chat REQUIRES a real model — say exactly why none is usable
        # (missing/empty key, or no offline URL) instead of a deterministic answer.
        raise LLMUnavailable(_llm_unavailable_reason() or "missing_key")
    if _configured:
        try:
            if full_ctx:
                # Bypass: send the FULL distilled graph every turn (pricier).
                payload = render.distilled(graph, window=window, min_severity=min_severity,
                                           max_entities=budget.REPORT_MAX_ENTITIES,
                                           budget_chars=budget.REPORT_BUDGET_CHARS,
                                           max_identities=max_identities)
                # "Full" is the report's budgeted summary: findings collapsed into
                # groups, without ids, and whatever did not fit dropped. Add back what
                # this question is about, uncollapsed, plus the case's real extent.
                _, _scoped = render.scope(graph, window=window, min_severity=min_severity)
                _prev = "\n".join(str(m.get("content") or "")[:2000] for m in (history or [])[-2:])
                _qf = render.question_findings(
                    _scoped, question, [v.get("finding_id") for v in (validations or [])],
                    graph=graph, context_text=_prev)
                if _qf:
                    _verdict = {v.get("finding_id"): v.get("status") for v in (validations or [])}
                    payload["findings_this_question_is_about"] = [
                        render.finding_detail(graph, f, _verdict.get(f.id)) for f in _qf]
                payload.update(render.case_extent(_scoped))
                # Kept deliberately small (the chat payload is sent on every turn):
                # the high/critical findings the budgeted summary dropped, one line
                # each, and the evidence details of the critical ones.
                # Compare against the payload's actual strings, not its JSON text: JSON
                # escapes backslashes and non-ASCII ("adatumlab\\srv", "—"), which made
                # a finding that WAS sent look missing.
                def _strings(o):
                    if isinstance(o, str):
                        yield o
                    elif isinstance(o, dict):
                        for v in o.values():
                            yield from _strings(v)
                    elif isinstance(o, (list, tuple)):
                        for v in o:
                            yield from _strings(v)
                _dump = "\n".join(_strings(payload))
                # The summary rewrites titles ("X (+1 related)", the "on <host>" tail
                # trimmed), so match on the rule part of the title, not the whole title.
                _missed = [f for f in _scoped if f.severity in ("high", "critical")
                           and f.title.split(" on ")[0][:40] not in _dump]
                if _missed:
                    payload["other_high_findings"] = [
                        {"title": f.title, "time": f.ts,
                         "hosts": [render._host_label(graph, a) for a in (f.asset_ids or [])]}
                        for f in _missed]
                _crit = render.critical_details(graph, _scoped, also_ids=[v.get("finding_id") for v in (validations or []) if v.get("status") == "true_positive"])
                if _crit:
                    payload["key_finding_details"] = _crit
            else:
                payload = render.chat_subgraph(graph, question, window=window,
                                               min_severity=min_severity,
                                               max_entities=budget.CHAT_MAX_ENTITIES,
                                               pin_ids=pin_ids, focus_labels=focus,
                                               also_finding_ids=[v.get("finding_id") for v in (validations or [])])
            # the analyst's triage, validations and manual events -- same as the report
            payload.update(analyst_context(dispositions, validations, manual_events, graph, checklist))
            if excluded_hosts:
                # Taken out of the analysis in Configuration: say so rather than
                # answering that the host does not exist.
                payload["hosts_excluded_from_analysis_by_operator"] = list(excluded_hosts)
            turns = "".join(f"{m.get('role')}: {m.get('content')}\n" for m in (history or []))
            user = f"{json.dumps(payload)}\n\n{turns}Q: {question}"
            system = CHAT_SYSTEM_PROMPT
            if master_prompt:
                # The case's Steering, as the report applies it: chat answering about
                # "the backup host noise" the analyst told the report to ignore read
                # as two different tools.
                system = ("## OPERATOR CONTEXT (from interactive validation) — treat as "
                          f"ground truth:\n{master_prompt.strip()}\n\n---\n\n") + system
            if mask:                                  # anonymize the LLM input too
                _build_mask_mapping(graph, mask)
                _log_mask_audit(run_id, mask, user)
                user = _apply_mask(user, mask)
                system = _MASK_IDENTITY_LEGEND + system
            ans = _real_llm(system, user, run_id=run_id, max_output_tokens=max_output_tokens)
            return _revert_mask(ans, mask)
        except Exception as e:  # noqa: BLE001
            if require_llm:
                # No silent deterministic fallback for the case chat: surface the
                # SPECIFIC failure (rejected key / no connection / timeout).
                raise LLMUnavailable(_classify_llm_error(e)) from e
            # legacy callers (tests / non-chat): fall through to deterministic retrieval.

    # FALLBACK (no LLM): if the question resolved to a HOST, answer scoped to it
    # deterministically so the pin works even without a model configured. Account/
    # IOC mentions fall through to the existing keyword retrieval below (which has
    # dedicated identity/IOC handling).
    pin_assets = [e for e in pinned if e.id.startswith("asset:")]
    if pin_assets:
        _aids = {e.id for e in pin_assets}
        _, _findings = render.scope(graph, window=window, min_severity=min_severity)
        hits = sorted((f for f in _findings if _aids & set(f.asset_ids)),
                      key=lambda f: -sev.rank(f.severity))
        head = "On " + ", ".join(e.label for e in pin_assets) + ":"
        if not hits:
            return f"{head} no findings in the current window/severity filter."
        lines = [f"- **[{f.severity}]** {f.title} — {f.summary}" for f in hits[:15]]
        return head + "\n" + "\n".join(lines)

    # FALLBACK (no LLM configured): deterministic keyword retrieval over the graph.
    q0 = (question or "").lower()
    # "what's been marked benign / explained / dispositioned"
    if dispositions and any(k in q0 for k in ("disposition", "marked benign", "what did i mark",
                                              "triaged", "explained", "marked as", "benign list",
                                              "what's benign", "whats benign")):
        lines = [f"- **{x.get('target')}** → {x.get('verdict')} ({x.get('attribution')}"
                 + (f", {x.get('reason')}" if x.get('reason') else "") + f") [{x.get('scope')}]"
                 for x in dispositions]
        return "Operator dispositions on this case:\n" + "\n".join(lines)
    q = (question or "").lower()
    _, findings = render.scope(graph, window=window, min_severity=min_severity)

    def cite(f):
        srcs = "/".join(f.sources) or "?"
        return f"- **[{f.severity}]** {f.title} — {f.summary}  _(source: {srcs})_"

    def _n_from(qq, default=5):
        m = re.search(r"\b(\d{1,3})\b", qq)
        return max(1, min(int(m.group(1)), 25)) if m else default

    _RANK_CUES = ("top", "worst", "most", "rank", "list", "biggest", "main", "key")
    _has_rank = any(k in q for k in _RANK_CUES) or bool(re.search(r"\b\d+\b", q))

    # 0a) top-N IDENTITIES / accounts (must precede the generic 'who' branch, which
    #     otherwise answers with a host). Ranks accounts by cross-host spread first.
    if any(k in q for k in ("identit", "account", "user ", "users", "credential", "logon")) \
            and not any(k in q for k in ("host", "machine", "endpoint", "computer")):
        accts = [e for e in graph.entities.values() if e.type == "account"]
        if accts:
            def _akey(e):
                return (1 if "cross_host" in (e.flags or []) else 0,
                        len(_assets_of(e)), sev.rank(e.severity), e.anomaly or 0)
            accts.sort(key=_akey, reverse=True)
            n = _n_from(q)
            lines = []
            for e in accts[:n]:
                hl = [_host_label(graph, x) for x in _assets_of(e)]
                xh = " (cross-host)" if "cross_host" in (e.flags or []) else ""
                lines.append(f"- **{e.label}**{xh} — {e.severity}, on {len(hl)} host(s)"
                             + (f": {', '.join(hl[:8])}" if hl else ""))
            return (f"Top {min(n, len(accts))} identities by cross-host spread + severity:\n"
                    + "\n".join(lines))

    # 0b) top-N HOSTS / machines, ranked by risk (precedes the default findings dump).
    if any(k in q for k in ("host", "machine", "endpoint", "computer", "asset")) and _has_rank:
        hosts = list(graph.by_type("asset"))
        if hosts:
            def _hcount(a):
                return len([f for f in findings if a.id in f.asset_ids])
            hosts.sort(key=lambda a: (a.attrs.get("risk_score") or 0,
                                      a.attrs.get("risk_intensity") or 0,
                                      sev.rank(a.severity), _hcount(a)), reverse=True)
            n = _n_from(q)
            lines = [f"- **{a.label}** — {a.severity}, risk {a.attrs.get('risk_score', 0)}, "
                     f"{_hcount(a)} finding(s)" for a in hosts[:n]]
            return f"Top {min(n, len(hosts))} hosts by risk:\n" + "\n".join(lines)

    # 1) host-focused
    for a in graph.by_type("asset"):
        if a.label and a.label.lower() in q:
            af = [f for f in findings if a.id in f.asset_ids]
            if af:
                return f"On **{a.label}**:\n" + "\n".join(cite(f) for f in af)

    # triage / escalation — which hosts to deep-dive next
    if any(k in q for k in ("escalate", "deep-dive", "deep dive", "what next", "run memory",
                            "run timesketch", "which host", "investigate next", "prioriti")):
        esc = sorted((a for a in graph.by_type("asset") if a.attrs.get("escalate")),
                     key=lambda a: -(a.attrs.get("risk_score") or 0))
        if esc:
            return ("Deep-dive candidates (malicious under broad collection, no memory/"
                    "Timesketch yet — run those next):\n"
                    + "\n".join(f"- **{a.label}** — risk {a.attrs.get('risk_score', 0)}, "
                                f"{a.severity}, seen by [{', '.join(a.attrs.get('modules') or [])}]"
                                for a in esc))
        return ("No escalation candidates — either nothing is high-risk, or the high-risk "
                "hosts already have memory/Timesketch coverage.")

    # summary / overview / who is worst
    if any(k in q for k in ("summary", "overview", "brief", "tl;dr", "what happened")):
        hosts = sorted(graph.by_type("asset"), key=lambda a: -sev.rank(a.severity))
        top = sorted(findings, key=lambda f: -sev.rank(f.severity))[:3]
        return (f"{len(hosts)} host(s); worst: "
                + ", ".join(f"{a.label} ({a.severity})" for a in hosts[:4]) + ".\n"
                + "Top findings:\n" + "\n".join(cite(f) for f in top))
    if any(k in q for k in ("who", "most malicious", "worst", "patient zero", "most affected")):
        hosts = sorted(graph.by_type("asset"), key=lambda a: -sev.rank(a.severity))
        if hosts:
            a = hosts[0]
            af = [f for f in findings if a.id in f.asset_ids]
            return (f"**{a.label}** is the most affected host ({a.severity}, {len(af)} findings) — "
                    f"likely patient zero.\n" + "\n".join(cite(f) for f in af[:4]))
    if any(k in q for k in ("initial access", "get in", "got in", "entry", "first compromise")):
        tl = render.timeline(graph, window=window)
        if tl:
            r = tl[0]
            return (f"Earliest in-window activity: `{r['ts']}` on **{r['host']}** — {r['title']}. "
                    f"That is the most likely initial-access anchor.")
    if any(k in q for k in ("vuln", "cve", "patch", "exposure")):
        vf = [f for f in findings if f.title.lower().startswith("vulnerability")]
        return ("Vulnerabilities:\n" + "\n".join(cite(f) for f in vf)) if vf \
            else "No vulnerabilities (CVE) above threshold in this case."
    if any(k in q for k in ("persist", "service", "autorun", "scheduled task", "stay")):
        pf = [f for f in findings if any(k in f.title.lower() for k in ("service", "persist", "task"))]
        return ("Persistence:\n" + "\n".join(cite(f) for f in pf)) if pf \
            else "No persistence findings above threshold in this case."

    # 1b) attack path / kill chain — the cross-host story, chronological + phased
    if any(k in q for k in ("attack path", "path the attack", "path did", "path took",
                            "which path", "kill chain", "kill-chain", "attack took",
                            "how the attack", "attack chain", "the chain", "story",
                            "narrative", "trace the", "across hosts", "across clients",
                            "across the", "multiple clients", "multiple hosts",
                            "from multiple", "full picture", "whole attack", "end to end",
                            "end-to-end", "progression", "sequence of")):
        tl = render.timeline(graph, window=window)
        xh = [f for f in findings if f.kind == "cross_host"]
        if tl:
            lines, last = [], None
            for r in tl[:30]:
                ph = r.get("phase") or ""
                head = f"**{ph}** — " if ph and ph != last else ""
                last = ph or last
                lines.append(f"- `{r['ts'] or '—'}` · {r['host']} · {head}{r['title']}")
            out = ("Attack path (chronological, across the affected hosts):\n"
                   + "\n".join(lines))
            if xh:
                out += ("\n\nCross-host pivots (same account/indicator on >1 host — the "
                        "lateral-movement spine):\n" + "\n".join(cite(f) for f in xh[:8]))
            return out
        if xh:
            return "Cross-host pivots:\n" + "\n".join(cite(f) for f in xh)

    # 2) lateral movement / how did they move / pivot
    if any(k in q for k in ("lateral", "move", "moved", "pivot", "spread", "how did",
                            "traverse", "propagat")):
        xh = [f for f in findings if f.kind == "cross_host"]
        if xh:
            return "Cross-host / lateral movement evidence:\n" + "\n".join(cite(f) for f in xh)
        return "No deterministic cross-host (lateral-movement) link surfaced in the graph for this window."

    # 3) timeline / when / first
    if any(k in q for k in ("timeline", "when", "first", "initial", "order", "happen")):
        tl = render.timeline(graph, window=window)
        if tl:
            lines = [f"- `{r['ts'] or '—'}` · {r['host']} · [{r['phase']}] {r['title']}" for r in tl[:20]]
            return "Attack timeline (chronological):\n" + "\n".join(lines)

    # 4) indicator / IP / account lookup
    for e in graph.entities.values():
        if e.type in ("ioc", "account") and e.label and e.label.lower() in q:
            hosts = ", ".join(_host_label(graph, x) for x in _assets_of(e))
            tag = " (CROSS-HOST)" if "cross_host" in e.flags else ""
            return (f"**{e.label}** ({e.type}){tag} seen on: {hosts}. "
                    f"Severity {e.severity}, sources {'/'.join(e.sources)}.")

    # 5) default: a brief case framing + top findings (no exact intent matched).
    top = sorted(findings, key=lambda f: -sev.rank(f.severity))[:8]
    if not top:
        return "No findings above the current severity threshold in this window."
    hosts = sorted(graph.by_type("asset"), key=lambda a: -sev.rank(a.severity))
    xh = sum(1 for f in findings if f.kind == "cross_host")
    head = (f"I don't have an exact answer for that (deterministic no-LLM mode — "
            f"configure an LLM for free-form Q&A). For context: {len(hosts)} host(s), "
            f"worst " + ", ".join(f"{a.label} ({a.severity})" for a in hosts[:3])
            + (f", {xh} cross-host finding(s)" if xh else "") + ".\n"
            "Try: \"attack path\", \"top 3 hosts\", \"top identities\", \"lateral movement\", "
            "\"timeline\", or a host/account/IP name.\n\nTop findings:")
    return head + "\n" + "\n".join(cite(f) for f in top)
