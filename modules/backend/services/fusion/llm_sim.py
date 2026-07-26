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
_AFFIRM = ("yes", "yeah", "yep", "yup", "confirm", "confirmed", "correct",
           "right", "ok", "okay", "sure", "do it", "apply", "agreed",
           "כן", "נכון", "אישור", "מאשר", "מאשרת", "בסדר", "אוקיי")
_NEGATE = ("no", "nope", "not", "don't", "dont", "cancel", "keep it", "wrong",
           "mistake", "לא", "בטל", "טעות", "לא נכון")


def is_affirmative(msg: str) -> bool:
    """True for a short standalone yes. Deliberately strict: only a SHORT reply
    counts, so a long sentence that merely contains 'ok' cannot apply a pending
    triage verdict by accident."""
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


def detect_disposition(graph, question: str):
    """If the message attributes activity as benign/IT/etc AND grounds to a real finding or
    entity, return a disposition dict; else None (caller falls back to normal chat). Grounding
    is mandatory — the same anti-hallucination discipline as the analyst pass."""
    q = (question or "").lower().strip().strip('"\u2019\'` ')
    # Questions are read-only by definition. Applying a disposition to one lets
    # a plain enquiry suppress a finding and re-fuse the case behind the
    # operator's back, which is exactly what "who is the most malicious user"
    # did before this guard existed.
    if q.endswith("?") or any(q.startswith(op) for op in _QUESTION_OPENERS):
        return None
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
# Real-LLM boundary — the ONLY place the model API is touched. Default OFF
# (mode='simulated'); flip frontend_config agentic.fusion_llm_mode='real' with an
# API key to enable. Any failure falls back to the deterministic narrator.
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
    cfg = _agentic_cfg()
    if str(cfg.get("fusion_llm_mode", "simulated")).lower() != "real":
        return False
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
              max_output_tokens=None) -> str:
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
    return call_llm(user_message, system_prompt, cfg, run_id=run_id)


REPORT_SYSTEM_PROMPT = (
    "You are a senior DFIR consultant writing the narrative section of an incident "
    "report for a customer, from the provided correlated incident graph (JSON: hosts, "
    "accounts, processes, IOCs, findings, cross-host links, timeline, and the analyst's "
    "dispositions/validations).\n"
    "Write these sections as clean markdown, in this order:\n"
    "## Executive Summary — 3-5 sentences in plain business language: what happened, "
    "how many hosts, the severity/confidence, and the bottom line for a non-technical "
    "reader.\n"
    "## Incident Overview — scope, the most-affected host(s) and the likely entry "
    "point/initial access, and what the adversary appears to have been after.\n"
    "## Attack Narrative — the kill chain as prose, in order (initial access → "
    "execution → persistence → C2 → lateral movement → impact), naming the hosts, "
    "accounts and times involved at each step.\n"
    "Reflect the analyst's validations: treat findings confirmed real as fact, and do "
    "NOT dwell on ones dispositioned benign / known-to-IT (mention they were cleared).\n"
    "Structured fact tables (timeline, hosts, IOCs, MITRE, recommendations) are appended "
    "by the system AFTER your text — do NOT reproduce them. Be specific and grounded: "
    "cite hosts/accounts/hashes verbatim from the graph; never invent anything not "
    "present. No preamble, start at '## Executive Summary'."
)
CHAT_SYSTEM_PROMPT = (
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
ANALYST_SYSTEM_PROMPT = (
    "You are a senior DFIR analyst reviewing a correlated incident graph (JSON) that "
    "already contains deterministic findings. Do THREE things and return STRICT JSON:\n"
    "1) incident_groups: cluster the EXISTING findings into named campaigns. Each group "
    "cites finding_ids that appear in the graph's findings.\n"
    "2) hypotheses: novel patterns the deterministic rules may have MISSED. Each MUST cite "
    "entity_ids that appear in the graph's top_entities, a confidence (low|medium|high), "
    "and a one-line reason. These are FOR ANALYST VERIFICATION — not confirmed.\n"
    "3) (optional) note operator dispositions you were given.\n"
    "HARD RULES: reference ONLY ids/values present in the provided graph. Do NOT invent "
    "hosts, hashes, accounts, campaign names, or threat actors. If you cannot ground a "
    "hypothesis in a real entity_id, omit it. Distinguish FACT (in the graph) from "
    "INFERENCE (your reasoning). Output JSON only: "
    '{"incident_groups":[{"name","finding_ids","rationale"}],'
    '"hypotheses":[{"title","entity_ids","confidence","reason"}]}'
)

_SIM_TAG = ("\n\n---\n_Narrative by the in-graph narrator (simulated — deterministic). "
            "Set agentic.fusion_llm_mode='real' to use a live model._\n")


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


def generate_report(graph, *, window=None, min_severity="informational",
                    initial_access=None, case_name="Case", run_id=None,
                    audience="both", language="en", master_prompt=None, mask=None,
                    dispositions=None, validations=None, prefer_llm=True,
                    max_entities=None, budget_chars=None, max_output_tokens=None,
                    detail="auto") -> str:
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
            payload = render.distilled(graph, window=window, min_severity=min_severity,
                                       max_entities=me, budget_chars=bc, detail=detail)
            # give the model the analyst's triage so the narrative reflects it
            if dispositions:
                payload["operator_dispositions"] = dispositions
            if validations:
                payload["analyst_validations"] = validations
            payload_str = json.dumps(payload)
            if mask:                                  # anonymize the LLM input too
                _build_mask_mapping(graph, mask)
                _log_mask_audit(run_id, mask, payload_str)   # audit BEFORE the send; only what's in the payload
                payload_str = _apply_mask(payload_str, mask)
            system = REPORT_SYSTEM_PROMPT
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
            narrative = _real_llm(system, payload_str, run_id=run_id,
                                  max_output_tokens=max_output_tokens)
            narrative = _revert_mask(narrative, mask)   # un-mask the LLM's output
            facts = render.facts_md(graph, window=window, min_severity=min_severity,
                                    initial_access=initial_access,
                                    dispositions=dispositions, validations=validations,
                                    detail=detail)
            # Real values throughout: masking protected the data only in transit to
            # the LLM; the operator's report is reverted (narrative) + never-masked facts.
            md = (f"# Incident Case Report — {case_name}\n\n{narrative}\n\n{facts}"
                  "\n\n---\n_Narrative by live LLM; fact tables deterministic._\n")
            return md
        except Exception as e:  # noqa: BLE001 — never let LLM failure break a case
            md = render.report(graph, window=window, min_severity=min_severity,
                               initial_access=initial_access, case_name=case_name,
                               dispositions=dispositions, validations=validations,
                               detail=detail)
            return md + (f"\n\n---\n_Live LLM unavailable "
                         f"({type(e).__name__}); deterministic fallback._\n")
    # Deterministic (no-LLM) path: nothing is sent to a provider, so no masking —
    # the operator gets the real report directly.
    md = render.report(graph, window=window, min_severity=min_severity,
                       initial_access=initial_access, case_name=case_name,
                       dispositions=dispositions, validations=validations,
                       detail=detail) + _SIM_TAG
    return md


def _parse_json(text):
    """Tolerant extraction of the first JSON object from an LLM response."""
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


def _ground(analysis: dict, graph) -> dict:
    """Deterministic post-filter: drop any cited id not present in the graph; reject a
    hypothesis left citing zero real entities. Grounding is enforced, not trusted."""
    valid_ent = set(graph.entities)
    valid_find = {f.id for f in graph.findings}
    groups = []
    for grp in (analysis.get("incident_groups") or []):
        if not isinstance(grp, dict):
            continue
        cited = [i for i in (grp.get("finding_ids") or []) if i in valid_find]
        removed = [i for i in (grp.get("finding_ids") or []) if i not in valid_find]
        if cited:
            grp = dict(grp); grp["finding_ids"] = cited
            if removed:
                grp["ungrounded_refs_removed"] = removed
            groups.append(grp)
    hyps = []
    for h in (analysis.get("hypotheses") or []):
        if not isinstance(h, dict):
            continue
        cited = [i for i in (h.get("entity_ids") or []) if i in valid_ent]
        removed = [i for i in (h.get("entity_ids") or []) if i not in valid_ent]
        if not cited:
            continue                              # zero real entities = hallucination, drop
        h = dict(h); h["entity_ids"] = cited
        h["status"] = "for_analyst_verification"
        if removed:
            h["ungrounded_refs_removed"] = removed
        hyps.append(h)
    return {"incident_groups": groups, "hypotheses": hyps}


def _simulated_analysis(graph, findings) -> dict:
    """Deterministic analyst output (no model): group findings by host, no hypotheses."""
    by_host: dict = {}
    for f in findings:
        for a in (f.asset_ids or ["?"]):
            by_host.setdefault(a, []).append(f.id)
    groups = [{"name": f"Activity on {_host_label(graph, a)}", "finding_ids": fids,
               "rationale": "deterministic grouping by host (simulated)."}
              for a, fids in by_host.items() if fids]
    return {"incident_groups": groups, "hypotheses": [], "simulated": True}


def analyze(graph, *, window=None, min_severity="informational", run_id=None,
            dispositions=None, max_entities=None, budget_chars=None,
            max_output_tokens=None, mask=None) -> dict:
    """ADVISORY analyst pass over the distilled graph: incident-grouping + grounded
    hypotheses. Reuses the agentic skills corpus for expertise. Never mutates
    graph.findings. Real path is grounding-gated; simulated path is deterministic.
    `max_entities`/`budget_chars` size the LLM payload (the case 'LLM payload' knob).
    `mask` (optional DataAnonymizer) anonymizes the LLM payload the same way
    generate_report() does — previously this pass sent the graph to the LLM
    unmasked even when the case had masking enabled."""
    me = max_entities or budget.REPORT_MAX_ENTITIES
    bc = budget_chars or budget.REPORT_BUDGET_CHARS
    _, findings = render.scope(graph, window=window, min_severity=min_severity)
    if not _use_real():
        return _simulated_analysis(graph, findings)
    try:
        payload = render.distilled(graph, window=window, min_severity=min_severity,
                                   max_entities=me, budget_chars=bc)
        # select the curated DFIR macro playbook FROM THE GRAPH (reuse agentic skills)
        system = ANALYST_SYSTEM_PROMPT
        try:
            from services.agentic.skills import select_macro_skill, compose_system_prompt
            from services.fusion.render import _sev_tally
            mitre = [m for f in findings for m in (f.mitre or [])]
            arts = sorted({e.attrs.get("artifact") for e in graph.entities.values()
                           if e.attrs.get("artifact")})
            macro = select_macro_skill(aggregated_mitre=mitre,
                                       severity_counts=_sev_tally(findings),
                                       artifact_names=arts)
            if macro:
                system = compose_system_prompt(ANALYST_SYSTEM_PROMPT, [macro])
        except Exception:  # noqa: BLE001 — skills are enrichment, never required
            pass
        user = json.dumps(payload)
        if dispositions:
            user += ("\n\nOPERATOR DISPOSITIONS (already triaged — do not re-flag): "
                     + json.dumps(dispositions))
        if mask:                                  # anonymize the LLM input too
            _build_mask_mapping(graph, mask)
            _log_mask_audit(run_id, mask, user)
            user = _apply_mask(user, mask)
            system = _MASK_IDENTITY_LEGEND + system
        raw = _real_llm(system, user, run_id=run_id, max_output_tokens=max_output_tokens)
        raw = _revert_mask(raw, mask)
        return _ground(_parse_json(raw), graph)
    except Exception:  # noqa: BLE001 — advisory only; never break a case
        return _simulated_analysis(graph, findings)


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
                                   run_id=None, mask=None) -> list:
    """Customer-confirmation checklist: per high finding, a likely-benign yes/no question
    the customer accepts (=> dispositioned benign) or declines (=> kept). Grounded to real
    finding_ids; deterministic fallback when no real LLM. Never raises.
    `mask` (optional DataAnonymizer) anonymizes the LLM payload the same way
    generate_report() does — previously this pass sent the graph to the LLM
    unmasked even when the case had masking enabled."""
    _, findings = render.scope(graph, window=window, min_severity=min_severity)
    high = [f for f in findings if sev.at_least(f.severity, "high")] or findings
    if not _use_real():
        return _simulated_checklist(high)
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
        return out or _simulated_checklist(high)
    except Exception:  # noqa: BLE001
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
    "missing_key": "⚠️ No LLM API key is configured. Add a valid key in Settings to use Case Analysis chat.",
    "invalid_key": "⚠️ The LLM API key was rejected — it looks invalid or outdated. Update it in Settings.",
    "no_internet": "⚠️ No connection to the LLM. Check the internet connection and try again.",
    "timeout": "⚠️ The LLM did not respond in time (timeout). Check the connection or the model, then retry.",
    "rate_limited": "⚠️ The LLM provider rate-limited the request. Wait a moment and try again.",
    "missing_offline_url": "⚠️ No local LLM (Ollama) URL is configured. Set it in Settings or switch to an online model.",
    "llm_error": "⚠️ Could not get a response from the LLM. Check the API key and internet connection.",
    "cli_not_installed": "⚠️ The subscription CLI is not installed. Install it in Settings → Agentic (needs internet).",
    "cli_not_authenticated": "⚠️ The subscription is not connected. Sign in from Settings → Agentic (needs internet).",
    "model_unsupported": "⚠️ The vendor rejected the selected model for this subscription. Clear the Model field in Settings → Agentic to use the model your plan allows.",
}


def llm_error_message(reason: str) -> str:
    """Operator-facing message for an LLMUnavailable reason code."""
    return _LLM_ERR_MESSAGES.get(reason, _LLM_ERR_MESSAGES["llm_error"])


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
    s = f"{type(exc).__name__} {exc}".lower()
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
         max_output_tokens=None, require_llm=False, mask=None) -> str:
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
                                           budget_chars=budget.REPORT_BUDGET_CHARS)
            else:
                payload = render.chat_subgraph(graph, question, window=window,
                                               min_severity=min_severity,
                                               max_entities=budget.CHAT_MAX_ENTITIES,
                                               pin_ids=pin_ids, focus_labels=focus)
            if dispositions:
                payload["operator_dispositions"] = dispositions   # so the LLM can answer triage Qs
            if validations:
                payload["analyst_validations"] = validations      # Timeline real/not-real/known
            turns = "".join(f"{m.get('role')}: {m.get('content')}\n" for m in (history or []))
            user = f"{json.dumps(payload)}\n\n{turns}Q: {question}"
            system = CHAT_SYSTEM_PROMPT
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
