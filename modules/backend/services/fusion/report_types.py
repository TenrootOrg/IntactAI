"""Report types — who the report is for — and the history of every report written.

Three readers, three different documents (not the same report in another tone):
  technical  — us, the analysts: the full internal report (the default).
  customer   — the customer's technical team: what happened, affected assets,
               indicators to block, remediation — without our internal triage,
               scoring or tooling.
  directors  — executives and decision makers: about one page, plain language,
               business impact and the decisions needed; nothing technical.

The type changes the instruction to the model (a structure of its own for the
customer and directors reports), a title and a banner, and which of the tables
the system appends are kept. Every report written is KEPT with its type and date.

History: files under DATA_DIR/<case_id>/<id>.md; described in the case details
under "report_history": {id, type, at, sha256, chars, kind: ai | template}.
Entries written before the types existed carry "stage" (flash / interim /
final) and keep that label.
"""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import uuid

TYPES = ("technical", "customer", "directors")
LABEL = {"technical": "Technical", "customer": "Technical customers", "directors": "Directors"}
TITLE = {"technical": "Technical Report", "customer": "Technical Customer Report", "directors": "Directors Report"}
READER = {"technical": "internal — the full detail for the investigating team",
          "customer": "the customer's technical team",
          "directors": "executives and decision makers"}
LEGACY_LABEL = {"flash": "Flash", "interim": "Interim", "final": "Final"}
DATA_DIR = "/app/data/case_reports"
_ID = re.compile(r"[0-9a-f]{12}")
_TEMPLATE_FOOTER = "_Deterministic report"
# banners this version and the stage version before it wrote under the title
_BANNER = re.compile(r"^_Report (?:for|stage): \*\*[^*\n]+\*\* — [^\n]*_\n?", re.M)
_TITLE = re.compile(r"^# (?:(?:Flash|Interim|Final|Technical|Technical Customer|Directors) Report"
                    r"|Incident Case Report|Incident Report)\s+—\s+(.*)$")
_INTERNAL_LINES = re.compile(r"(?m)^(?:_Report detail: \*\*[^\n]*_|_\*\*(?:Focused|Segmented) report\*\* — [^\n]*_"
                             r"|\| \*\*Entities correlated\*\* \|[^\n]*)\n?")
_STATS_BLOCK = re.compile(r"(?m)^(?:> \*\*All timestamps are UTC\.\*\*\n\n\| \| \|\n\|---\|---\|\n(?:\| \*\*[^\n]*\n?)*"
                          r"|_Scope: [^\n]*_\n?)")
_STATUS_BLOCK = re.compile(r"(?ms)^## (?:Status|Containment Status)\n\n_Containment as set on the Risk tab[^\n]*_\n.*?(?=^## |\Z)")
STATUS_LABEL = {"compromised": "Compromised", "isolated": "Quarantined", "quarantined": "Quarantined",
                "reimaged": "Reimaged", "clean": "Clean"}

# Tables the system appends to every AI report after the narrative.
_SYSTEM_TABLES = ("Analyst Validations", "Timeline of Events", "MITRE ATT&CK Mapping",
                  "Host Risk", "Limitations & Assumptions", "Indicators of Compromise",
                  "Cross-Host Correlation", "Suspicious Timeframes", "Timeframes",
                  "Phases at a glance", "Shared across hosts", "Activity outside")
# What each type leaves out of a model-written report (only system tables —
# nothing the model wrote is removed) …
_DROP = {
    "customer": ("Analyst Validations", "Host Risk", "Suspicious Timeframes", "Timeframes",
                 "Phases at a glance", "Shared across hosts", "Activity outside"),
    "directors": _SYSTEM_TABLES,
}
# … and what the offline template keeps.
_TEMPLATE_KEEP = {
    "customer": ("Executive Summary", "Attack Assessment", "Timeline of Events",
                 "Indicators of Compromise", "MITRE ATT&CK Mapping", "Cross-Host Correlation",
                 "Recommendations", "Limitations & Assumptions", "Evidence attached"),
    "directors": ("Executive Summary", "Attack Assessment", "Recommendations"),
}

_NO_INTERNALS = (
    "Do not mention our internal tooling or workflow: no product or feature names (Intact, "
    "Jev, Refusion, fusion, agentic, scopes), no internal confidence scores, and no "
    "analyst-triage mechanics. Name evidence by what it is (Windows event logs, Sysmon, "
    "PowerShell logs, the file table, memory). Activity the analyst marked False Positive "
    "is NOT part of the incident — leave it out; activity marked Known may be mentioned as "
    "expected activity confirmed with the customer. "
    "State only actions that are recorded: containment and case state come from "
    "analyst_case_status and analyst_host_status. Never say or imply that anything was "
    "contained, isolated, cleaned, rebuilt or reset unless it is recorded there; when "
    "nothing is recorded, say plainly that containment has not been recorded yet.")

_DIRECTIVE = {
    "technical": "",            # the full internal report: the default instructions as they are
    "customer": (
        "REPORT FOR: THE CUSTOMER'S TECHNICAL TEAM (IT / security staff of the affected "
        "organisation — technical readers, but outside our team).\n"
        "Use THIS structure instead of the default one:\n"
        "## Summary — 4-6 sentences: what happened, when, how it most likely started, and "
        "the current state.\n"
        "## What Happened — the attack as a chronological narrative with UTC times, hosts, "
        "accounts and the techniques used (ATT&CK names with their IDs are fine).\n"
        "## Affected Assets — a table: Host or account | What was seen | Current status "
        "(from analyst_host_status: compromised / quarantined / reimaged / clean; "
        "'not yet contained' when none is given).\n"
        "## Indicators to Block and Hunt — a table: Type | Value | Context — only indicators "
        "seen in THIS incident (hashes, IPs, domains, file paths, account names).\n"
        "## Remediation Steps — numbered and ordered: Immediate (next 24 h), Short-term "
        "(1-2 weeks), Hardening.\n"
        "## Detection & Monitoring — what to alert on from now on, per technique seen.\n"
        "Technical terms are fine; explain any that are not common knowledge in a few words. "
        + _NO_INTERNALS),
    "directors": (
        "REPORT FOR: DIRECTORS AND EXECUTIVES — non-technical decision makers (CEO, board, "
        "CFO, legal).\n"
        "Use THIS structure instead of the default one — about one page, at most ~450 words:\n"
        "## Bottom Line — 2-3 sentences: what happened, whether it is under control now, and "
        "the overall risk (Critical / High / Medium / Low) in plain words.\n"
        "## Business Impact — what is affected in business terms: which kinds of systems, "
        "people and data; what is confirmed versus only possible; any regulatory or "
        "notification exposure worth considering.\n"
        "## What We Have Done — the investigation so far, and containment ONLY as recorded "
        "in analyst_case_status / analyst_host_status (which machines are isolated, "
        "cleaned or rebuilt); if none is recorded, say containment has not been recorded "
        "yet and list it under Decisions Needed.\n"
        "## Decisions Needed — each a clear question with the recommended option and why "
        "(e.g. 'Approve resetting all administrator passwords tonight — recommended, because "
        "...'). If no decision is needed now, say so.\n"
        "## Next Steps — who does what, and when the next update comes.\n"
        "Rules: NO technical language — no hashes, IP addresses, file paths, command lines, "
        "detection or rule names, ATT&CK IDs, log names. Name tools only by what they do "
        "('a password-stealing tool'). Refer to machines by role and count ('two employee "
        "laptops and one server') unless a name matters for a decision. No tables. Calm and "
        "factual. " + _NO_INTERNALS),
}


def type_of(d) -> str:
    """The report type last chosen for the case; Technical when none (old cases)."""
    t = (d or {}).get("report_type") if isinstance(d, dict) else None
    return t if t in TYPES else "technical"


def directive(rtype) -> str:
    return _DIRECTIVE.get(rtype, "")


def apply(md, rtype, host_status=None, case_status=None) -> str:
    """A freshly written report, shaped for its reader:
      - the title and a banner say which report it is (also on the PDF / HTML cover);
      - customer / directors: only the tables that reader needs (the template keeps
        its matching sections; a model-written report loses only system tables);
      - customer: a Containment Status table from the Risk tab's host statuses."""
    md = _STATUS_BLOCK.sub("", _BANNER.sub("", str(md or "")))
    if rtype not in TYPES or not md.strip():
        return md
    if rtype in _DROP:
        md = (_keep_sections(md, _TEMPLATE_KEEP[rtype]) if _TEMPLATE_FOOTER in md
              else _drop_sections(md, _DROP[rtype]))
        # How WE built it (detail level, focused/segmented, entity counts) means
        # nothing to an outside reader; directors also lose the statistics block.
        md = _INTERNAL_LINES.sub("", md)
        if rtype == "directors":
            md = _STATS_BLOCK.sub("", md)
        md = re.sub(r"\n{3,}", "\n\n", md)
    if rtype == "customer":
        # Before the first section, AFTER the statistics block: _STATUS_BLOCK removes
        # up to the next "## ", so placed above the statistics it took them with it
        # the next time the report was shaped.
        block = _status_block(host_status, case_status) + "\n"
        m = re.search(r"(?m)^## ", md)
        md = md[:m.start()] + block + md[m.start():] if m else md.rstrip() + "\n\n" + block
    banner = f"_Report for: **{LABEL[rtype]}** — {READER[rtype]}._"
    lines = md.split("\n")
    for i, ln in enumerate(lines):
        if ln.startswith("# "):
            m = _TITLE.match(ln)
            name = m.group(1) if m else ln[2:].strip()
            lines[i] = f"# {TITLE[rtype]} — {name}"
            lines.insert(i + 1, "\n" + banner)
            return "\n".join(lines)
    return banner + "\n\n" + md


def wants_evidence(d) -> bool:
    """Directors get no evidence section; the other two do (when it is switched on)."""
    return type_of(d) != "directors"


def _status_block(host_status, case_status) -> str:
    rows = sorted((host_status or {}).items())
    out = ["## Containment Status", "",
           f"_Containment as set on the Risk tab · case status: {str(case_status or 'open').capitalize()}_", ""]
    if rows:
        out += ["| Host | Status |", "|---|---|"]
        out += [f"| {h} | {STATUS_LABEL.get(st, str(st).capitalize())} |" for h, st in rows]
    else:
        out.append("No host has a containment status recorded yet.")
    return "\n".join(out) + "\n"


def _split(md):
    parts = re.split(r"(?m)^(?=## )", md)
    head, secs = parts[0], parts[1:]
    footer = ""
    if secs:
        m = re.search(r"\n\n---\n_(?:Deterministic report|Narrative by live LLM)[\s\S]*$", secs[-1])
        if m:
            footer, secs[-1] = secs[-1][m.start():], secs[-1][:m.start()]
    return head, secs, footer


def _keep_sections(md, keep) -> str:
    head, secs, footer = _split(md)
    return head + "".join(s for s in secs if any(s[3:].startswith(k) for k in keep)) + footer


def _drop_sections(md, drop) -> str:
    head, secs, footer = _split(md)
    return head + "".join(s for s in secs if not any(s[3:].startswith(k) for k in drop)) + footer


# ---- history -----------------------------------------------------------------
def _dir(case_id) -> str:
    return os.path.join(DATA_DIR, re.sub(r"[^A-Za-z0-9_.-]", "_", str(case_id)))


def history(d) -> list:
    """Every report kept for the case, newest first, each with its label. Old
    cases: none; a damaged entry is skipped, never raised."""
    raw = (d or {}).get("report_history") if isinstance(d, dict) else None
    out = []
    for i, x in enumerate(raw if isinstance(raw, list) else []):
        if not (isinstance(x, dict) and _ID.fullmatch(str(x.get("id") or ""))):
            continue
        t = x.get("type") if x.get("type") in TYPES else None
        label = LABEL[t] if t else LEGACY_LABEL.get(x.get("stage"), "Report")
        out.append((str(x.get("at") or ""), i, {
            "id": x["id"], "type": t or "", "label": label, "at": x.get("at"),
            "chars": int(x.get("chars") or 0), "kind": "ai" if x.get("kind") == "ai" else "template",
            "sha256": str(x.get("sha256") or "")}))
    # newest first; two written in the same second: the later-kept one first
    out.sort(key=lambda t: (t[0], t[1]), reverse=True)
    return [t[2] for t in out]


def archive(case_id, md, rtype) -> dict | None:
    """Keep this report in the case's history. Not again when it is the same text
    as the newest kept one (a Refusion that reused the report)."""
    from . import store
    md = str(md or "")
    if not md.strip():
        return None
    sha = hashlib.sha256(md.encode("utf-8")).hexdigest()
    hist = history(store.get_case(case_id) or {})
    if hist and hist[0]["sha256"] == sha:
        return None
    rid = uuid.uuid4().hex[:12]
    os.makedirs(_dir(case_id), exist_ok=True)
    tmp = os.path.join(_dir(case_id), rid + ".part")
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(md)
    os.replace(tmp, os.path.join(_dir(case_id), rid + ".md"))
    item = {"id": rid, "type": rtype if rtype in TYPES else "technical", "at": store._now_iso(),
            "sha256": sha, "chars": len(md), "kind": "template" if _TEMPLATE_FOOTER in md else "ai"}
    store._mutate_list_field(case_id, "report_history",
                             lambda v: (v if isinstance(v, list) else []) + [item])
    return item


def read(case_id, rid) -> str | None:
    if not _ID.fullmatch(str(rid or "")):
        return None
    try:
        with open(os.path.join(_dir(case_id), rid + ".md"), encoding="utf-8") as fh:
            return fh.read()
    except OSError:
        return None


def delete(case_id, rid) -> dict:
    from . import store
    if not _ID.fullmatch(str(rid or "")):
        return {"error": "no such report"}
    gone = {}

    def _mutate(vals):
        keep = []
        for v in vals if isinstance(vals, list) else []:
            (gone.update(v) if isinstance(v, dict) and v.get("id") == rid else keep.append(v))
        return keep

    store._mutate_list_field(case_id, "report_history", _mutate)
    if not gone:
        return {"error": "no such report"}
    try:
        os.remove(os.path.join(_dir(case_id), rid + ".md"))
    except OSError:
        pass
    label = LABEL.get(gone.get("type")) or LEGACY_LABEL.get(gone.get("stage"), "Report")
    store.log_case_event(case_id, "Report history", "info", f"{label} report of {gone.get('at')} deleted")
    return {"deleted": rid}


def delete_case_reports(case_id) -> None:
    shutil.rmtree(_dir(case_id), ignore_errors=True)
