"""Report stages and report history (plan step 9).

DFIR engagements report in stages (NIST SP 800-61, SANS): a FLASH in the first
hours, INTERIM reports while the case is open, a FINAL at closure. The stage
changes how the next report is written — an instruction to the model (as the
audience choice is), a banner under the title, and for the offline template a
shorter Flash. Every report written is KEPT with its stage and date, so an
Interim never overwrites the Final that was sent to the customer.

History: files under DATA_DIR/<case_id>/<id>.md; described in the case details
under "report_history": {id, stage, at, sha256, chars, kind: ai | template}.
"""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import uuid

STAGES = ("flash", "interim", "final")
LABEL = {"flash": "Flash", "interim": "Interim", "final": "Final"}
MEANING = {"flash": "initial notification", "interim": "investigation ongoing", "final": "case closed"}
DATA_DIR = "/app/data/case_reports"
_ID = re.compile(r"[0-9a-f]{12}")
_BANNER = re.compile(r"^_Report stage: \*\*[A-Za-z]+\*\* — [^\n]*_\n?", re.M)
_TEMPLATE_FOOTER = "_Deterministic report"
# A Flash from the offline template keeps only these sections.
FLASH_KEEP = ("Executive Summary", "Attack Assessment", "Host Risk", "Recommendations",
              "Evidence attached")
# A Flash written by the model loses the long fact tables the system appends to
# every AI report — only those; nothing the model wrote is removed.
FLASH_DROP = ("Timeline of Events", "MITRE ATT&CK Mapping", "Indicators of Compromise",
              "Limitations & Assumptions", "Cross-Host Correlation", "Suspicious Timeframes",
              "Timeframes", "Phases at a glance", "Shared across hosts", "Activity outside",
              "Host Risk", "Analyst Validations")
_TITLE = re.compile(r"^# (?:(?:Flash|Interim|Final) Report|Incident Case Report|Incident Report)\s+—\s+(.*)$")
STATUS_LABEL = {"compromised": "Compromised", "isolated": "Quarantined", "quarantined": "Quarantined",
                "reimaged": "Reimaged", "clean": "Clean"}

_DIRECTIVE = {
    "flash": (
        "REPORT STAGE: FLASH — the initial notification, written in the first hours.\n"
        "Replace the full report structure with a SHORT report, at most about two pages:\n"
        "## Executive Summary — what is known now, in 3-5 sentences, and how sure.\n"
        "## Affected Hosts & Accounts — bullets, each with why it is affected.\n"
        "## Immediate Containment — what to do now, most urgent first.\n"
        "## Open Questions — what is not known yet and is being investigated.\n"
        "## Next Update — what the next report will cover.\n"
        "Do NOT write the per-finding catalogue, the timeline, the MITRE mapping or the "
        "IOC tables — they belong in the Interim and Final reports."),
    "interim": (
        "REPORT STAGE: INTERIM — the investigation is ongoing.\n"
        "Keep the full report structure. A Status block (containment per host) is added "
        "at the top by the system — do NOT write your own Status section. Mark "
        "conclusions as provisional wherever the evidence is not complete yet, and end "
        "the narrative with:\n"
        "## Open Questions — what is not known yet and is still being investigated."),
    "final": (
        "REPORT STAGE: FINAL — the case is closed.\n"
        "Keep the full report structure; state conclusions definitively where the "
        "evidence supports them, and say plainly what remains undetermined. Add a last "
        "section:\n"
        "## Lessons Learned — what worked in detection and response, the gaps in "
        "visibility, tooling or process this incident exposed, and the improvements "
        "that would have caught it earlier."),
}


def _case_status(d) -> str:
    st = str((d or {}).get("case_status") or "").lower() if isinstance(d, dict) else ""
    return st if st in ("open", "contained", "closed") else "open"


def stage_of(d) -> str:
    """The case's report stage: the one last chosen, else from the case status
    (Closed -> Final, otherwise Interim). Old cases have none -> Interim."""
    st = (d or {}).get("report_stage") if isinstance(d, dict) else None
    if st in STAGES:
        return st
    return "final" if _case_status(d) == "closed" else "interim"


def directive(stage) -> str:
    return _DIRECTIVE.get(stage, "")


def apply(md, stage, host_status=None, case_status=None) -> str:
    """A freshly written report, marked with its stage:
      - the title says it: "# Flash Report — <case>" (also the PDF / HTML cover);
      - a banner under the title;
      - Flash: short — the template keeps only its short sections; a model-written
        Flash loses the long fact tables the system appends;
      - Interim: a Status block at the top, built by the system from the Risk
        tab's host statuses ({host name: status}) and the case status."""
    md = _BANNER.sub("", str(md or ""))
    md = _STATUS_BLOCK.sub("", md)
    if stage not in STAGES or not md.strip():
        return md
    if stage == "flash":
        md = (_keep_sections(md, FLASH_KEEP) if _TEMPLATE_FOOTER in md
              else _drop_sections(md, FLASH_DROP))
    banner = f"_Report stage: **{LABEL[stage]}** — {MEANING[stage]}._"
    extra = ("\n\n" + _status_block(host_status, case_status)) if stage == "interim" else ""
    lines = md.split("\n")
    for i, ln in enumerate(lines):
        if ln.startswith("# "):
            m = _TITLE.match(ln)
            name = m.group(1) if m else ln[2:].strip()
            lines[i] = f"# {LABEL[stage]} Report — {name}"
            lines.insert(i + 1, "\n" + banner + extra)
            return "\n".join(lines)
    return banner + extra + "\n\n" + md


_STATUS_BLOCK = re.compile(r"(?ms)^## Status\n\n_Containment as set on the Risk tab[^\n]*_\n.*?(?=^## |\Z)")


def _status_block(host_status, case_status) -> str:
    rows = sorted((host_status or {}).items())
    out = ["## Status", "",
           f"_Containment as set on the Risk tab · case status: {str(case_status or 'open').capitalize()}_", ""]
    if rows:
        out += ["| Host | Status |", "|---|---|"]
        out += [f"| {h} | {STATUS_LABEL.get(st, str(st).capitalize())} |" for h, st in rows]
    else:
        out.append("No host has a status yet — set them on the Risk tab (Compromised, Quarantined, "
                   "Reimaged, Clean).")
    return "\n".join(out) + "\n"


def _drop_sections(md, drop) -> str:
    """Remove every "## " section whose title starts with one of `drop`."""
    parts = re.split(r"(?m)^(?=## )", md)
    head, secs = parts[0], parts[1:]
    footer = ""
    if secs:
        m = re.search(r"\n\n---\n_(?:Deterministic report|Narrative by live LLM)[\s\S]*$", secs[-1])
        if m:
            footer, secs[-1] = secs[-1][m.start():], secs[-1][:m.start()]
    kept = [s for s in secs if not any(s[3:].startswith(k) for k in drop)]
    return head + "".join(kept) + footer


def _keep_sections(md, keep) -> str:
    """Drop every "## " section whose title does not start with one of `keep`;
    the text before the first section and the closing footer stay."""
    parts = re.split(r"(?m)^(?=## )", md)
    head, secs = parts[0], parts[1:]
    footer = ""
    if secs:
        m = re.search(r"\n\n---\n_(?:Deterministic report|Narrative by live LLM)[\s\S]*$", secs[-1])
        if m:
            footer, secs[-1] = secs[-1][m.start():], secs[-1][:m.start()]
    kept = [s for s in secs if any(s[3:].startswith(k) for k in keep)]
    return head + "".join(kept) + footer


# ---- history -----------------------------------------------------------------
def _dir(case_id) -> str:
    return os.path.join(DATA_DIR, re.sub(r"[^A-Za-z0-9_.-]", "_", str(case_id)))


def history(d) -> list:
    """Every report kept for the case, newest first. Old cases: none; a damaged
    entry is skipped, never raised."""
    raw = (d or {}).get("report_history") if isinstance(d, dict) else None
    out = []
    for i, x in enumerate(raw if isinstance(raw, list) else []):
        if isinstance(x, dict) and _ID.fullmatch(str(x.get("id") or "")):
            out.append((str(x.get("at") or ""), i, {
                "id": x["id"], "stage": x.get("stage") if x.get("stage") in STAGES else "interim",
                "at": x.get("at"), "chars": int(x.get("chars") or 0),
                "kind": "ai" if x.get("kind") == "ai" else "template",
                "sha256": str(x.get("sha256") or "")}))
    # newest first; two written in the same second: the later-kept one first
    out.sort(key=lambda t: (t[0], t[1]), reverse=True)
    return [t[2] for t in out]


def archive(case_id, md, stage) -> dict | None:
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
    item = {"id": rid, "stage": stage if stage in STAGES else "interim", "at": store._now_iso(),
            "sha256": sha, "chars": len(md), "kind": "template" if _TEMPLATE_FOOTER in md else "ai"}
    store._mutate_list_field(case_id, "report_history",
                             lambda v: (v if isinstance(v, list) else []) + [item])
    return item


def read(case_id, rid) -> str | None:
    if not _ID.fullmatch(str(rid or "")):
        return None
    p = os.path.join(_dir(case_id), rid + ".md")
    try:
        with open(p, encoding="utf-8") as fh:
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
    store.log_case_event(case_id, "Report history", "info",
                         f"{LABEL.get(gone.get('stage'), 'Report')} report of {gone.get('at')} deleted")
    return {"deleted": rid}


def delete_case_reports(case_id) -> None:
    shutil.rmtree(_dir(case_id), ignore_errors=True)
