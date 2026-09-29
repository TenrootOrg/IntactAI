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
              "Analyst Validations", "Evidence attached")

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
        "Keep the full report structure, and add right after the Executive Summary:\n"
        "## Status — containment per host (use analyst_host_status when given: "
        "compromised / quarantined / reimaged / clean), what is confirmed so far, and "
        "the open questions still being investigated.\n"
        "Mark conclusions as provisional wherever the evidence is not complete yet."),
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


def apply(md, stage) -> str:
    """A freshly written report, marked with its stage: a banner under the title,
    and — for the offline template only — a Flash cut to its short sections."""
    md = _BANNER.sub("", str(md or ""))
    if stage not in STAGES or not md.strip():
        return md
    if stage == "flash" and _TEMPLATE_FOOTER in md:
        md = _keep_sections(md, FLASH_KEEP)
    banner = f"_Report stage: **{LABEL[stage]}** — {MEANING[stage]}._\n"
    lines = md.split("\n")
    for i, ln in enumerate(lines):
        if ln.startswith("# "):
            lines.insert(i + 1, "\n" + banner.rstrip("\n"))
            return "\n".join(lines)
    return banner + "\n" + md


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
