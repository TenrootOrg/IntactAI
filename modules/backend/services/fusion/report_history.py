"""Report history — every report written for a case is KEPT, so regenerating
never loses the previous one: view, download (PDF / HTML / MD) or delete it.

ONE entry per timeframe (scope): a new report for a timeframe that already has an
entry replaces it; a new timeframe -- a Refusion over other dates, or "Analyze this
scope" -- gets its own entry.

Files under DATA_DIR/<case_id>/<id>.md; described in the case details under
"report_history": {id, at, sha256, chars, kind: ai | template, scope, scope_label}.

Report stages (Flash / Interim / Final) and report types (Technical, Technical
customers, Directors) were tried on 2026-09-29 and removed — one report again.
Reports kept while they existed carry "stage" or "type" and keep that label.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import uuid
import re

DATA_DIR = "/app/data/case_reports"
LEGACY_LABEL = {"flash": "Flash", "interim": "Interim", "final": "Final", "technical": "Technical",
                "customer": "Technical customers", "directors": "Directors"}
_ID = re.compile(r"[0-9a-f]{12}")
_TEMPLATE_FOOTER = "_Deterministic report"


def _dir(case_id) -> str:
    return os.path.join(DATA_DIR, re.sub(r"[^A-Za-z0-9_.-]", "_", str(case_id)))


def label_of(x) -> str:
    return LEGACY_LABEL.get(x.get("type") or x.get("stage"), "Report")


FULL_SCOPE = "full"       # store.FULL_SCOPE_ID; an entry kept before scopes were recorded belongs here


def history(d, scope=None) -> list:
    """The reports kept for the case, newest first, each with its label. Old
    cases: none; a damaged entry is skipped, never raised.

    `scope`: only that timeframe's reports -- what the Analysis tab lists. Every
    scope has its own reports; the list used to show every scope's rows under
    whichever scope was selected ("both of the reports are being found in both
    scopes"). None = all of them (looking one up by id, the bundle, the tests)."""
    raw = (d or {}).get("report_history") if isinstance(d, dict) else None
    out = []
    for i, x in enumerate(raw if isinstance(raw, list) else []):
        if not (isinstance(x, dict) and _ID.fullmatch(str(x.get("id") or ""))):
            continue
        if scope is not None and str(x.get("scope") or FULL_SCOPE) != str(scope):
            continue
        out.append((str(x.get("at") or ""), i, {
            "id": x["id"], "label": label_of(x), "at": x.get("at"),
            "chars": int(x.get("chars") or 0), "kind": "ai" if x.get("kind") == "ai" else "template",
            "sha256": str(x.get("sha256") or ""), "scope_label": str(x.get("scope_label") or "")}))
    # newest first; two written in the same second: the later-kept one first
    out.sort(key=lambda t: (t[0], t[1]), reverse=True)
    return [t[2] for t in out]


def archive(case_id, md, scope=None, scope_label=None) -> dict | None:
    """Keep this report in the case's history -- one entry per timeframe.

    A report for a timeframe that already has an entry REPLACES it: same id (a View
    link on screen stays valid), new text and time, and it becomes the newest. The
    first scan's template report and the AI report written over it minutes later
    used to be two entries for the one load of data. A report for a new timeframe
    is a new entry. Without a scope (and entries kept before scopes were recorded)
    it is the old rule: a new entry, unless it repeats the newest one's text.
    """
    from . import store
    md = str(md or "")
    if not md.strip():
        return None
    sha = hashlib.sha256(md.encode("utf-8")).hexdigest()
    raw = (store.get_case(case_id) or {}).get("report_history")
    raw = [x for x in (raw if isinstance(raw, list) else [])
           if isinstance(x, dict) and _ID.fullmatch(str(x.get("id") or ""))]
    same = next((x for x in reversed(raw) if x.get("scope") == scope), None) if scope else None
    if same is not None and same.get("sha256") == sha:
        return None
    if scope is None:
        hist = history({"report_history": raw})
        if hist and hist[0]["sha256"] == sha:
            return None
    rid = same["id"] if same is not None else uuid.uuid4().hex[:12]
    os.makedirs(_dir(case_id), exist_ok=True)
    tmp = os.path.join(_dir(case_id), rid + ".part")
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(md)
    os.replace(tmp, os.path.join(_dir(case_id), rid + ".md"))
    item = {"id": rid, "at": store._now_iso(),
            "sha256": sha, "chars": len(md), "kind": "template" if _TEMPLATE_FOOTER in md else "ai"}
    if scope:
        item.update(scope=str(scope), scope_label=str(scope_label or ""))
    store._mutate_list_field(case_id, "report_history",
                             lambda v: [x for x in (v if isinstance(v, list) else [])
                                        if not (isinstance(x, dict) and x.get("id") == rid)] + [item])
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
    label = label_of(gone)
    store.log_case_event(case_id, "Report history", "info", f"{label} report of {gone.get('at')} deleted")
    return {"deleted": rid}


def delete_case_reports(case_id) -> None:
    shutil.rmtree(_dir(case_id), ignore_errors=True)
