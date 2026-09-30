"""Report history — every report written for a case is KEPT, so regenerating
never loses the previous one: view, download (PDF / HTML / MD) or delete it.

Files under DATA_DIR/<case_id>/<id>.md; described in the case details under
"report_history": {id, at, sha256, chars, kind: ai | template}.

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


def history(d) -> list:
    """Every report kept for the case, newest first, each with its label. Old
    cases: none; a damaged entry is skipped, never raised."""
    raw = (d or {}).get("report_history") if isinstance(d, dict) else None
    out = []
    for i, x in enumerate(raw if isinstance(raw, list) else []):
        if not (isinstance(x, dict) and _ID.fullmatch(str(x.get("id") or ""))):
            continue
        out.append((str(x.get("at") or ""), i, {
            "id": x["id"], "label": label_of(x), "at": x.get("at"),
            "chars": int(x.get("chars") or 0), "kind": "ai" if x.get("kind") == "ai" else "template",
            "sha256": str(x.get("sha256") or "")}))
    # newest first; two written in the same second: the later-kept one first
    out.sort(key=lambda t: (t[0], t[1]), reverse=True)
    return [t[2] for t in out]


def archive(case_id, md) -> dict | None:
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
    item = {"id": rid, "at": store._now_iso(),
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
    label = label_of(gone)
    store.log_case_event(case_id, "Report history", "info", f"{label} report of {gone.get('at')} deleted")
    return {"deleted": rid}


def delete_case_reports(case_id) -> None:
    shutil.rmtree(_dir(case_id), ignore_errors=True)
