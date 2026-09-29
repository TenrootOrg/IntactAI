"""Evidence the analyst attaches to a case — screenshots, e-mails, logs,
exports from TimeSketch / Kibana / IRIS (plan step 6).

Every item has a NAME and a DESCRIPTION (both required), the file (original file
name, size, type, SHA-256), and what it belongs to: host, time, source, and —
when attached from a Timeline event — that event. Stored on the appliance under
DATA_DIR/<case_id>/<id>; described in the case details under "case_files".

The model sees an item ONLY when "Include in AI" is set (off by default): its
name, description and linked event; a text file's text too (capped, masked with
the rest of the case). Never a picture's pixels.
"""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import uuid

DATA_DIR = "/app/data/case_files"
MAX_BYTES = 100 * 1024 * 1024
AI_TEXT_CAP = 20_000
SOURCES = ("timeline", "timesketch", "kibana", "iris", "velociraptor", "other")
_IMAGE = (".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".tif", ".tiff")
_TEXT = (".txt", ".log", ".csv", ".tsv", ".json", ".jsonl", ".eml", ".md", ".xml", ".yaml", ".yml",
         ".ini", ".cfg", ".conf", ".ps1", ".psm1", ".bat", ".cmd", ".sh", ".vbs", ".js", ".html", ".htm")
_ID = re.compile(r"[0-9a-f]{12}")


def _store():
    from . import store
    return store


def _dir(case_id) -> str:
    return os.path.join(DATA_DIR, re.sub(r"[^A-Za-z0-9_.-]", "_", str(case_id)))


def _kind(file_name) -> str:
    n = str(file_name or "").lower()
    return "image" if n.endswith(_IMAGE) else "text" if n.endswith(_TEXT) else "other"


def _clean_file_name(name) -> str:
    n = os.path.basename(str(name or "").replace("\\", "/")).replace("\x00", "").strip()
    return n[:200] or "file"


def _s(v, cap) -> str:
    return v.strip()[:cap] if isinstance(v, str) else ""


def listing(d) -> list:
    """The case's evidence. Cases from older versions have none; a damaged entry
    is skipped, never raised. Items from the first version of this feature (no
    title, no description) show their file name as the name."""
    raw = (d or {}).get("case_files") if isinstance(d, dict) else None
    out = []
    for x in raw if isinstance(raw, list) else []:
        if not (isinstance(x, dict) and _ID.fullmatch(str(x.get("id") or "")) and x.get("name")):
            continue
        fname = _s(x.get("file_name"), 200) or str(x["name"])
        out.append({"id": x["id"], "name": str(x["name"]), "description": _s(x.get("description"), 1000),
                    "file_name": fname, "size": int(x.get("size") or 0), "sha256": str(x.get("sha256") or ""),
                    "kind": x.get("kind") or _kind(fname), "ai": bool(x.get("ai")),
                    "host": _s(x.get("host"), 200), "time": _s(x.get("time"), 40),
                    "source": x.get("source") if x.get("source") in SOURCES else "other",
                    "finding_id": _s(x.get("finding_id"), 100), "finding_title": _s(x.get("finding_title"), 300),
                    "added_at": x.get("added_at")})
    return out


def path_of(case_id, file_id) -> str | None:
    if not _ID.fullmatch(str(file_id or "")):
        return None
    p = os.path.join(_dir(case_id), file_id)
    return p if os.path.isfile(p) else None


def _event(case_id, finding_id) -> dict | None:
    """Host, time and title of a Timeline row — read from the case itself, never
    trusted from the browser."""
    st = _store()
    from .correlate import _part_ids
    g = st.load_graph(case_id)
    # a part of a bundled row (one rule / file / detection) links to its ROW
    f = next((f for f in g.findings if finding_id in f.ids() or finding_id in _part_ids(f)), None)
    if f is None:
        return None
    hosts = []
    for a in f.asset_ids or []:
        e = g.entities.get(a)
        hosts.append(e.label if e is not None else a)
    return {"finding_id": f.id, "finding_title": f.title, "host": ", ".join(hosts), "time": f.ts or ""}


def add(case_id, stream, file_name, *, name, description, host="", time="", source="", finding_id="") -> dict:
    """Save one evidence file; its SHA-256 is computed while it is written."""
    st = _store()
    if not st.get_case(case_id):
        return {"error": "case not found"}
    name, description = _s(name, 200), _s(description, 1000)
    if not name or not description:
        return {"error": "give the evidence a name and a description"}
    link = {}
    if _s(finding_id, 100):
        link = _event(case_id, _s(finding_id, 100))
        if not link:
            return {"error": "that Timeline event is not in the case any more — refresh and try again"}
    fname = _clean_file_name(file_name)
    fid = uuid.uuid4().hex[:12]
    os.makedirs(_dir(case_id), exist_ok=True)
    dest, tmp = os.path.join(_dir(case_id), fid), os.path.join(_dir(case_id), fid + ".part")
    h, size = hashlib.sha256(), 0
    try:
        with open(tmp, "wb") as out:
            while True:
                chunk = stream.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_BYTES:
                    raise ValueError(f"the file is larger than {MAX_BYTES // (1024 * 1024)} MB")
                h.update(chunk)
                out.write(chunk)
        if not size:
            raise ValueError("the file is empty")
        os.replace(tmp, dest)
    except ValueError as e:
        _unlink(tmp)
        return {"error": str(e)}
    item = {"id": fid, "name": name, "description": description, "file_name": fname, "size": size,
            "sha256": h.hexdigest(), "kind": _kind(fname), "ai": False,
            "host": link.get("host") or _s(host, 200), "time": link.get("time") or _s(time, 40),
            "source": "timeline" if link else (source if source in SOURCES else "other"),
            "finding_id": link.get("finding_id", ""), "finding_title": link.get("finding_title", ""),
            "added_at": st._now_iso()}
    st._mutate_list_field(case_id, "case_files", lambda v: (v if isinstance(v, list) else []) + [item])
    st.log_case_event(case_id, "Evidence added", "info",
                      f"{name} — {fname} ({size:,} bytes) · SHA-256 {item['sha256']}"
                      + (f" · linked to {item['finding_title']}" if link else ""))
    return next(x for x in listing({"case_files": [item]}))


def update(case_id, file_id, fields) -> dict:
    """Edit name, description, host, time, source, "Include in AI"; finding_id ""
    unlinks the Timeline event. Name and description cannot be emptied."""
    st = _store()
    if not st.get_case(case_id):
        return {"error": "case not found"}
    fields = fields if isinstance(fields, dict) else {}
    for k in ("name", "description"):
        if k in fields and not _s(fields.get(k), 1000):
            return {"error": f"the {k} cannot be empty"}
    if "source" in fields and fields.get("source") not in SOURCES:
        return {"error": f"source must be one of: {', '.join(SOURCES)}"}
    found, old = {}, {}

    def _mutate(vals):
        vals = vals if isinstance(vals, list) else []
        for v in vals:
            if isinstance(v, dict) and v.get("id") == file_id:
                old.update(v)
                for k, cap in (("name", 200), ("description", 1000), ("host", 200), ("time", 40)):
                    if k in fields:
                        v[k] = _s(fields.get(k), cap)
                if "source" in fields:
                    v["source"] = fields["source"]
                if "ai" in fields:
                    v["ai"] = bool(fields.get("ai"))
                if "finding_id" in fields and not _s(fields.get("finding_id"), 100):
                    v["finding_id"], v["finding_title"] = "", ""
                found.update(v)
        return vals

    st._mutate_list_field(case_id, "case_files", _mutate)
    if not found:
        return {"error": "no such evidence"}
    changed = [k for k in ("name", "description", "host", "time", "source", "ai", "finding_id")
               if k in fields and old.get(k) != found.get(k)]
    if changed:
        st.log_case_event(case_id, "Evidence edited", "info", f"{found.get('name')}: {', '.join(changed)}")
    return next(x for x in listing({"case_files": [found]}))


def delete(case_id, file_id) -> dict:
    st = _store()
    if not st.get_case(case_id):
        return {"error": "case not found"}
    gone = {}

    def _mutate(vals):
        keep = []
        for v in vals if isinstance(vals, list) else []:
            (gone.update(v) if isinstance(v, dict) and v.get("id") == file_id else keep.append(v))
        return keep

    st._mutate_list_field(case_id, "case_files", _mutate)
    if not gone:
        return {"error": "no such evidence"}
    p = path_of(case_id, file_id)
    if p:
        _unlink(p)
    st.log_case_event(case_id, "Evidence deleted", "info",
                      f"{gone.get('name')} — {gone.get('file_name') or gone.get('name')} · SHA-256 {gone.get('sha256')}")
    return {"deleted": file_id}


def delete_case_files(case_id) -> None:
    """The case itself was deleted: its evidence goes with it."""
    shutil.rmtree(_dir(case_id), ignore_errors=True)


def per_finding(d) -> dict:
    """{finding id: how many evidence items are linked to it} — for the Timeline."""
    out: dict = {}
    for f in listing(d):
        if f["finding_id"]:
            out[f["finding_id"]] = out.get(f["finding_id"], 0) + 1
    return out


def for_model(case_id, d) -> list:
    """What "Include in AI" hands the model: name, description, file, type, host,
    time, linked event; a text file's text too (capped). Nothing for the rest."""
    out = []
    for f in listing(d):
        if not f["ai"]:
            continue
        item = {"evidence": f["name"], "file": f["file_name"], "type": f["kind"]}
        for k in ("description", "host", "time", "source"):
            if f[k]:
                item[k] = f[k]
        if f["finding_title"]:
            item["supports_finding"] = f["finding_title"]
        if f["kind"] == "text":
            p = path_of(case_id, f["id"])
            if p:
                try:
                    with open(p, "rb") as fh:
                        raw = fh.read(AI_TEXT_CAP * 4)
                    if b"\x00" not in raw[:4096]:
                        txt = raw.decode("utf-8", "replace")
                        item["text"] = txt[:AI_TEXT_CAP] + ("…[cut]" if len(txt) > AI_TEXT_CAP else "")
                except OSError:
                    pass
        out.append(item)
    return out


def _unlink(p) -> None:
    try:
        os.remove(p)
    except OSError:
        pass
