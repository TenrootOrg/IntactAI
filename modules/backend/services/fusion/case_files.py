"""Files the analyst attaches to a case — screenshots, e-mails, logs, documents
(plan step 6).

Stored on the appliance under DATA_DIR/<case_id>/<file id>; described in the
case details under "case_files": {id, name, size, sha256, kind, description, ai,
added_at}. The model sees a file ONLY when its "Include in AI" flag is set (off
by default): a picture by its name and description — never the image itself —
and a text file by its text, capped, masked with the rest of the case.
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
_IMAGE = (".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".tif", ".tiff")
_TEXT = (".txt", ".log", ".csv", ".tsv", ".json", ".jsonl", ".eml", ".md", ".xml", ".yaml", ".yml",
         ".ini", ".cfg", ".conf", ".ps1", ".psm1", ".bat", ".cmd", ".sh", ".vbs", ".js", ".html", ".htm")


def _store():
    from . import store
    return store


def _dir(case_id) -> str:
    return os.path.join(DATA_DIR, re.sub(r"[^A-Za-z0-9_.-]", "_", str(case_id)))


def _kind(name) -> str:
    n = str(name or "").lower()
    return "image" if n.endswith(_IMAGE) else "text" if n.endswith(_TEXT) else "other"


def _clean_name(name) -> str:
    n = os.path.basename(str(name or "").replace("\\", "/")).replace("\x00", "").strip()
    return n[:200] or "file"


def listing(d) -> list:
    """The case's files. Cases from older versions have none; a damaged entry is
    skipped, never raised."""
    raw = (d or {}).get("case_files") if isinstance(d, dict) else None
    out = []
    for x in raw if isinstance(raw, list) else []:
        if isinstance(x, dict) and re.fullmatch(r"[0-9a-f]{12}", str(x.get("id") or "")) and x.get("name"):
            out.append({"id": x["id"], "name": str(x["name"]), "size": int(x.get("size") or 0),
                        "sha256": str(x.get("sha256") or ""), "kind": x.get("kind") or _kind(x["name"]),
                        "description": str(x.get("description") or ""), "ai": bool(x.get("ai")),
                        "added_at": x.get("added_at")})
    return out


def path_of(case_id, file_id) -> str | None:
    if not re.fullmatch(r"[0-9a-f]{12}", str(file_id or "")):
        return None
    p = os.path.join(_dir(case_id), file_id)
    return p if os.path.isfile(p) else None


def add(case_id, stream, filename, description="") -> dict:
    """Save an upload; its SHA-256 is computed while it is written."""
    st = _store()
    if not st.get_case(case_id):
        return {"error": "case not found"}
    name = _clean_name(filename)
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
    item = {"id": fid, "name": name, "size": size, "sha256": h.hexdigest(), "kind": _kind(name),
            "description": str(description or "").strip()[:500], "ai": False, "added_at": st._now_iso()}
    st._mutate_list_field(case_id, "case_files", lambda v: (v if isinstance(v, list) else []) + [item])
    st.log_case_event(case_id, "Case file added", "info", f"{name} ({size:,} bytes) · SHA-256 {item['sha256']}")
    return item


def update(case_id, file_id, *, name=None, description=None, ai=None) -> dict:
    st = _store()
    if not st.get_case(case_id):
        return {"error": "case not found"}
    if name is not None:
        name = _clean_name(name)
    found, old = {}, {}

    def _mutate(vals):
        vals = vals if isinstance(vals, list) else []
        for v in vals:
            if isinstance(v, dict) and v.get("id") == file_id:
                old.update(v)
                if name is not None:
                    v["name"], v["kind"] = name, _kind(name)
                if description is not None:
                    v["description"] = str(description).strip()[:500]
                if ai is not None:
                    v["ai"] = bool(ai)
                found.update(v)
        return vals

    st._mutate_list_field(case_id, "case_files", _mutate)
    if not found:
        return {"error": "no such file"}
    if name is not None and name != old.get("name"):
        st.log_case_event(case_id, "Case file renamed", "info", f"{old.get('name')} → {name}")
    if ai is not None and bool(ai) != bool(old.get("ai")):
        st.log_case_event(case_id, "Case file", "info", f"{found['name']}: {'included in' if ai else 'excluded from'} AI")
    return {k: found[k] for k in ("id", "name", "size", "sha256", "kind", "description", "ai", "added_at") if k in found}


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
        return {"error": "no such file"}
    p = path_of(case_id, file_id)
    if p:
        _unlink(p)
    st.log_case_event(case_id, "Case file deleted", "info", f"{gone.get('name')} · SHA-256 {gone.get('sha256')}")
    return {"deleted": file_id}


def delete_case_files(case_id) -> None:
    """The case itself was deleted: its files go with it."""
    shutil.rmtree(_dir(case_id), ignore_errors=True)


def for_model(case_id, d) -> list:
    """What "Include in AI" hands the model: every flagged file's name, type and
    description; a text file's text too (capped). Nothing for unflagged files."""
    out = []
    for f in listing(d):
        if not f["ai"]:
            continue
        item = {"file": f["name"], "type": f["kind"]}
        if f["description"]:
            item["description"] = f["description"]
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
