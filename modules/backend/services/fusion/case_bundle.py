#!/usr/bin/env python3
"""Portable case bundles — move a whole case between Intact appliances.

An engagement is analysed on the customer's (usually air-gapped) appliance and
then has to continue on ours. What has to survive that move is not the pretty
output — it is everything the case cannot be rebuilt from:

  - the operator's decisions (dispositions, timeline validations, manual events,
    checklist answers, identity merges) — irreplaceable by definition;
  - the report and chat — reproducible only by paying an LLM again, and never
    word for word;
  - the COLLECTED DATA itself: /data/downloads/<run_id>/raw_results.json and
    memory_payload.json. On the destination there is no Velociraptor holding the
    original flow and no VolWeb holding the yara hits, so if those files stay
    behind the imported case can be looked at but never recomputed — frozen the
    day it was exported.

That last point is the whole architecture. Because the payloads travel, a
future release can always RE-FUSE an imported case with its own engine, which
is what makes the forward-compatibility promise real: an old bundle does not
have to be understood in detail by a new release, it only has to be re-fusable.
See CASE_BUNDLE_CONTRACT.md, which the next release is expected to honour.

The bundle is therefore a ZIP with a manifest, not one JSON document — a single
member payload is ~547 MB, so nothing is ever held whole in memory: files are
streamed in and out a chunk at a time and checksummed in the same pass.

Two rules that are easy to get wrong and expensive to discover later:

  * RUN IDS ARE NEVER REUSED. Ids are `<type>_<epoch_ms>`, so two appliances
    collecting at the same moment mint the same id. The previous implementation
    preserved source ids and saved with INSERT OR REPLACE, which silently
    overwrote whatever the destination already had under that id and re-tagged
    it into the new case — stealing a run out of somebody else's case. Import
    mints fresh ids and rewrites every reference to them.
  * NOTHING SYSTEM-WIDE TRAVELS. A bundle is one case: no keys, no settings, no
    users, no other cases, and not the case's own activity log (an audit trail
    of who did what on the customer's appliance is theirs, not ours). The
    imported case starts a fresh log with one entry describing the import.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import zipfile
from datetime import datetime, timezone

from services import archive_guard

# ── bundle identity ──────────────────────────────────────────────────────────
EXPORT_KIND = "intact_case_export"

# 1 = the original single-JSON bundle (metadata only, never shipped — its UI was
#     hidden from the day it was written). Not accepted: it carries no payloads,
#     so importing one produces a case that can never be re-fused. Re-export on
#     the source appliance instead.
# 2 = this ZIP layout.
BUNDLE_SCHEMA = 2
MAX_SUPPORTED_SCHEMA = 2

MANIFEST_NAME = "manifest.json"
BUNDLE_EXT = ".intactcase.zip"

# Only these paths are ever read out of a bundle, and only when the manifest
# lists them. This — not the entry names in the zip — is the traversal defence:
# a member called "../../etc/passwd" is not matched by the pattern, and a member
# absent from the manifest is never extracted at all.
_ARC_RE = re.compile(
    r"^(?:case\.json|graph\.json"
    r"|runs/[A-Za-z0-9_]+\.json"
    r"|payloads/[A-Za-z0-9_]+/(?:raw_results|memory_payload)\.json"
    r"|aws_runs/[A-Za-z0-9_]+\.json)$")

_RUN_ID_RE = re.compile(r"^[A-Za-z0-9_]+$")

# ── where things live on disk ────────────────────────────────────────────────
# Export archives land on the big named volume (report_downloads), the same one
# that already holds the 547 MB-per-run payloads — it is the volume provisioned
# for data at this scale, and it survives a container recreate. The Maintenance
# "Report Downloads" purge wipes it; that is acceptable and handled: the
# download route answers 410 and the operator exports again.
EXPORT_DIR = "/data/downloads/case_exports"

# Payload readers in store.py try /app/data/downloads first, then /data/downloads
# (only the second is ever written). Mirror that order when collecting, and write
# where the pipelines write, so an imported run is indistinguishable from a local
# one to every reader.
DOWNLOAD_DIRS = ("/app/data/downloads", "/data/downloads")
DOWNLOAD_WRITE_DIR = "/data/downloads"
AWS_DIRS = ("/app/data/aws_runs", "/data/aws_runs")
AWS_WRITE_DIR = "/app/data/aws_runs"

PAYLOAD_FILES = ("raw_results.json", "memory_payload.json")

_CHUNK = 4 * 1024 * 1024

# Details the case row must NOT carry across an appliance boundary.
#   fusion_graph        — travels as graph.json; legacy cases kept it inline and
#                         that is exactly the 8-18s-per-call cliff the sidecar
#                         split fixed (see store.py's sidecar section)
#   activity_log        — the customer's audit trail; a fresh one is seeded
#   is_default/is_system— an imported case is always an ordinary case
#   auto_fuse_incomplete— a crash-loop marker about the SOURCE appliance's memory
_STRIP_FROM_CASE = ("fusion_graph", "activity_log", "is_default", "is_system",
                    "auto_fuse_incomplete")


class BundleError(Exception):
    """Operator-facing: says what is wrong with the bundle and what to do."""


# ── lazy collaborators (keeps this module unit-testable without the backend) ──
def _store():
    from services.fusion import store
    return store


def _ws():
    from services import workflow_service
    return workflow_service


def product_version() -> str:
    """The release that produced (or is reading) a bundle. Same VERSION file the
    /api/version route reads; 'unknown' rather than an exception if absent."""
    try:
        base = os.environ.get("INTACT_PATH", "/app/workdir")
        with open(os.path.join(base, "VERSION")) as f:
            return f.read().strip() or "unknown"
    except Exception:
        return "unknown"


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def safe_name(s, limit=60) -> str:
    out = "".join(c if (c.isalnum() or c in "-_") else "_" for c in (s or "case"))
    return out.strip("_")[:limit] or "case"


def human_bytes(n) -> str:
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{int(n)} B" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


class _Progress:
    """Progress + logging against a workflow run, or nowhere.

    Every call is best-effort: a bundle must not fail because the row it reports
    into went away. Warnings are logged at 'warning', never 'error' — an error
    entry makes update_run_status flip a finished run to 'failed', and "a payload
    file was already purged" is a caveat on the export, not a failed export.
    """

    def __init__(self, run_id=None):
        self.run_id = run_id
        self.warnings = []

    def log(self, msg, level="info"):
        if not self.run_id:
            return
        try:
            self._ws_add(msg, level)
        except Exception:
            pass

    def _ws_add(self, msg, level):
        _ws().add_log_to_run(self.run_id, msg, level)

    def warn(self, msg):
        self.warnings.append(msg)
        self.log(msg, "warning")

    def pct(self, value, detail=None):
        if not self.run_id:
            return
        try:
            _ws().update_run_status(self.run_id, "running", progress=int(value))
        except Exception:
            pass
        if detail:
            self.log(detail)


def _find_file(dirs, *parts):
    """First existing path across the candidate roots, or None."""
    for base in dirs:
        p = os.path.join(base, *parts)
        if os.path.exists(p) and os.path.isfile(p):
            return p
    return None


# ═════════════════════════════════════════════════════════════════════════════
# EXPORT
# ═════════════════════════════════════════════════════════════════════════════

def _no_data_warning(run, exported_for):
    """Warn only when a run really has nothing to fuse from on the far side.

    Each module keeps its evidence somewhere different, so "no raw_results.json"
    is meaningless for a cloud scan (its findings are a separate file) and for a
    Timesketch run (its distilled events live on the row). Asking the wrong
    question produced a warning about missing data for a run whose data was in
    the bundle all along — noise that teaches operators to ignore warnings.
    """
    rid = run.get("run_id")
    atype = run.get("automation_type") or ""
    det = run.get("details") or {}
    if rid in exported_for:
        return None
    if atype in ("aws_scan", "azure_scan"):
        if det.get("findings") or det.get("sigma_findings") or det.get("findings_by_severity"):
            return None
        return (f"run {rid}: no cloud findings on this appliance — it will not "
                f"contribute to a re-fuse on the destination")
    if atype == "memory":
        if det.get("plugins"):
            return None
        return (f"run {rid}: no memory_payload.json — its YARA hits cannot be "
                f"recovered from anywhere and will be missing after a re-fuse")
    if atype == "timesketch":
        if det.get("timeline_events"):
            return None
        return (f"run {rid}: no timeline events on the row, and the destination "
                f"has no Timesketch sketch to read — it will not contribute to a "
                f"re-fuse")
    if atype in _ws().AGENTIC_TYPES:
        if det.get("collected_data"):
            return None                    # small/legacy run: rows live on the row
        return (f"run {rid}: no raw_results.json (purged?) — it will not "
                f"contribute to a re-fuse on the destination appliance")
    return None


def plan_export(case_id) -> dict:
    """Everything the bundle will contain, and how big it is, without writing.

    Separated from the build so the route can reject (System workspace, unknown
    case) before starting a background run, and so tests can assert on the
    inventory without producing a zip.
    """
    st, ws = _store(), _ws()
    case_run = ws.get_automation_run(case_id)
    if not case_run or case_run.get("automation_type") != st.CASE_TYPE:
        raise BundleError("case not found")
    if st.is_system_case(case_id):
        raise BundleError("the System workspace is not an investigation case and "
                          "cannot be exported")

    det = dict(case_run.get("details") or {})
    member_ids = st._members_for_case(case_id, det)
    rows, warnings, files, payload_bytes = [], [], [], 0

    for rid in member_ids:
        run = ws.get_automation_run(rid)
        if not run:
            warnings.append(f"member run {rid} is no longer on this appliance — skipped")
            continue
        rows.append(("member", run))
        for fname in PAYLOAD_FILES:
            src = _find_file(DOWNLOAD_DIRS, rid, fname)
            if src:
                sz = os.path.getsize(src)
                payload_bytes += sz
                files.append({"arc": f"payloads/{rid}/{fname}", "src": src, "bytes": sz})
        aws = _find_file(AWS_DIRS, f"{rid}.json")
        if aws:
            sz = os.path.getsize(aws)
            payload_bytes += sz
            files.append({"arc": f"aws_runs/{rid}.json", "src": aws, "bytes": sz})

    # A run whose collected data is gone (typically the Maintenance "Report
    # Downloads" purge) still exports — its row and its share of the fused graph
    # travel — but it will contribute nothing to a re-fuse on the destination,
    # and that is worth saying before the move rather than discovering after it.
    exported_for = {f["arc"].split("/")[1] if f["arc"].startswith("payloads/")
                    else f["arc"].split("/")[1][:-5] for f in files}
    for kind, run in rows:
        if kind != "member":
            continue
        w = _no_data_warning(run, exported_for)
        if w:
            warnings.append(w)

    # Baselines this case captured: environment-scope dispositions live here, so
    # leaving them behind silently un-suppresses known-good activity.
    try:
        for r in ws.get_all_automation_runs() or []:
            if r.get("automation_type") != st.BASELINE_TYPE:
                continue
            if (r.get("details") or {}).get("source_case") == case_id:
                rows.append(("baseline", r))
    except Exception as e:                              # noqa: BLE001
        warnings.append(f"could not enumerate baselines: {e}")

    graph_src = None
    graph_inline = None
    try:
        p = st._graph_path(case_id)
        if os.path.exists(p):
            graph_src = p
    except Exception:
        pass
    if graph_src is None and det.get("fusion_graph"):
        graph_inline = det.get("fusion_graph")          # legacy inline graph

    graph_bytes = os.path.getsize(graph_src) if graph_src else 0
    return {
        "case_id": case_id,
        "case_run": case_run,
        "name": det.get("name") or case_run.get("name") or "case",
        "rows": rows,
        "member_ids": [r.get("run_id") for k, r in rows if k == "member"],
        "baseline_ids": [r.get("run_id") for k, r in rows if k == "baseline"],
        "files": files,
        "graph_src": graph_src,
        "graph_inline": graph_inline,
        "payload_bytes": payload_bytes,
        "graph_bytes": graph_bytes,
        "estimate_bytes": payload_bytes + graph_bytes + 8 * 1024 * 1024,
        "warnings": warnings,
    }


def _zip_doc(zf, arc, obj):
    """Write a small JSON document, returning its inventory entry."""
    data = json.dumps(obj, default=str).encode("utf-8")
    zf.writestr(arc, data)
    return {"path": arc, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}


def _zip_file(zf, arc, src, on_bytes=None):
    """Stream a file into the archive, hashing it in the same pass.

    Never reads the file whole: a raw_results.json is ~547 MB and several may be
    in one bundle. If fusion replaces the graph sidecar mid-export the open fd
    keeps the old inode, so the archive stays a consistent snapshot either way.
    """
    h = hashlib.sha256()
    total = 0
    with open(src, "rb") as fh, zf.open(arc, "w") as dst:
        while True:
            buf = fh.read(_CHUNK)
            if not buf:
                break
            h.update(buf)
            dst.write(buf)
            total += len(buf)
            if on_bytes:
                on_bytes(len(buf))
    return {"path": arc, "sha256": h.hexdigest(), "bytes": total}


def export_case_bundle(case_id, *, run_id=None, cancel=None) -> dict:
    """Build the bundle for one case. Returns the details of the finished file.

    Runs on a background thread: a multi-GB archive cannot be built inside a
    request (nginx gives up waiting for the first byte after 300s, and the
    response would be buffered). The route hands back a run id, the operator
    watches progress, then downloads the finished file.
    """
    st = _store()
    prog = _Progress(run_id)
    plan = plan_export(case_id)
    for w in plan["warnings"]:
        prog.warn(w)

    name = plan["name"]
    out_dir = os.path.join(EXPORT_DIR, case_id)
    archive_guard.require_free_space(out_dir, plan["estimate_bytes"])

    # Keep-latest: one archive per case. Exports are re-buildable and large, so
    # holding every past one just fills the volume the payloads live on.
    _sweep_export_dir(out_dir)

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    final = os.path.join(out_dir, f"{safe_name(name)}-{stamp}{BUNDLE_EXT}")
    partial = final + ".partial"

    prog.log(f"Exporting case \"{name}\": {len(plan['member_ids'])} run(s), "
             f"{len(plan['baseline_ids'])} baseline(s), "
             f"{human_bytes(plan['payload_bytes'])} of collected data")
    prog.pct(8)

    written = [0]
    total = max(1, plan["estimate_bytes"])

    def _tick(n):
        written[0] += n
        prog.pct(min(95, 10 + int(85.0 * written[0] / total)))

    inventory = []
    try:
        with zipfile.ZipFile(partial, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
            det = dict(plan["case_run"].get("details") or {})
            for k in _STRIP_FROM_CASE:
                det.pop(k, None)
            inventory.append(_zip_doc(zf, "case.json",
                                      {**plan["case_run"], "details": det}))

            for kind, run in plan["rows"]:
                rid = run.get("run_id")
                entry = _zip_doc(zf, f"runs/{rid}.json", run)
                entry["role"] = kind
                inventory.append(entry)

            if plan["graph_src"]:
                prog.log(f"Adding the fused graph ({human_bytes(plan['graph_bytes'])})")
                inventory.append(_zip_file(zf, "graph.json", plan["graph_src"], on_bytes=_tick))
            elif plan["graph_inline"] is not None:
                inventory.append(_zip_doc(zf, "graph.json", plan["graph_inline"]))

            for f in plan["files"]:
                if cancel is not None and cancel.is_set():
                    raise BundleError("export cancelled")
                prog.log(f"Adding {f['arc']} ({human_bytes(f['bytes'])})")
                inventory.append(_zip_file(zf, f["arc"], f["src"], on_bytes=_tick))

            # Manifest last: the checksums are only known now.
            manifest = {
                "kind": EXPORT_KIND,
                "schema": BUNDLE_SCHEMA,
                "product_version": product_version(),
                "exported_at": _now_iso(),
                "case_id": case_id,
                "case_name": name,
                "member_run_ids": plan["member_ids"],
                "baseline_run_ids": plan["baseline_ids"],
                "has_graph": bool(plan["graph_src"] or plan["graph_inline"] is not None),
                "files": inventory,
                "warnings": list(prog.warnings),
            }
            zf.writestr(MANIFEST_NAME, json.dumps(manifest, indent=2, default=str))

        os.replace(partial, final)
    except BaseException:
        _rm(partial)
        raise

    size = os.path.getsize(final)
    prog.pct(100)
    prog.log(f"Bundle ready: {os.path.basename(final)} ({human_bytes(size)})")
    try:
        st.log_case_event(case_id, "Export case", "ok",
                          f"exported {len(plan['member_ids'])} run(s), "
                          f"{human_bytes(plan['payload_bytes'])} of collected data "
                          f"→ {os.path.basename(final)}")
    except Exception:
        pass
    return {"bundle_path": final, "bundle_name": os.path.basename(final),
            "bundle_bytes": size, "case_id": case_id, "case_name": name,
            "runs_exported": len(plan["member_ids"]),
            "baselines_exported": len(plan["baseline_ids"]),
            "warnings": list(prog.warnings)}


def _sweep_export_dir(out_dir):
    try:
        for fn in os.listdir(out_dir):
            if fn.endswith(BUNDLE_EXT) or fn.endswith(".partial"):
                _rm(os.path.join(out_dir, fn))
    except FileNotFoundError:
        pass
    except Exception:
        pass


def _rm(path):
    try:
        os.remove(path)
    except Exception:
        pass


# ═════════════════════════════════════════════════════════════════════════════
# IMPORT
# ═════════════════════════════════════════════════════════════════════════════

def read_manifest(zip_path) -> dict:
    """Manifest of a bundle, validated for kind and schema. Raises BundleError.

    Cheap enough to call before committing to an import — the manifest is the
    first thing worth knowing about a file an operator just carried in on a USB
    stick.
    """
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            raw = zf.read(MANIFEST_NAME)
    except KeyError:
        raise BundleError("not an Intact case bundle (no manifest.json) — if this is "
                          "an offline-collector ZIP, import it from the Velociraptor "
                          "page instead") from None
    except zipfile.BadZipFile as e:
        raise BundleError(f"not a readable ZIP archive: {e}") from e
    try:
        man = json.loads(raw)
    except Exception as e:
        raise BundleError(f"the bundle manifest is not readable JSON: {e}") from e
    if not isinstance(man, dict) or man.get("kind") != EXPORT_KIND:
        raise BundleError("not an Intact case bundle")

    schema = man.get("schema")
    try:
        schema = int(schema)
    except (TypeError, ValueError):
        raise BundleError("the bundle does not declare a schema version") from None
    if schema > MAX_SUPPORTED_SCHEMA:
        raise BundleError(
            f"This bundle was exported by a newer Intact release (bundle schema "
            f"{schema}; this appliance supports up to {MAX_SUPPORTED_SCHEMA}). "
            f"Import it on an appliance at least as new as the exporter.")
    if schema < 2:
        raise BundleError(
            "This bundle is in the pre-release single-JSON format, which carries no "
            "collected data and cannot be re-fused. Re-export the case on the source "
            "appliance to produce a current bundle.")
    man["schema"] = schema
    return man


def _mint_id(run_type) -> str:
    ws = _ws()
    for _ in range(50):
        rid = ws._next_run_id(run_type)
        try:
            if ws.get_automation_run(rid):
                continue                   # astronomically unlikely; cheap to check
        except Exception:
            pass
        return rid
    raise BundleError("could not allocate a free run id")


def _remap(text, id_map) -> str:
    """Rewrite every reference to a source id, on the serialized JSON.

    Run ids are threaded through the graph in more places than a structured walk
    would reliably find — evidence refs, a case's run_ids list, disposition
    targets, timeline finding ids, the memory mapper's asset anchor when a run
    had no client_id. Rewriting the text catches all of them at once.

    Matching is bounded by non-identifier characters on both sides, so
    `agentic_1755512400001` never matches inside `agentic_17555124000011` and a
    shorter id can never eat a longer one's prefix.
    """
    if not id_map:
        return text
    pattern = re.compile(
        r"(?<![A-Za-z0-9_])(" +
        "|".join(re.escape(k) for k in sorted(id_map, key=len, reverse=True)) +
        r")(?![A-Za-z0-9_])")
    return pattern.sub(lambda m: id_map[m.group(1)], text)


def _unique_case_name(name) -> str:
    """`name`, or the first free "name (imported N)". Import never merges into an
    existing case, so a repeated import must not produce two identical rows."""
    st, ws = _store(), _ws()
    try:
        taken = {(r.get("details") or {}).get("name")
                 for r in (ws.get_all_automation_runs() or [])
                 if r.get("automation_type") == st.CASE_TYPE}
    except Exception:
        return name
    if name not in taken:
        return name
    cand = f"{name} (imported)"
    n = 2
    while cand in taken:
        cand = f"{name} (imported {n})"
        n += 1
    return cand


def import_case_bundle(zip_path, *, run_id=None, name=None) -> dict:
    """Recreate a case from a bundle. Always a NEW case; never a merge.

    Nothing is written until the whole archive has been verified, and everything
    written is remembered so a failure half-way can be undone — a half-imported
    case that looks real but is missing evidence is worse than no case at all.
    """
    st, ws = _store(), _ws()
    prog = _Progress(run_id)

    stats = archive_guard.inspect_zip(zip_path)
    man = read_manifest(zip_path)
    prog.log(f"Bundle: case \"{man.get('case_name')}\" from "
             f"{man.get('product_version', 'unknown')}, exported {man.get('exported_at')}")

    files = [f for f in (man.get("files") or []) if isinstance(f, dict)]
    for f in files:
        p = f.get("path") or ""
        if not _ARC_RE.match(p):
            raise BundleError(f"the bundle lists an unexpected file ({p!r}) — refusing it")
    listed = {f["path"] for f in files}
    if "case.json" not in listed:
        raise BundleError("the bundle has no case.json")

    payload_bytes = sum(int(f.get("bytes") or 0) for f in files
                        if f["path"].startswith(("payloads/", "aws_runs/")))
    other_bytes = sum(int(f.get("bytes") or 0) for f in files
                      if not f["path"].startswith(("payloads/", "aws_runs/")))
    # Two filesystems: payloads land on the downloads volume, the graph + rows on
    # the bind mount. Checking only one of them is checking the wrong disk.
    archive_guard.require_free_space(DOWNLOAD_WRITE_DIR, payload_bytes)
    archive_guard.require_free_space(_graph_dir(), other_bytes)

    prog.pct(15, f"Verifying {len(files)} file(s), "
                 f"{human_bytes(stats['total_uncompressed'])} uncompressed")

    with zipfile.ZipFile(zip_path, "r") as zf:
        _verify(zf, files, prog)

        case_doc = json.loads(zf.read("case.json"))
        run_docs = {}
        for f in files:
            if f["path"].startswith("runs/"):
                doc = json.loads(zf.read(f["path"]))
                run_docs[f["path"]] = (doc, f.get("role"))

        src_case_id = case_doc.get("run_id") or man.get("case_id")
        src_det = case_doc.get("details") or {}
        disp = (name or src_det.get("name") or case_doc.get("name")
                or man.get("case_name") or "Imported case").strip()
        disp = _unique_case_name(disp)

        created = []                        # unwound in reverse if anything fails
        try:
            new_case_id = ws.create_automation_run(
                automation_type=st.CASE_TYPE, name=f"Case — {disp}",
                case_id=None, details={})
            created.append(("case", new_case_id))

            id_map = {}
            if src_case_id:
                id_map[src_case_id] = new_case_id
            new_members, new_baselines = [], []
            for path, (doc, role) in run_docs.items():
                old = doc.get("run_id")
                if not old or not _RUN_ID_RE.match(str(old)):
                    continue
                new = _mint_id(doc.get("automation_type") or "run")
                id_map[old] = new
                (new_baselines if role == "baseline" else new_members).append(new)

            prog.pct(30, f"Rewriting {len(id_map)} identifier(s) — imported runs never "
                         f"reuse the source appliance's ids")

            # Rows first, then payloads, then the graph. The case row's details are
            # written LAST (below), so a crash leaves an empty case an operator can
            # delete normally rather than a case that looks complete and is not.
            for path, (doc, role) in run_docs.items():
                old = doc.get("run_id")
                if old not in id_map:
                    continue
                row = json.loads(_remap(json.dumps(doc, default=str), id_map))
                row["run_id"] = id_map[old]
                det = row.get("details") or {}
                det.pop("is_default", None)
                det.pop("is_system", None)
                row["details"] = det
                row["case_id"] = new_case_id if role != "baseline" else None
                _save_row(row)
                created.append(("run", row["run_id"]))

            done = [0]
            total = max(1, payload_bytes)
            for f in files:
                p = f["path"]
                if not p.startswith(("payloads/", "aws_runs/")):
                    continue
                parts = p.split("/")
                old_rid = parts[1] if p.startswith("payloads/") else parts[1][:-5]
                new_rid = id_map.get(old_rid)
                if not new_rid:
                    prog.warn(f"{p}: no run row for {old_rid} in this bundle — skipped")
                    continue
                if p.startswith("payloads/"):
                    dest_dir = os.path.join(DOWNLOAD_WRITE_DIR, new_rid)
                    dest = os.path.join(dest_dir, parts[2])
                    created.append(("dir", dest_dir))
                else:
                    dest_dir = AWS_WRITE_DIR
                    dest = os.path.join(dest_dir, f"{new_rid}.json")
                    created.append(("file", dest))
                os.makedirs(dest_dir, exist_ok=True)
                with zf.open(p) as src, open(dest, "wb") as out:
                    archive_guard.copy_bounded(src, out, int(f.get("bytes") or 0) + _CHUNK,
                                               what=p)
                done[0] += int(f.get("bytes") or 0)
                prog.pct(min(85, 35 + int(50.0 * done[0] / total)))

            if "graph.json" in listed:
                prog.pct(88, "Installing the fused graph")
                graph = json.loads(_remap(zf.read("graph.json").decode("utf-8"), id_map))
                st._write_graph_sidecar(new_case_id, graph)
                created.append(("graph", new_case_id))

            # The case row, last.
            new_det = json.loads(_remap(json.dumps(src_det, default=str), id_map))
            for k in _STRIP_FROM_CASE:
                new_det.pop(k, None)
            new_det["name"] = disp
            new_det["member_run_ids"] = new_members
            new_det["imported"] = {
                "at": _now_iso(),
                "from_version": man.get("product_version"),
                "source_case_id": src_case_id,
                "exported_at": man.get("exported_at"),
                "bundle_schema": man.get("schema"),
            }
            ws.update_run_status(new_case_id, case_doc.get("status") or "completed",
                                 details=new_det)
        except BaseException:
            _unwind(created, prog)
            raise

    st.log_case_event(new_case_id, "Import case", "ok",
                      f"imported from {man.get('product_version', 'unknown')} "
                      f"(exported {man.get('exported_at')}) — {len(new_members)} run(s), "
                      f"{len(new_baselines)} baseline(s), "
                      f"{human_bytes(payload_bytes)} of collected data")
    for w in (man.get("warnings") or [])[:20]:
        st.log_case_event(new_case_id, "Import case", "warning", str(w))
    for w in prog.warnings[:20]:
        st.log_case_event(new_case_id, "Import case", "warning", str(w))

    prog.pct(100)
    prog.log(f"Imported \"{disp}\" — {len(new_members)} run(s), "
             f"{len(new_baselines)} baseline(s)")
    return {"case_id": new_case_id, "name": disp, "runs_imported": len(new_members),
            "baselines_imported": len(new_baselines), "id_map": id_map,
            "source_version": man.get("product_version"),
            "warnings": list(prog.warnings)}


def _verify(zf, files, prog):
    """Checksum every listed file BEFORE anything is written.

    A bundle crosses an air gap on removable media; a truncated copy is a normal
    failure, not an exotic one, and it must be caught while the destination is
    still untouched.
    """
    for i, f in enumerate(files):
        want = (f.get("sha256") or "").lower()
        h = hashlib.sha256()
        try:
            with zf.open(f["path"]) as src:
                while True:
                    buf = src.read(_CHUNK)
                    if not buf:
                        break
                    h.update(buf)
        except KeyError:
            raise BundleError(f"the bundle is missing {f['path']}, which its manifest "
                              f"lists — the copy is incomplete") from None
        if want and h.hexdigest() != want:
            raise BundleError(f"checksum mismatch on {f['path']} — the bundle is "
                              f"corrupt; copy it again from the source appliance")
        if i % 5 == 0:
            prog.pct(15 + int(10.0 * (i + 1) / max(1, len(files))))


def _graph_dir():
    try:
        return os.path.dirname(_store()._graph_path("x")) or "/app/data"
    except Exception:
        return "/app/data"


def _save_row(row):
    from services.file_storage_service import save_workflow
    save_workflow(row)


def _delete_row(run_id):
    from services.file_storage_service import delete_workflow
    delete_workflow(run_id)


def _unwind(created, prog):
    """Remove everything this import created, newest first.

    Deliberately NOT store.delete_case: that assumes a live, complete case (it
    guards Default/System, cancels timers and purges the cross-case KB). This is
    the inverse of what was written here and nothing else.
    """
    st = _store()
    for kind, val in reversed(created):
        try:
            if kind in ("case", "run"):
                _delete_row(val)
            elif kind == "graph":
                st._delete_graph_sidecar(val)
            elif kind == "dir":
                shutil.rmtree(val, ignore_errors=True)
            elif kind == "file":
                _rm(val)
        except Exception:
            pass
    prog.log("Import failed — everything it created has been removed", "warning")
