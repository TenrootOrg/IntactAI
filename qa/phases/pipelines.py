"""Run each feature's LIGHTWEIGHT blueprint end to end.

The feature sweep proves the API answers. This proves the product *works*: a
real collection against a real client, a real detection run over real evidence,
a real artefact built. Every blueprint used here is the cheapest one the
platform ships for that feature, chosen so a full pass costs minutes rather than
the hour a "Full Investigation" would.

  Velociraptor   agentic_linux_triage   the Linux QuickWins collection
  Collector      offline generate       a real Linux collector binary

  Timesketch     tus purpose=timesketch  real host logs through plaso
  Fusion         cases/quick + fuse      entities and relationships from them

TIMESKETCH IS NOT WINDOWS-LOCKED -- only its COLLECTION step is. `kape_service`
hard-codes `Windows.Triage.Targets`, and `/api/timesketch/import` refuses any
flow that route did not register, so the flow-driven path genuinely needs
Windows. But `process_kape_upload` is reached by a second door: the tus upload
with `purpose=timesketch`, which takes a ZIP and no flow at all. And
`detect_kape_format` classifies by LAYOUT -- any member path containing
`uploads/` is a "velociraptor" collection -- so real Linux logs under `uploads/`
go straight through the same pipeline a customer's KAPE collection uses.

Measured on a live appliance with this host's own /var/log: 286,044 plaso events
(syslog 117k, syslog_traditional 20k, dpkg 4.8k, utmp 929) with the default
parser set, 10,414 with the `linux` preset. This was never a hypothetical.

WHAT STILL CANNOT RUN, and why it is skipped rather than faked. Memory is
genuinely blocked in code, not by evidence: `services/memory/pipeline.py`
registers every image as `os_name="windows"` at all three call sites, every
shipped blueprint is `volatility3.plugins.windows.*`, and no ISF symbols ship --
so even a perfect Linux image would fail inside Volatility. It runs only when
the Windows evidence job supplies a real image; otherwise it is a recorded skip.

The cloud modules (AWS sigma, o365rc) are deliberately NOT exercised here. They
are a separate concern from the DFIR pipeline this phase covers, and their
detection engines run over uploaded evidence rather than anything a client
collects -- so they neither need nor benefit from the machinery below.
"""

import json
import os
import re
import socket
import time

from lib import api as api_lib, shell

# The lightest blueprint the platform ships for each feature. Ids, not names:
# selecting by name once picked "Full Triage" over "Event Logs Only" and made a
# run ten times longer for no extra coverage.
BLUEPRINTS = {
    "velociraptor_linux": "agentic_linux_triage",
    "timesketch": "timesketch_event_logs",     # EventLogs / winevtx — Windows only
    "memory": "memory_quick_wins",             # needs an acquired image
}

# Bounded so a wedged pipeline fails the phase instead of eating the job's
# 330-minute budget. Generous enough for a cold container that has to warm up.
TIMEOUT_COLLECTION_S = 900
TIMEOUT_CLOUD_S = 600
TIMEOUT_COLLECTOR_S = 900
# Plaso over a few hundred thousand events, then Timesketch's own Celery
# workers indexing them. Measured at ~2 minutes for 286k events on a live box;
# the ceiling is generous because indexing is the slow, variable half.
TIMEOUT_TIMESKETCH_S = 2400
TIMEOUT_MEMORY_S = 3600


def register(runner, cfg):
    if not cfg.pipelines:
        return

    tl = runner.ctx.tl

    @runner.phase("pipelines",
                  "Run each feature's lightweight blueprint end to end",
                  needs=("features",))
    def pipelines(ctx):
        detail = {"ran": {}, "skipped": []}
        c = ctx.get("client")
        if c is None:
            ctx.check("an authenticated client is available", False,
                      note="the auth phase did not sign in")
            return detail

        _velociraptor_linux(ctx, c, detail)
        _offline_collector(ctx, c, detail)
        _timesketch(ctx, c, cfg, detail)
        _fusion(ctx, c, detail)
        _windows_evidence(ctx, c, detail)
        return detail


# --- Velociraptor ----------------------------------------------------------


def _velociraptor_linux(ctx, c, detail):
    """The lightweight Linux collection, against the client we just enrolled.

    This is the one pipeline that needs the appliance to have enrolled itself,
    and it is the reason that was worth doing: without it there is no client and
    every collection path in the product is untestable on a bare runner.
    """
    client_id = ctx.get("client_id")
    if not client_id:
        detail["skipped"].append({
            "pipeline": "velociraptor", "blueprint": BLUEPRINTS["velociraptor_linux"],
            "reason": "no client enrolled — enrol_linux produced none"})
        ctx.check("Velociraptor: collection pipeline ran", True,
                  actual="SKIPPED: no enrolled client",
                  note="not a failure; there is nothing to collect from")
        return

    try:
        body = c.request("POST", "/api/agentic/run", json={
            "blueprint_id": BLUEPRINTS["velociraptor_linux"],
            "client_ids": [client_id],
            "collection_minutes": 5,
        }, expect=(200, 201, 202))
    except Exception as exc:                                  # noqa: BLE001
        ctx.check(f"Velociraptor: {BLUEPRINTS['velociraptor_linux']} dispatches",
                  False, actual=str(exc)[:180])
        return

    run_id = (body or {}).get("run_id")
    ctx.check(f"Velociraptor: {BLUEPRINTS['velociraptor_linux']} dispatches",
              bool(run_id), actual=run_id)
    if not run_id:
        return

    run = c.wait_for_run(run_id, TIMEOUT_COLLECTION_S, ctx.tl,
                         what="agentic linux triage")
    ok = api_lib.run_succeeded(run)
    ctx.check("Velociraptor: the collection run completed", ok,
              expected="completed", actual=(run or {}).get("status"),
              note="a None status means the wait timed out — the run is still "
                   "going, which is not the same as failed")

    # Row counts live in the run's LOG TEXT, not in details — repeatedly
    # relearned. Recorded rather than asserted: a quiet Linux runner legitimately
    # has little to find, and asserting rows>0 would make this flaky for a
    # reason that says nothing about the product.
    rows = _collected_rows(c, run_id)
    detail["ran"]["velociraptor"] = {
        "run_id": run_id, "client_id": client_id, "rows": rows,
        "blueprint": BLUEPRINTS["velociraptor_linux"]}
    ctx.check("Velociraptor: the collection reported what it gathered",
              rows is not None, actual=rows,
              note="dispatch and completion are asserted; detection content is "
                   "not — a CI runner is not a compromised host")


# --- offline collector -----------------------------------------------------


def _offline_collector(ctx, c, detail):
    """Build a real Linux collector binary.

    No endpoint needed: this is the artefact an operator carries to a machine
    that cannot reach the server, so a broken build breaks the air-gap workflow
    entirely, silently, for whoever tries to use it next.
    """
    cfg_id = None
    name = f"QA-CI-{time.strftime('%Y%m%d-%H%M%S')}"
    try:
        body = c.request("POST", "/api/velociraptor/offline/configs",
                         json={"name": name, "artifacts": ["Generic.Client.Info"]},
                         expect=(200, 201))
        cfg_id = (body or {}).get("config_id") or (body or {}).get("id")
    except Exception as exc:                                  # noqa: BLE001
        ctx.check("Collector: an offline config can be created", False,
                  actual=str(exc)[:180])
        return
    ctx.check("Collector: an offline config can be created", bool(cfg_id),
              actual=cfg_id)
    if not cfg_id:
        return

    try:
        body = c.request("POST", "/api/velociraptor/offline/generate", json={
            "config_id": cfg_id, "os": "linux", "encryption_scheme": "none",
        }, expect=(200, 201, 202))
    except Exception as exc:                                  # noqa: BLE001
        ctx.check("Collector: a Linux collector is generated", False,
                  actual=str(exc)[:180])
        _delete_quietly(c, f"/api/velociraptor/offline/configs/{cfg_id}")
        return

    file_id = (body or {}).get("file_id") or (body or {}).get("id")
    run_id = (body or {}).get("run_id")
    if run_id and not file_id:
        run = c.wait_for_run(run_id, TIMEOUT_COLLECTOR_S, ctx.tl,
                             what="offline collector build")
        file_id = ((run or {}).get("details") or {}).get("file_id")

    ctx.check("Collector: a Linux collector is generated", bool(file_id),
              actual=file_id)
    if file_id:
        size = _download_size(c, f"/api/velociraptor/offline/download/{file_id}")
        detail["ran"]["offline_collector"] = {"config_id": cfg_id,
                                              "file_id": file_id, "bytes": size}
        ctx.check("Collector: the built binary is a plausible size",
                  (size or 0) > 2 * 2**20, expected=">2 MB",
                  actual=f"{(size or 0) / 2**20:.1f} MB",
                  note="a tiny file here is an error page or a truncated build")

    _delete_quietly(c, f"/api/velociraptor/offline/configs/{cfg_id}")


# --- Timesketch ------------------------------------------------------------


def _timesketch(ctx, c, cfg, detail):
    """Real host logs, through plaso, into a sketch.

    The evidence is this machine's own /var/log -- written by the same sshd,
    systemd and dpkg a customer's box runs. Nothing is synthesised, which is the
    point: a fixture only ever proves the parser still parses the fixture.

    `plaso_parser` is sent EXPLICITLY as "" (every parser). The tus hook
    defaults it to `win7`, and win7 against Linux logs extracts nothing --
    producing a run that is marked completed with no sketch at all. That silent
    pass is the failure this phase exists to catch, so it must not be the
    failure this phase ships with.
    """
    from lib import evidence as evidence_lib, tus as tus_lib

    run_dir = ctx.run_dir
    host = socket.gethostname()
    zip_path = os.path.join(run_dir, "artifacts", f"{host}.zip")

    def _sudo(argv):
        r = shell.sudo(argv, cfg.sudo_password, timeout=180, tl=ctx.tl,
                       stage="pipelines")
        return r.out if r.ok else ""

    try:
        info = evidence_lib.build_linux_evidence_zip(zip_path, host, sudo=_sudo)
    except Exception as exc:                                  # noqa: BLE001
        ctx.check("Timesketch: host evidence was packaged", False,
                  actual=str(exc)[:180])
        return

    ctx.check("Timesketch: host evidence was packaged", bool(info["members"]),
              expected="at least one log", actual=", ".join(info["members"]) or "none",
              note="real /var/log content from this machine, not a fixture")
    if not info["members"]:
        return

    upload_id = tus_lib.upload(c, zip_path, {
        "purpose": "timesketch",
        "filename": f"{host}.zip",          # the hook requires a .zip name
        "plaso_parser": "",                 # every parser; NOT the win7 default
        "plaso_workers": "2",
        "sketch_name": f"QA-CI-{host}",
        "case_id": str(ctx.get("qa_case_id") or ""),
    }, tl=ctx.tl, stage="pipelines")

    ctx.check("Timesketch: the evidence uploaded through tus", bool(upload_id),
              actual=upload_id,
              note="tus goes through nginx and needs the session cookie; the "
                   "loopback bypass is not available on this path")
    if not upload_id:
        return

    run = _wait_for_upload_run(c, upload_id, host, TIMEOUT_TIMESKETCH_S, ctx.tl)
    ctx.check("Timesketch: the ingest run reached a terminal state", bool(run),
              actual=(run or {}).get("status"))
    if not run:
        return

    text = _run_log_text(c, run.get("id"))
    events = _plaso_events(text)
    sketch = re.search(r"Sketch(?: ID)?:\s*(\d+)", text)
    timeline = re.search(r"Timeline(?: ID)?:\s*(\d+)", text)

    detail["ran"]["timesketch"] = {
        "run_id": run.get("id"), "events": events,
        "sketch_id": sketch.group(1) if sketch else None,
        "timeline_id": timeline.group(1) if timeline else None,
        "members": info["members"], "evidence": "this host's /var/log",
    }

    # THE assertion. A completed run proves nothing: when plaso extracts zero
    # events the pipeline logs "No events extracted", marks the run COMPLETED and
    # returns without creating a sketch. Only the event count separates a working
    # ingest from that.
    ctx.check("Timesketch: plaso extracted events from the evidence",
              (events or 0) > 0, expected=">0", actual=events,
              note="zero events still reports 'completed' with no sketch -- the "
                   "silent pass this check exists to catch")
    ctx.check("Timesketch: a sketch was created", bool(sketch),
              actual=sketch.group(1) if sketch else None)
    ctx.check("Timesketch: a timeline was indexed into the sketch", bool(timeline),
              actual=timeline.group(1) if timeline else None)
    if sketch:
        ctx.set(sketch_id=sketch.group(1))


# --- fusion ----------------------------------------------------------------


def _fusion(ctx, c, detail):
    """Attach every run this phase produced to a case and fuse it.

    `relationships > 0` is the assertion that distinguishes correlation from
    concatenation -- the harness's own stated most-valuable check. On a Linux
    host it is well founded rather than hopeful: `Generic.System.Pstree` is in
    the shipped Linux blueprint, survives the fusion allowlist, and every Linux
    box has a process tree, so `spawned` edges exist whenever a collection ran.
    """
    run_ids = [v["run_id"] for v in detail["ran"].values() if v.get("run_id")]
    if not run_ids:
        detail["skipped"].append({"pipeline": "fusion",
                                  "reason": "no runs were produced to fuse"})
        return

    try:
        body = c.request("POST", "/api/cases/quick",
                         json={"name": f"QA-CI-fusion-{time.strftime('%H%M%S')}",
                               "run_ids": run_ids},
                         expect=(200, 201))
    except Exception as exc:                                  # noqa: BLE001
        ctx.check("Fusion: the case fused", False, actual=str(exc)[:180])
        return

    ents = (body or {}).get("entities")
    rels = (body or {}).get("relationships")
    finds = (body or {}).get("findings")
    detail["ran"]["fusion"] = {"entities": ents, "relationships": rels,
                              "findings": finds, "runs": len(run_ids)}

    ctx.check("Fusion: the case fused", ents is not None,
              actual=f"{ents} entities")
    ctx.check("Fusion: entities were extracted", (ents or 0) > 0,
              expected=">0", actual=ents)
    ctx.check("Fusion: relationships were built", (rels or 0) > 0,
              expected=">0", actual=rels,
              note="relationships are what separate correlation from a pile of "
                   "rows; pstree alone should produce spawned edges")


# --- evidence produced by the Windows job ----------------------------------


def _windows_evidence(ctx, c, detail):
    """Ingest what the windows-latest job harvested, if it ran.

    A Windows runner cannot reach this appliance -- separate VM, no shared
    network -- so it does not try. It collects its own real .evtx and, if the
    kernel driver will load, its own memory, and hands them over as artifacts.
    That covers the two things a Linux host genuinely cannot provide: winevtx
    input, and a memory image Volatility can actually analyse.
    """
    root = (os.environ.get("QA_WINDOWS_EVIDENCE") or "").strip()
    if not root or not os.path.isdir(root):
        for pipeline, why in (
            ("timesketch (winevtx)", "no Windows evidence supplied"),
            ("memory", "no Windows memory image supplied; the pipeline "
                       "registers every image as os_name=windows and ships no "
                       "Linux symbols, so a Linux image cannot substitute"),
        ):
            detail["skipped"].append({"pipeline": pipeline, "reason": why})
            ctx.check(f"{pipeline}: pipeline ran", True,
                      actual=f"SKIPPED: {why}",
                      note="not a failure; the evidence was not provided")
        return

    _timesketch_winevtx(ctx, c, detail, root)
    _memory(ctx, c, detail, root)


def _timesketch_winevtx(ctx, c, detail, root):
    """The real winevtx path: Windows event logs, KAPE-shaped, plaso winevtx."""
    from lib import tus as tus_lib

    zips = sorted(f for f in os.listdir(root) if f.lower().endswith(".zip"))
    if not zips:
        detail["skipped"].append({"pipeline": "timesketch (winevtx)",
                                  "reason": "no evtx ZIP in the evidence bundle"})
        return
    path = os.path.join(root, zips[0])

    upload_id = tus_lib.upload(c, path, {
        "purpose": "timesketch",
        "filename": os.path.basename(path),
        "plaso_parser": "winevtx",          # the blueprint's own parser
        "sketch_name": "QA-CI-winevtx",
        "case_id": str(ctx.get("qa_case_id") or ""),
    }, tl=ctx.tl, stage="pipelines")
    ctx.check("Timesketch/winevtx: the evidence uploaded", bool(upload_id),
              actual=upload_id)
    if not upload_id:
        return

    run = _wait_for_upload_run(c, upload_id, os.path.basename(path),
                               TIMEOUT_TIMESKETCH_S, ctx.tl)
    text = _run_log_text(c, (run or {}).get("id")) if run else ""
    events = _plaso_events(text)
    sketch = re.search(r"Sketch(?: ID)?:\s*(\d+)", text or "")
    detail["ran"]["timesketch_winevtx"] = {
        "run_id": (run or {}).get("id"), "events": events,
        "sketch_id": sketch.group(1) if sketch else None,
        "blueprint": BLUEPRINTS["timesketch"], "evidence": "Windows runner .evtx"}
    ctx.check("Timesketch/winevtx: plaso extracted events", (events or 0) > 0,
              expected=">0", actual=events,
              note="real Windows event logs parsed with the winevtx parser")


def _memory(ctx, c, detail, root):
    """VolWeb, from an image the Windows job acquired.

    Uploaded BARE, never zipped: inside a ZIP the pipeline's floor is 200 MB and
    a smaller member is discarded as metadata, while a bare file only has to
    clear 16 MB. It must also be uncompressed -- the sniffer rejects gzip, zstd
    and zlib magic outright.
    """
    images = sorted(f for f in os.listdir(root)
                    if f.lower().endswith((".raw", ".bin", ".mem", ".dmp")))
    if not images:
        why = ("the Windows runner could not acquire memory (the kernel driver "
               "would not load)")
        detail["skipped"].append({"pipeline": "memory", "reason": why})
        ctx.check("memory: pipeline ran", True, actual=f"SKIPPED: {why}",
                  note="attempted and reported, never faked")
        return

    path = os.path.join(root, images[0])
    size = os.path.getsize(path)
    if size < 16 * 2**20:
        why = f"image is {size / 2**20:.1f} MB, below the pipeline's 16 MB floor"
        detail["skipped"].append({"pipeline": "memory", "reason": why})
        ctx.check("memory: pipeline ran", True, actual=f"SKIPPED: {why}")
        return

    try:
        with open(path, "rb") as fh:
            body = c.s.post(c.base + "/api/memory/upload",
                            files={"file": (os.path.basename(path), fh,
                                            "application/octet-stream")},
                            data={"mode": "plugin",      # skip the slow YARA corpus
                                  "case_name": "QA-CI",
                                  "client_name": "windows-runner"},
                            timeout=1800)
    except Exception as exc:                                  # noqa: BLE001
        ctx.check("memory: the image uploaded", False, actual=str(exc)[:180])
        return

    ok = body.status_code in (200, 201, 202)
    ctx.check("memory: the image uploaded", ok, expected="200/202",
              actual=body.status_code)
    if not ok:
        return
    run_id = (body.json() or {}).get("run_id")
    run = c.wait_for_run(run_id, TIMEOUT_MEMORY_S, ctx.tl, what="volweb analysis")

    report = ((run or {}).get("details") or {}).get("report_md") or ""
    plugins = {m.group(1): m.group(2).startswith("\u2713")
               for m in re.finditer(r"^\|\s*`([^`]+)`\s*\|\s*([^|]+?)\s*\|\s*$",
                                    report, re.M)}
    detail["ran"]["memory"] = {"run_id": run_id, "bytes": size,
                               "plugins_ok": sorted(k for k, v in plugins.items() if v),
                               "evidence": "Windows runner memory"}
    ctx.check("memory: the analysis completed", api_lib.run_succeeded(run),
              actual=(run or {}).get("status"))
    ctx.check("memory: Volatility produced plugin results",
              any(plugins.values()), actual=", ".join(sorted(plugins)) or "none",
              note="results live only in details.report_md as a markdown table; "
                   "there is no structured plugin key")


# --- helpers ---------------------------------------------------------------


def _collected_rows(c, run_id):
    """Row counts from the run's log text — details carries no counts."""
    try:
        logs = c.run_logs(run_id)
    except Exception:                                         # noqa: BLE001
        return None
    text = logs if isinstance(logs, str) else json.dumps(logs)
    import re
    m = re.search(r"Collected\s+([\d,]+)\s+row", text)
    return int(m.group(1).replace(",", "")) if m else 0


def _download_size(c, path):
    try:
        r = c.s.get(c.base + path, timeout=300, stream=True)
        if r.status_code != 200:
            return 0
        return sum(len(chunk) for chunk in r.iter_content(chunk_size=2**20))
    except Exception:                                         # noqa: BLE001
        return 0


def _wait_for_upload_run(c, upload_id, filename, timeout_s, tl):
    """Find and await the run a tus upload started.

    The upload API returns no run id -- `/api/uploads/status/<id>` reports only
    size -- so the run has to be recognised in the automations list by its
    upload id or filename. Matching on either, because which one lands in
    details depends on the purpose.
    """
    deadline = time.time() + timeout_s
    terminal = ("completed", "success", "succeeded", "failed", "error",
                "cancelled")
    run_id = None
    while time.time() < deadline:
        try:
            body = c.get("/api/dashboard/automations", expect=(200,))
        except Exception:                                     # noqa: BLE001
            body = None
        for run in ((body or {}).get("runs") or []):
            det = run.get("details") or {}
            if run_id and run.get("id") == run_id:
                if (run.get("status") or "").lower() in terminal:
                    return run
            elif not run_id and (det.get("upload_id") == upload_id
                                 or det.get("filename") == filename):
                run_id = run.get("id")
                if tl:
                    tl.event("upload_run", detail={"run_id": run_id,
                                                   "upload_id": upload_id})
                if (run.get("status") or "").lower() in terminal:
                    return run
        time.sleep(15)
    return None


def _run_log_text(c, run_id):
    """The run's log lines joined into one string.

    Everything worth asserting on -- event counts, sketch and timeline ids --
    exists only in this text. `details` carries no counts, which is documented
    the hard way in more than one place in this repo.
    """
    if not run_id:
        return ""
    try:
        run = c.run_status(run_id) or {}
    except Exception:                                         # noqa: BLE001
        return ""
    logs = run.get("logs") or []
    parts = []
    for entry in logs:
        if isinstance(entry, dict):
            parts.append(str(entry.get("message") or ""))
        else:
            parts.append(str(entry))
    return "\n".join(parts)


def _plaso_events(text):
    """Events plaso extracted, from the log text. None when it never said."""
    m = re.search(r"Plaso extracted\s+([\d,]+)\s+events", text or "")
    if not m:
        m = re.search(r"Events extracted:\s*([\d,]+)", text or "")
    return int(m.group(1).replace(",", "")) if m else None


def _delete_quietly(c, path):
    try:
        c.request("DELETE", path, expect=(200, 204, 404))
    except Exception:                                         # noqa: BLE001
        pass
