"""The four workflow stages, in the dependency order the operator specified.

    A1  KAPE collection starts (Timesketch automation)
     |
    A2  GATE: the collection has finished CLIENT-SIDE
     |          |
     |          B   agentic blueprint, dispatched as a Velociraptor HUNT
    A3  Timesketch ingest + index  (runs in parallel with B)
     |          |
     +----+-----+
          |
    GATE: A3 complete AND B complete
          |
     C  VolWeb: acquire memory, run plugins + yara
          |
     D  Fusion: fuse the Case from all three sources

Why the A2 gate is on CLIENT-SIDE completion and not on the ingest finishing:
the endpoint must never run two heavy collections at once — on a 4 GB VM that
would slow both and distort the very memory state phase C is about to capture.
But the Timesketch ingest is server-side work that can safely overlap the hunt,
and that overlap is where the time saving comes from.
"""

import time

from lib import api as api_lib

# Fast-QA profile. Breadth traded for speed on purpose, and the report says so
# rather than implying a thorough examination.
#
# The shipped "Forensic Timeline: Event Logs Only" blueprint, which sets
# kape_target: EventLogs. Chosen BY ID rather than by name matching: the first
# version searched for "kape"/"triage"/"windows" and duly selected "Forensic
# Timeline: Full Triage" (_KapeTriage), the slowest of the three — it collects
# the full filesystem triage set where this run only needs event logs. That
# turned a couple of minutes of collection into tens.
#
# Event logs are also exactly what this QA wants: phase 3 clears them first, so
# the collected set contains only QA-generated activity and a detection that
# fires is unambiguously ours.
TIMESKETCH_BLUEPRINT_ID = "timesketch_event_logs"
TIMESKETCH_BLUEPRINT_FALLBACK = ("event log", "evtx")
VOLATILITY_PLUGINS = ["windows.pslist", "windows.malfind"]


def register(runner, cfg):
    tl = runner.ctx.tl

    # ---------------------------------------------------------------- A1 --
    @runner.phase("kape", "Start the KAPE collection (Timesketch automation)",
                  needs=("activity",))
    def kape(ctx):
        c, client_id = ctx.get("client"), ctx.get("client_id")
        bp = _pick_blueprint(c, "/api/blueprints/timesketch",
                             by_id=TIMESKETCH_BLUEPRINT_ID,
                             prefer=TIMESKETCH_BLUEPRINT_FALLBACK)
        ctx.check("the event-logs Timesketch blueprint exists", bool(bp),
                  expected=TIMESKETCH_BLUEPRINT_ID,
                  actual=bp and (bp.get("id"), bp.get("name")),
                  note="shipped as 'Forensic Timeline: Event Logs Only'")

        # Take the KAPE target FROM the blueprint rather than hardcoding it, so
        # the run collects exactly what the blueprint says and the two cannot
        # drift apart.
        settings = (bp or {}).get("settings") or {}
        kape_target = settings.get("kape_target") or "EventLogs"

        payload = {"client_id": client_id,
                   "client_name": ctx.get("hostname") or client_id,
                   "kape_target": kape_target}
        if bp:
            payload["blueprint_id"] = bp.get("id") or bp.get("blueprint_id")
            payload["blueprint"] = bp.get("name")

        ctx.check("collecting event logs only, not a full triage",
                  kape_target == "EventLogs", expected="EventLogs",
                  actual=kape_target,
                  note="_KapeTriage collects the whole filesystem triage set "
                       "and takes an order of magnitude longer")

        body = c.post("/api/velociraptor/timesketch", payload)
        run_id = body.get("run_id") if isinstance(body, dict) else None
        flow_id = body.get("flow_id") if isinstance(body, dict) else None

        ctx.check("KAPE collection accepted", bool(run_id), actual=body)
        # Captured at LAUNCH, not on completion: if this hangs, the id is what
        # lets an operator go and look at it in the product.
        ctx.set(kape_run_id=run_id, kape_flow_id=flow_id)
        tl.ids(kape_run_id=run_id, kape_flow_id=flow_id)

        # SECOND CALL, and it is not optional.
        #
        # /api/velociraptor/timesketch ONLY dispatches the KAPE collection. Its
        # own response says so: "KAPE collection started. Call
        # /api/timesketch/import with this flow_id to start the full pipeline."
        # Without it the run sits at 5% for ever — the collection completes on
        # the endpoint, Velociraptor has the files, and nothing moves. That
        # looked exactly like a stalled backend, which is how it was first
        # diagnosed; it was a two-step API and the harness only made step one.
        #
        # The import reuses the SAME run_id (it reads it back out of the job
        # registry), monitors the flow to completion itself, then runs plaso
        # and the Timesketch index. So this one call covers the A2 gate and
        # stage A3.
        import_payload = {
            "flow_id": flow_id,
            "client_id": client_id,
            "client_name": payload["client_name"],
            "sketch_name": f"QA {ctx.tl.run_id}",
            # winevtx: the collection is event logs only, so pointing plaso at
            # the matching parser preset skips work it cannot use anyway.
            "plaso_parser": settings.get("plaso_parser") or "winevtx",
            "plaso_workers": settings.get("plaso_workers", 2),
            "plaso_hasher": settings.get("plaso_hasher", ""),
            "monitor_timeout": cfg.timeout("kape_collection", 30) * 60,
            "timesketch_processing_timeout":
                cfg.timeout("timesketch_ingest", 45) * 60,
        }
        imported = c.post("/api/timesketch/import", import_payload)
        ctx.check("Timesketch import pipeline started",
                  isinstance(imported, dict) and not imported.get("error"),
                  actual=imported,
                  note="without this the collection completes and the run "
                       "never leaves 5%")

        return {"run_id": run_id, "flow_id": flow_id,
                "kape_target": kape_target,
                "blueprint": payload.get("blueprint"),
                "plaso_parser": import_payload["plaso_parser"],
                "import_response": imported}

    # ---------------------------------------------------------------- A2 --
    @runner.phase("kape_gate", "Wait for the collection to finish client-side",
                  needs=("kape",))
    def kape_gate(ctx):
        """The gate that lets the hunt start. Watches for the collection to
        stop running ON THE CLIENT — not for the whole Timesketch automation to
        finish, which includes a server-side ingest that can safely overlap."""
        c, run_id = ctx.get("client"), ctx.get("kape_run_id")

        # The import pipeline writes a log line per stage, and `details.phase`
        # is never populated — so progress is read from the LOGS, not from a
        # status field. Watching for the words that mean the endpoint is done
        # and the server has taken over is what releases the hunt: the point of
        # the gate is that the endpoint never runs two heavy collections at
        # once, while server-side plaso and indexing can safely overlap.
        SERVER_SIDE = ("download", "downloaded", "plaso", "processing",
                       "extracting", "uploading to timesketch", "sketch")

        def probe():
            run = c.run_status(run_id)
            if not run:
                return None
            status = (run.get("status") or "").lower()
            if status in ("completed", "success", "failed", "error", "cancelled"):
                return run
            blob = " ".join(str(l.get("message", "")).lower()
                            for l in (run.get("logs") or []))
            if any(w in blob for w in SERVER_SIDE):
                return run
            if (run.get("progress") or 0) > 20:
                return run
            return None

        run, waited = tl.wait(
            "the KAPE collection to finish on the client",
            timeout_s=cfg.timeout("kape_collection", 30) * 60,
            poll_s=15, probe=probe,
            describe=lambda r: (r.get("details") or {}).get("phase")
                               or r.get("status"))

        ctx.check("KAPE collection finished client-side", bool(run),
                  actual=(run or {}).get("status"),
                  note="the hunt is gated on this so the endpoint never runs "
                       "two heavy collections at once")
        return {"waited_s": round(waited, 1),
                "status": (run or {}).get("status")}

    # ----------------------------------------------------------------- B --
    @runner.phase("hunt", "Agentic blueprint, dispatched as a Velociraptor hunt",
                  needs=("kape_gate",))
    def hunt(ctx):
        """Runs as a HUNT rather than a per-client flow because that is the path
        the platform is shipped to use, and the two behave differently: the hunt
        path live-pulls, while the agentic rescan path reads a stored
        raw_results.json."""
        c, client_id = ctx.get("client"), ctx.get("client_id")
        bp = _pick_blueprint(c, "/api/blueprints/agentic",
                             prefer=("windows",)) or \
             _pick_blueprint(c, "/api/blueprints/velociraptor",
                             prefer=("windows",))
        ctx.check("a Windows agentic blueprint exists", bool(bp))
        if not bp:
            return {}

        bp_id = bp.get("id") or bp.get("blueprint_id")
        body = c.post("/api/agentic/run", {
            "blueprint_id": bp_id,
            "blueprint": bp.get("name"),
            "client_ids": [client_id],
            "collection_minutes": max(5, cfg.timeout("blueprint_hunt", 30) // 2),
        })
        run_id = body.get("run_id") if isinstance(body, dict) else None
        ctx.check("hunt accepted", bool(run_id), actual=body)
        ctx.set(hunt_run_id=run_id)
        tl.ids(hunt_run_id=run_id)

        run = c.wait_for_run(run_id, cfg.timeout("blueprint_hunt", 30) * 60, tl,
                             what="the agentic blueprint hunt")
        ctx.check("hunt reached a terminal state", bool(run),
                  actual=(run or {}).get("status"))
        ctx.check("hunt succeeded", api_lib.run_succeeded(run),
                  expected="completed", actual=(run or {}).get("status"))

        # Assert ROWS COLLECTED, not findings.
        #
        # This pipeline is collect-only by design — its own final log line says
        # "fuse this run into a Case for analysis" — so findings are produced at
        # fusion, not here, and `details` carries no finding count at all.
        # Asserting findings against it failed a hunt that had just collected
        # 183 rows across 10 artifacts: the harness measuring the wrong thing,
        # not the platform misbehaving.
        rows, artifacts = _collected_counts(c, run_id)
        ctx.check("hunt collected rows from the endpoint", (rows or 0) > 0,
                  expected=">0 rows", actual=rows,
                  note="zero rows against a host we just ran detection bait on "
                       "would be the realistic bug")
        return {"run_id": run_id, "blueprint": bp.get("name"),
                "rows": rows, "artifacts": artifacts,
                "status": (run or {}).get("status")}

    # ---------------------------------------------------------------- A3 --
    @runner.phase("timesketch", "Wait for the Timesketch ingest to finish",
                  needs=("kape_gate",))
    def timesketch(ctx):
        """Waits for INDEXING to finish, not for the import call to return. An
        import that 202s and then fails asynchronously is the realistic bug, and
        it is invisible to a harness that only checks the response."""
        c, run_id = ctx.get("client"), ctx.get("kape_run_id")

        run = c.wait_for_run(run_id, cfg.timeout("timesketch_ingest", 45) * 60,
                             tl, what="the Timesketch ingest to finish")
        ctx.check("Timesketch automation reached a terminal state", bool(run),
                  actual=(run or {}).get("status"))
        ctx.check("Timesketch automation succeeded",
                  api_lib.run_succeeded(run),
                  expected="completed", actual=(run or {}).get("status"))

        # /api/timesketch/sketches returns only id/name/description — there is
        # no event count in it, so the old "sketch has events" check was
        # asserting against a field that does not exist and failed a pipeline
        # that had completed successfully. The pipeline's own logs are the
        # authoritative record: they report the sketch and timeline it created.
        sketch, timeline, done = _sketch_from_logs(c, run_id)
        ctx.check("a sketch was created", bool(sketch), actual=sketch)
        ctx.check("a timeline was indexed into the sketch", bool(timeline),
                  actual=timeline,
                  note="a sketch with no timeline means the import returned "
                       "but the index never landed — the realistic async bug")
        ctx.check("the import pipeline reported success", done,
                  expected="PIPELINE COMPLETED SUCCESSFULLY",
                  actual=done)
        ctx.set(sketch_id=sketch, timeline_id=timeline)
        tl.ids(sketch_id=str(sketch) if sketch else None)
        return {"sketch_id": sketch, "timeline_id": timeline,
                "status": (run or {}).get("status")}

    # ----------------------------------------------------------------- C --
    @runner.phase("volweb", "Acquire memory, run plugins and yara",
                  needs=("timesketch", "hunt"))
    def volweb(ctx):
        """Gated on BOTH the ingest and the hunt, so the endpoint is quiet when
        its memory is captured. Plugin output and yara are asserted separately:
        yara runs in its own worker and quietly no-ops if rules are missing, so
        folding it into a single "analysis completed" check would hide exactly
        the failure worth catching."""
        c, client_id = ctx.get("client"), ctx.get("client_id")
        bp = _pick_blueprint(c, "/api/blueprints/memory", prefer=("windows",)) \
            or _pick_blueprint(c, "/api/memory/blueprints", prefer=("windows",))

        payload = {"client_id": client_id,
                   "client_name": ctx.get("hostname") or client_id,
                   # VolWeb groups evidence under its own case name; keep it
                   # stable so repeat runs accumulate in one place rather
                   # than littering VolWeb with a case per run.
                   "case_name": "QA"}
        if bp:
            payload["blueprint_id"] = bp.get("id") or bp.get("blueprint_id")

        body = c.post("/api/memory/run", payload)
        run_id = body.get("run_id") if isinstance(body, dict) else None
        ctx.check("memory acquisition accepted", bool(run_id), actual=body)
        if not run_id:
            return {"response": body}
        ctx.set(volweb_run_id=run_id)
        tl.ids(volweb_run_id=run_id)

        run = c.wait_for_run(run_id, cfg.timeout("volweb_analysis", 60) * 60, tl,
                             what="VolWeb acquisition and analysis")
        ctx.check("VolWeb run reached a terminal state", bool(run),
                  actual=(run or {}).get("status"))
        ctx.check("VolWeb run succeeded", api_lib.run_succeeded(run),
                  expected="completed", actual=(run or {}).get("status"))

        det = (run or {}).get("details") or {}
        plugins = det.get("plugins") or det.get("plugin_results") or \
            det.get("extracted_plugins") or {}
        ctx.check("plugin output was produced", bool(plugins),
                  expected=">0 plugins",
                  actual=(list(plugins)[:6] if isinstance(plugins, (dict, list))
                          else plugins) if plugins
                  else f"none found; details keys = {sorted(det)[:12]}",
                  note="pslist proves the image parses at all")

        # Yara is asserted as HAVING RUN, not as having matched.
        #
        # The plan called for one targeted rule matching the canary the bait
        # writes into an RWX allocation, so that a miss would be unambiguous.
        # That is not reachable from here: rules come from VolWeb's seeded
        # corpus, scoped by the blueprint's yara_categories, and there is no
        # per-run rule-injection endpoint. Worse, the pipeline documents zero
        # hits as a legitimate outcome (services/memory/analyzers.py:195), so
        # asserting a hit would fail on a correctly working platform.
        #
        # What is still worth catching is the real failure mode the plan named:
        # yara quietly no-opping because its worker is dead or no rules are
        # active. So this asserts the scan executed and produced a result set,
        # and records the hit count as information. The report states plainly
        # that detection CONTENT was not verified.
        yara_ran = any(k in det for k in
                       ("yara_hits", "yara", "yarascan", "yara_summary"))
        yara_hits = det.get("yara_hits") or det.get("yara") or []
        hit_count = len(yara_hits) if isinstance(yara_hits, list) else yara_hits
        ctx.check("yara scan executed", yara_ran,
                  expected="a yarascan result set", actual=sorted(det)[:10],
                  note="catches the worker being dead or no rules active; a "
                       "zero-hit result is legitimate and is NOT a failure")
        if yara_ran and not hit_count:
            tl.warn("yara_zero_hits", detail={
                "note": "legitimate per the pipeline, but it means this run "
                        "did not exercise the yara matching path end to end"})

        for key in ("image_path", "memory_image", "dump_path"):
            if det.get(key):
                ctx.set(memory_image_paths=[det[key]])
                break

        return {"run_id": run_id, "plugins": plugins,
                "yara_ran": yara_ran, "yara_hits": hit_count,
                "status": (run or {}).get("status")}

    # ----------------------------------------------------------------- D --
    # Depends on the two collection stages, NOT on volweb passing.
    #
    # Fusion is the most valuable assertion in the run, and VolWeb is the
    # stage most likely to fail for reasons unrelated to it (a slow
    # acquisition, a missing symbol table, a dead yara worker). Making a
    # VolWeb check failure skip fusion would hide the answer we most want.
    # Fusion's own "memory/VolWeb contributed entities" check reports the
    # missing source clearly, so nothing is silently glossed over.
    @runner.phase("fusion", "Fuse the Case from all three sources",
                  needs=("timesketch", "hunt"))
    def fusion(ctx):
        """Fusion is the platform's core value and the thing most able to
        silently half-work: a Case that reports "fused" while having dropped a
        whole source looks correct until somebody trusts it. So "it completed"
        is not a pass."""
        c = ctx.get("client")
        member_runs = [r for r in (ctx.get("kape_run_id"), ctx.get("hunt_run_id"),
                                   ctx.get("volweb_run_id")) if r]

        # Fuse the PERSISTENT QA case the auth phase established, rather than
        # minting a per-run one. Every workflow this run started was already
        # tagged into it by the X-Case-Id header, so its members are the runs
        # this QA produced — plus the history of previous runs, which is the
        # point of a persistent case.
        case_id = ctx.get("qa_case_id")
        ctx.check("fusing the persistent QA case", bool(case_id),
                  actual=case_id, note="established in the auth phase")
        if not case_id:
            return {"error": "no QA case"}
        ctx.set(case_id=case_id)
        tl.ids(case_id=case_id)

        t0 = time.monotonic()
        fused = c.post(f"/api/cases/{case_id}/fuse", {},
                       timeout=cfg.timeout("fusion", 15) * 60)
        fuse_s = round(time.monotonic() - t0, 1)

        entities = fused.get("entities") if isinstance(fused, dict) else None
        rels = fused.get("relationships") if isinstance(fused, dict) else None
        findings = fused.get("findings") if isinstance(fused, dict) else None
        cross = fused.get("cross_host_findings") if isinstance(fused, dict) else None
        warnings = (fused.get("warnings") or []) if isinstance(fused, dict) else []

        ctx.check("fuse returned a graph", bool(entities), actual=entities)
        ctx.check("relationships were built", (rels or 0) > 0,
                  expected=">0", actual=rels,
                  note="entities with no relationships means concatenation, "
                       "not correlation")
        ctx.check("findings were produced", (findings or 0) > 0,
                  expected=">0", actual=findings)
        ctx.check("fusion emitted no warnings", not warnings,
                  actual=warnings[:5],
                  note="a warning here usually means a source was dropped")

        # Every source must have contributed. A Case built from one source
        # still fuses fine, so counting entities proves nothing on its own.
        # The graph is nested under `fusion_graph`; the top level carries
        # case_id and import_in_progress. Reading the top level for entities
        # would silently find none and report every source as missing.
        graph_body = _safe_get(c, f"/api/cases/{case_id}/graph") or {}
        graph = graph_body.get("fusion_graph") or graph_body
        ctx.check("fusion import is not still running",
                  not graph_body.get("import_in_progress"),
                  note="asserting on a graph that is still importing reads "
                       "as missing sources")
        sources = _sources_in(graph)
        for want, label in (("velociraptor", "Velociraptor"),
                            ("timesketch", "Timesketch"),
                            ("memory", "memory/VolWeb")):
            ctx.check(f"{label} contributed entities",
                      any(want in s for s in sources),
                      expected=want, actual=sorted(sources)[:8],
                      note="this is the real 'fuse everything' test")

        # Correlation, not concatenation: the host must appear ONCE.
        hosts = _safe_get(c, f"/api/cases/{case_id}/hosts") or {}
        host_list = hosts.get("hosts") if isinstance(hosts, dict) else hosts
        host_list = host_list if isinstance(host_list, list) else []
        ctx.check("the Windows host is one asset, not one per source",
                  len(host_list) == 1, expected=1, actual=len(host_list),
                  note="duplicates mean the resolver silently failed while every "
                       "count still looks healthy")

        return {"case_id": case_id, "fuse_seconds": fuse_s,
                "entities": entities, "relationships": rels,
                "findings": findings, "cross_host_findings": cross,
                "warnings": warnings, "sources": sorted(sources),
                "member_runs": member_runs}


# --- helpers -------------------------------------------------------------


def _safe_get(c, path):
    try:
        return c.get(path)
    except Exception:                                         # noqa: BLE001
        return None


def _pick_blueprint(c, path, by_id=None, prefer=()):
    """Select a blueprint: exact id first, then a name substring, then the first.

    Exact id first because name matching is fragile in a way that fails
    quietly. Searching for "triage" to find a KAPE blueprint selected
    "Forensic Timeline: Full Triage" over "Event Logs Only" — a valid
    blueprint, just the slowest one, so the run worked and merely took an order
    of magnitude longer than intended.
    """
    body = _safe_get(c, path)
    if body is None:
        return None
    items = body.get("blueprints", body) if isinstance(body, dict) else body
    items = [it for it in (items or []) if isinstance(it, dict)]
    if not items:
        return None

    if by_id:
        for it in items:
            if (it.get("id") or it.get("blueprint_id")) == by_id:
                return it
    for want in prefer:
        for it in items:
            if want in (it.get("name") or "").lower():
                return it
    return items[0]


def _finding_count(run):
    if not isinstance(run, dict):
        return None
    det = run.get("details") or {}
    for key in ("findings", "finding_count", "results", "hits"):
        val = det.get(key)
        if isinstance(val, int):
            return val
        if isinstance(val, list):
            return len(val)
    return None


def _run_log_text(c, run_id):
    run = c.run_status(run_id) or {}
    return "\n".join(str(l.get("message", "")) for l in (run.get("logs") or []))


def _collected_counts(c, run_id):
    """(rows, artifacts) as the collection pipeline reported them.

    Read from the run's own log line — "Collected 183 row(s) across 10
    artifact(s)" — because `details` carries no counts.
    """
    import re
    m = re.search(r"Collected\s+([\d,]+)\s+row\(s\)\s+across\s+([\d,]+)\s+artifact",
                  _run_log_text(c, run_id), re.I)
    if not m:
        return None, None
    return (int(m.group(1).replace(",", "")),
            int(m.group(2).replace(",", "")))


def _sketch_from_logs(c, run_id):
    """(sketch_id, timeline_id, completed_ok) from the import pipeline's logs."""
    import re
    text = _run_log_text(c, run_id)
    sketch = re.search(r"Sketch(?: ID)?:\s*.*?\(?ID:?\s*(\d+)\)?", text, re.I) \
        or re.search(r"Sketch ID:\s*(\d+)", text, re.I)
    timeline = re.search(r"Timeline(?: ID)?:\s*.*?\(?ID:?\s*(\d+)\)?", text, re.I) \
        or re.search(r"Timeline ID:\s*(\d+)", text, re.I)
    done = "PIPELINE COMPLETED SUCCESSFULLY" in text.upper()
    return (sketch.group(1) if sketch else None,
            timeline.group(1) if timeline else None, done)


def _sketch_with_events(c):
    """The sketch with the most events, as (sketch_id, event_count, keys).

    The third element is the item's key names. Sketch payload shape is not
    pinned anywhere, so if the count is under a name this does not know, the
    failure message can say which names exist instead of just reporting zero.
    """
    body = _safe_get(c, "/api/timesketch/sketches")
    if body is None:
        return None, None, []
    items = body.get("sketches", body) if isinstance(body, dict) else body
    items = [it for it in (items or []) if isinstance(it, dict)]
    if not items:
        return None, 0, []

    def count(it):
        for key in ("event_count", "events", "num_events", "total_events"):
            try:
                return int(it.get(key) or 0)
            except (TypeError, ValueError):
                continue
        return 0

    best = max(items, key=count)
    return (best.get("id") or best.get("sketch_id"), count(best),
            sorted(best.keys())[:12])


def _sources_in(graph):
    """Every module name that contributed an entity, lowercased."""
    out = set()
    entities = graph.get("entities") or graph.get("nodes") or []
    for e in entities:
        if not isinstance(e, dict):
            continue
        srcs = e.get("sources") or e.get("source") or []
        if isinstance(srcs, str):
            srcs = [srcs]
        for s in srcs:
            if isinstance(s, str):
                out.add(s.lower())
            elif isinstance(s, dict):
                for key in ("module", "source", "name"):
                    if s.get(key):
                        out.add(str(s[key]).lower())
    return out
