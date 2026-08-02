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
KAPE_TARGET = "_KapeTriage"
VOLATILITY_PLUGINS = ["windows.pslist", "windows.malfind"]


def register(runner, cfg):
    tl = runner.ctx.tl

    # ---------------------------------------------------------------- A1 --
    @runner.phase("kape", "Start the KAPE collection (Timesketch automation)",
                  needs=("activity",))
    def kape(ctx):
        c, client_id = ctx.get("client"), ctx.get("client_id")
        bp = _pick_blueprint(c, "/api/blueprints/timesketch",
                             prefer=("kape", "triage", "windows"))
        ctx.check("a Timesketch blueprint exists", bool(bp),
                  note="the shipped default blueprint set should provide one")

        payload = {"client_id": client_id,
                   "client_name": ctx.get("hostname") or client_id,
                   "kape_target": KAPE_TARGET}
        if bp:
            payload["blueprint_id"] = bp.get("id") or bp.get("blueprint_id")
            payload["blueprint"] = bp.get("name")

        body = c.post("/api/velociraptor/timesketch", payload)
        run_id = body.get("run_id") if isinstance(body, dict) else None
        flow_id = body.get("flow_id") if isinstance(body, dict) else None

        ctx.check("KAPE collection accepted", bool(run_id), actual=body)
        # Captured at LAUNCH, not on completion: if this hangs, the id is what
        # lets an operator go and look at it in the product.
        ctx.set(kape_run_id=run_id, kape_flow_id=flow_id)
        tl.ids(kape_run_id=run_id, kape_flow_id=flow_id)
        return {"run_id": run_id, "flow_id": flow_id,
                "kape_target": KAPE_TARGET,
                "blueprint": payload.get("blueprint")}

    # ---------------------------------------------------------------- A2 --
    @runner.phase("kape_gate", "Wait for the collection to finish client-side",
                  needs=("kape",))
    def kape_gate(ctx):
        """The gate that lets the hunt start. Watches for the collection to
        stop running ON THE CLIENT — not for the whole Timesketch automation to
        finish, which includes a server-side ingest that can safely overlap."""
        c, run_id = ctx.get("client"), ctx.get("kape_run_id")

        def probe():
            run = c.run_status(run_id)
            if not run:
                return None
            det = run.get("details") or {}
            phase = (det.get("phase") or "").lower()
            status = (run.get("status") or "").lower()
            # Either the automation has moved past collection into an
            # ingest/processing phase, or it has finished outright.
            if status in ("completed", "success", "failed", "error"):
                return run
            if phase and not any(w in phase for w in
                                 ("collect", "kape", "start", "queue", "wait")):
                return run
            if det.get("collection_complete") or det.get("kape_ready"):
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

        det = (run or {}).get("details") or {}
        findings = _finding_count(run)
        ctx.check("hunt produced findings", (findings or 0) > 0,
                  expected=">0",
                  # Report the available keys, not just "None". If the count is
                  # simply under a name this does not know, the failure message
                  # is the fix rather than the start of an investigation.
                  actual=findings if findings is not None
                  else f"no count found; details keys = {sorted(det)[:12]}",
                  note="a hunt that completes with zero findings against a host "
                       "we just ran detection bait on is the realistic bug")
        return {"run_id": run_id, "blueprint": bp.get("name"),
                "findings": findings, "status": (run or {}).get("status")}

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

        sketch, events, keys = _sketch_with_events(c)
        ctx.check("a sketch exists", bool(sketch), actual=sketch)
        ctx.check("the sketch has events", (events or 0) > 0,
                  expected=">0",
                  actual=events if events else f"0; sketch keys = {keys}",
                  note="a sketch that indexes zero events after a KAPE triage "
                       "of a host with freshly-generated activity is a failure, "
                       "not a quiet box")
        ctx.set(sketch_id=sketch, sketch_events=events)
        tl.ids(sketch_id=str(sketch) if sketch else None)
        return {"sketch_id": sketch, "events": events,
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
                   "case_name": f"QA {ctx.tl.run_id}"}
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

        body = c.post("/api/cases", {"name": f"QA {ctx.tl.run_id}",
                                     "member_run_ids": member_runs,
                                     "min_severity": "low"})
        case_id = body.get("case_id") if isinstance(body, dict) else None
        ctx.check("case created", bool(case_id), actual=body)
        if not case_id:
            return {"response": body}
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


def _pick_blueprint(c, path, prefer=()):
    body = _safe_get(c, path)
    if body is None:
        return None
    items = body.get("blueprints", body) if isinstance(body, dict) else body
    if not isinstance(items, list) or not items:
        return None
    for want in prefer:
        for it in items:
            if isinstance(it, dict) and want in (it.get("name") or "").lower():
                return it
    return items[0] if isinstance(items[0], dict) else None


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
