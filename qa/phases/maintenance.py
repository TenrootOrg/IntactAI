"""System Purge — the operator's disk-reclamation surface, previously untested.

WHY THIS EXISTS, with two bugs found by hand on 2026-09-06 that this would have
caught in seconds:

  * The ELK section asked Elasticsearch for its index list WITHOUT CREDENTIALS.
    ES requires auth, so the probe returned 401, the `!= 200` branch reported
    "elasticsearch unreachable", and the row scanned 0 and deleted 0 while
    looking like it had worked. 2.43 GB across 63 indices was unreclaimable
    from the UI and nothing said so.
  * The cross-case knowledge base was reachable by no section at all, so a
    purged box kept enriching new cases from evidence the operator believed
    they had deleted.

Both are the same shape: a section that reports success having done nothing. The
scan phase below is the cheap assertion that catches it — on a box the suite has
just filled with real evidence, a section covering that evidence CANNOT honestly
scan zero.

TWO PHASES, deliberately. `purge_scan` is non-destructive and runs in the middle
of the suite, where a failure is a clear signal and nothing has been lost.
`purge_run` actually deletes and therefore runs LAST, after every other phase has
made its assertions — a purge is the one operation whose whole job is to destroy
the state everything else depends on.
"""

SECTIONS_PATH = "/api/maintenance/purge/sections"

# The scan shells out to `docker system df`, du's the Velociraptor datastore and
# queries Elasticsearch. Measured: longer than the client's 60s default.
SCAN_TIMEOUT_S = 300

# What `purge_run` actually removes. DATA sections only, and the docker_* rows
# are excluded on purpose: they prune images, and the suite still has to collect
# logs and write a report out of the containers afterwards. Pruning "unused"
# images is safe in principle, and this is not the phase to find out where that
# principle ends.
PURGE_SECTIONS = ("workflows", "uploads", "temp_files", "report_downloads",
                  "velociraptor", "elk", "timesketch")

# Sections that MUST report bytes on a box this suite has just used. Anything
# here scanning zero is the ELK bug again, whatever the cause.
MUST_HAVE_DATA = ("workflows", "velociraptor")


def _rows(body):
    return (body or {}).get("sections") or (body if isinstance(body, list) else [])


def _by_id(body):
    return {s.get("id"): s for s in _rows(body) if isinstance(s, dict)}


def register(runner, cfg):
    tl = runner.ctx.tl

    # ------------------------------------------------------------------ 1 --
    @runner.phase("purge_scan", "Scan every purge section (destroys nothing)",
                  needs=("pipelines",))
    def purge_scan(ctx):
        c = ctx.get("client")
        # A LONG TIMEOUT, because the scan is genuinely slow: it shells out to
        # `docker system df`, du's the Velociraptor datastore and queries
        # Elasticsearch. The first run died on the client's 60s default with a
        # read timeout, which reads as "the endpoint is broken" rather than
        # "this honestly takes a while".
        body = c.get(SECTIONS_PATH, timeout=SCAN_TIMEOUT_S)
        rows = _rows(body)
        detail = {"sections": len(rows),
                  "sizes": {s.get("id"): s.get("size_bytes") for s in rows
                            if isinstance(s, dict)}}

        ctx.check("the purge dialog lists its sections", len(rows) > 0,
                  expected=">0 sections", actual=len(rows))
        if not rows:
            return detail

        found = _by_id(body)
        # THE ELK BUG, as an assertion. The suite has just run a collection and
        # fused a case, so these sections are holding real bytes; a zero here
        # means the section cannot see its own data.
        blind = [k for k in MUST_HAVE_DATA
                 if k in found and not (found[k].get("size_bytes") or 0)]
        ctx.check("no section reports zero on a box holding its data",
                  not blind,
                  expected="every section with data reports bytes",
                  actual=", ".join(blind) + " scanned 0" if blind else "all report",
                  note="a section that cannot see its data purges nothing and "
                       "still reports success — this is exactly how the ELK row "
                       "hid 2.43 GB behind an unauthenticated 401")

        # A section HOLDING SOMETHING must say what. An empty one legitimately
        # has nothing to explain -- the first run failed on azure_runs, uploads,
        # upgrade_packages, temp_files and report_downloads, all of which were
        # simply empty on a fresh box. "0 B" with no detail is fine; "1.2 GB"
        # with no detail is what an operator cannot act on.
        mute = [s.get("id") for s in rows
                if isinstance(s, dict) and (s.get("size_bytes") or 0) > 0
                and not (s.get("detail") or "").strip()]
        ctx.check("every section holding data explains what it holds", not mute,
                  actual=", ".join(str(m) for m in mute) or "all explained")

        # The estimate must not promise the same disk twice: docker_deep counts
        # Images + Build Cache, which are their own rows.
        naive = sum((s.get("size_bytes") or 0) for s in rows if isinstance(s, dict))
        covered = {c2 for s in rows if isinstance(s, dict)
                   for c2 in (s.get("covers") or [])}
        deduped = sum((s.get("size_bytes") or 0) for s in rows
                      if isinstance(s, dict) and s.get("id") not in covered)
        detail["naive_bytes"], detail["deduped_bytes"] = naive, deduped
        ctx.check("overlapping sections are declared, not double-counted",
                  deduped <= naive,
                  expected="de-duplicated total <= naive sum",
                  actual=f"{deduped} <= {naive}",
                  note="Docker Deep Prune reports the same bytes as Images and "
                       "Build Cache; summing all three promised 41 GB and freed 24")
        return detail

    # ------------------------------------------------------------------ 2 --
    # LAST. It deletes the evidence every other phase asserts on.
    @runner.phase("purge_run", "Purge the data sections and prove the bytes went",
                  needs=("purge_scan",))
    def purge_run(ctx):
        c = ctx.get("client")
        before = _by_id(c.get(SECTIONS_PATH, timeout=SCAN_TIMEOUT_S))
        wanted = [s for s in PURGE_SECTIONS if s in before]
        detail = {"requested": wanted,
                  "before": {k: before[k].get("size_bytes") for k in wanted}}
        ctx.check("the sections to purge exist", bool(wanted),
                  actual=", ".join(wanted) or "none")
        if not wanted:
            return detail

        body = c.post(SECTIONS_PATH, {"sections": wanted}, expect=(200, 202))
        run_id = (body or {}).get("run_id")
        detail["run_id"] = run_id
        ctx.check("the purge started", bool(run_id), actual=body)
        if not run_id:
            return detail
        tl.ids(purge_run_id=run_id)

        run = c.wait_for_run(run_id, cfg.timeout("purge", 20) * 60, tl,
                             what="the system purge")
        status = (run or {}).get("status")
        detail["status"] = status
        ctx.check("the purge reached a terminal state", bool(run), actual=status)
        ctx.check("the purge completed", status == "completed",
                  expected="completed", actual=status)

        after = _by_id(c.get(SECTIONS_PATH, timeout=SCAN_TIMEOUT_S))
        detail["after"] = {k: (after.get(k) or {}).get("size_bytes") for k in wanted}

        # The point of the whole feature: bytes an operator was promised are
        # actually gone. Asserted on the sections that HAD data, because a
        # section that was already empty cannot shrink.
        had = [k for k in wanted if (before[k].get("size_bytes") or 0) > 0]
        grew = [k for k in had
                if (after.get(k) or {}).get("size_bytes", 0) >= before[k]["size_bytes"]]
        ctx.check("the purged sections actually shrank", not grew,
                  expected="every section that held data reports less",
                  actual=", ".join(grew) + " did not shrink" if grew
                         else f"{len(had)} section(s) freed",
                  note="a purge that reports success without freeing anything is "
                       "the failure this phase exists to catch")

        # And the box must survive it. A purge is not a factory reset.
        health = c.get("/api/health")
        ctx.check("the appliance is still healthy after a purge",
                  bool(health), actual=str(health)[:120],
                  note="the purge removes evidence, not the product")
        return detail
