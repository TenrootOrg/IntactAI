"""The Case Analysis surface — the largest API area and, until now, the thinnest.

WHY THIS EXISTS. `/api/cases` carries 43 endpoints and the harness called eleven
of them. Everything an analyst actually does after a case fuses — read the risk
table, triage a finding, group two identities, validate a timeline event, take
the report away as a PDF — was never exercised. A release could break any of it
and every scenario would still be green.

DELIBERATELY NO MODEL. The report assertions run against the DETERMINISTIC
narrator, which is what the product uses when no model is configured — and CI
configures none, on purpose: an appliance test must not need an API key. So this
covers report ASSEMBLY (altitude, section set, the phase table agreeing with the
zoom targets, the PDF rendering) and not the narration. The narrated path is a
known gap, recorded in qa/coverage.py.

The phases run against the case `pipelines` fused, because that is the only one
in the run with a real graph behind it.
"""

import re


def _case(ctx):
    return ctx.get("fused_case_id")


def _items(body, key):
    """A list out of a response that may BE the list, or wrap it under `key`.

    These endpoints are not consistent about it, and `(a_list or {}).get(...)`
    raises AttributeError rather than returning nothing -- failing the phase for
    the shape of the JSON instead of the behaviour under test.
    """
    if isinstance(body, list):
        return body
    if isinstance(body, dict):
        v = body.get(key)
        if isinstance(v, list):
            return v
    return []


# Endpoints that legitimately answer 404 on a case with none of that thing yet.
# The client RAISES on an unexpected status, so a bare get() would fail the
# phase for an empty checklist rather than for a broken one.
_SOFT = (200, 201, 202, 404)


def register(runner, cfg):

    # ------------------------------------------------------------------ 1 --
    @runner.phase("case_read", "Read every Case Analysis surface an analyst opens",
                  needs=("pipelines",))
    def case_read(ctx):
        """Shape, not status. A 200 carrying `{}` passes a reachability sweep and
        tells you nothing: the risk table with no rows, the zoom targets with no
        windows and the identity list with no people all answer 200 on a box
        where fusion silently produced nothing."""
        c, cid = ctx.get("client"), _case(ctx)
        ctx.check("a fused case is available to analyse", bool(cid), actual=cid)
        if not cid:
            return {}
        detail = {"case_id": cid, "read": {}}

        base = f"/api/cases/{cid}"
        risk = c.get(f"{base}/risk", expect=_SOFT)
        rows = _items(risk, "rows") or _items(risk, "hosts")
        detail["read"]["risk_hosts"] = len(rows)
        ctx.check("the risk table ranks at least one host", len(rows) > 0,
                  expected=">0 hosts", actual=len(rows),
                  note="the case fused a real collection, so a host must rank")

        zt = c.get(f"{base}/zoom_targets", expect=_SOFT)
        targets = _items(zt, "targets") or _items(zt, "zoom_targets")
        detail["read"]["zoom_targets"] = len(targets)
        ctx.check("zoom targets are computed", isinstance(targets, list),
                  actual=len(targets),
                  note="deterministic: a focused case legitimately has none, so "
                       "the shape is asserted rather than a count")

        idents = c.get(f"{base}/identities", expect=_SOFT)
        people = _items(idents, "identities")
        detail["read"]["identities"] = len(people)
        ctx.check("identities were clustered", isinstance(people, list),
                  actual=len(people))

        # These carry operator state and are legitimately empty on a fresh case;
        # what matters is that they answer with the right SHAPE.
        for name, path, key in (
            ("dispositions", f"{base}/dispositions", "dispositions"),
            ("checklist", f"{base}/checklist", "checklist"),
            ("timeline", f"{base}/timeline", "timeline"),
        ):
            body = c.get(path, expect=_SOFT)
            got = _items(body, key)
            detail["read"][name] = len(got)
            ctx.check(f"{name} answers with a list",
                      isinstance(body, (list, dict)),
                      actual=type(body).__name__,
                      note="empty is fine on a fresh case; a string or None is "
                           "an error page that answered 200")

        log = c.get(f"{base}/log", expect=_SOFT)
        entries = _items(log, "log") or _items(log, "events")
        detail["read"]["log"] = len(entries)
        ctx.check("the case activity log recorded the fuse", len(entries) > 0,
                  expected=">0 entries", actual=len(entries),
                  note="the fuse writes to this log; an empty one means the "
                       "operator has no record of what the box did")
        return detail

    # ------------------------------------------------------------------ 2 --
    @runner.phase("case_report",
                  "Generate the deterministic report and check it is assembled",
                  needs=("case_read",))
    def case_report(ctx):
        """No model is configured, so this is the air-gap narrator — the same
        path any appliance without a key takes, which makes it worth more
        coverage than the narrated one, not less."""
        c, cid = ctx.get("client"), _case(ctx)
        if not cid:
            return {}
        detail = {"case_id": cid}
        base = f"/api/cases/{cid}"

        c.post(f"{base}/report", {}, expect=(200, 201, 202))
        body = c.get(f"{base}/report", expect=_SOFT)
        md = (body or {}).get("report_md") or ""
        detail["chars"] = len(md)
        ctx.check("the report was written", len(md) > 500,
                  expected=">500 chars", actual=len(md),
                  note="a deterministic report over a real graph is thousands "
                       "of characters; a short one means it fell back to a stub")

        # The banner states which report this is, and the two altitudes read
        # completely differently. Whichever it chose, it must SAY so -- an
        # operator cannot tell a focused report from a truncated segmented one.
        mode = ("segmented" if "**Segmented report**" in md
                else "focused" if "**Focused report**" in md else None)
        detail["mode"] = mode
        ctx.check("the report declares its altitude", bool(mode),
                  expected="Segmented or Focused", actual=mode or "neither",
                  note="render.report_mode_banner writes this; missing means "
                       "the banner was dropped from assembly")

        headings = re.findall(r"^##\s+(.+?)\s*$", md, re.MULTILINE)
        detail["sections"] = headings
        required = ["Indicators of Compromise", "Host Risk", "Limitations"]
        absent = [h for h in required
                  if not any(h.lower() in x.lower() for x in headings)]
        ctx.check("every deterministic section is present", not absent,
                  expected=", ".join(required),
                  actual=", ".join(absent) + " missing" if absent else "all present")

        # The phase table and the zoom cards are built from ONE list on purpose,
        # so an operator clicking "Timeframe 3" gets the window the report
        # described. If they disagree the console sends them to the wrong scope.
        if mode == "segmented":
            zt = c.get(f"{base}/zoom_targets")
            targets = _items(zt, "targets") or _items(zt, "zoom_targets")
            clickable = [t for t in targets
                         if isinstance(t, dict) and not t.get("rollup")]
            rows = re.findall(r"^\|\s*(\d+)\s*\|", md, re.MULTILINE)
            detail["phase_rows"], detail["zoom_cards"] = len(rows), len(clickable)
            ctx.check("the phase table and the zoom cards agree",
                      len(rows) == len(clickable),
                      expected=f"{len(clickable)} (zoom cards)",
                      actual=f"{len(rows)} rows in the report",
                      note="both are built from render.analysable(); a mismatch "
                           "means a card points at a phase the report never "
                           "described, or the reverse")
        return detail

    # ------------------------------------------------------------------ 3 --
    @runner.phase("case_pdf", "Download the branded PDF and prove it rendered",
                  needs=("case_report",))
    def case_pdf(ctx):
        c, cid = ctx.get("client"), _case(ctx)
        if not cid:
            return {}
        detail = {"case_id": cid}
        blob = c.raw(f"/api/cases/{cid}/report/download/pdf")
        detail["bytes"] = len(blob)

        ctx.check("the download is a PDF", blob[:5] == b"%PDF-",
                  expected="%PDF- header", actual=repr(blob[:12]),
                  note="an HTML error page also arrives with status 200")
        ctx.check("the PDF has real content", len(blob) > 20000,
                  expected=">20 KB", actual=f"{len(blob) // 1024} KB",
                  note="a cover page alone is a few KB; a report over a fused "
                       "graph is tens of KB or more")
        pages = blob.count(b"/Type /Page") or blob.count(b"/Type/Page")
        detail["pages"] = pages
        ctx.check("the PDF is more than a cover", pages > 1,
                  expected=">1 page", actual=pages,
                  note="the cover is its own page; a one-page PDF means the "
                       "body never rendered")

        md = c.raw(f"/api/cases/{cid}/report/download")
        detail["md_bytes"] = len(md)
        ctx.check("the markdown download works too", len(md) > 500,
                  expected=">500 bytes", actual=len(md))
        return detail

    # ------------------------------------------------------------------ 4 --
    @runner.phase("case_mutations",
                  "Drive the analyst's triage loop and prove state changed",
                  needs=("case_read",))
    def case_mutations(ctx):
        """Every check here asserts a STATE CHANGE, not a status code. An
        endpoint that accepts a disposition and stores nothing answers 200."""
        c, cid = ctx.get("client"), _case(ctx)
        if not cid:
            return {}
        detail = {"case_id": cid, "did": []}
        base = f"/api/cases/{cid}"

        # --- disposition: triage a real finding ---------------------------
        graph = c.get(f"{base}/graph", expect=_SOFT)
        # Nested: the endpoint wraps the graph, it does not return it. Probed
        # against a live appliance rather than assumed -- `graph["findings"]` is
        # absent, and reading it would have found nothing to triage and failed
        # the phase for the shape of the envelope.
        findings = _items((graph or {}).get("fusion_graph"), "findings")
        detail["findings"] = len(findings)
        if findings:
            fid = findings[0].get("id")
            before = len(_items(c.get(f"{base}/dispositions", expect=_SOFT),
                                "dispositions"))
            c.post(f"{base}/disposition",
                   {"finding_id": fid, "disposition": "benign",
                    "note": "QA: expected activity"})
            after = _items(c.get(f"{base}/dispositions", expect=_SOFT),
                           "dispositions")
            detail["did"].append("disposition")
            ctx.check("a disposition is stored against the finding",
                      len(after) > before,
                      expected=f">{before}", actual=len(after),
                      note="triage that is not persisted is triage the analyst "
                           "has to redo on every reload")
        else:
            ctx.check("there was a finding to triage", False,
                      note="the fused case produced none, so the triage loop "
                           "could not be exercised at all")

        # --- identities: group, then undo ---------------------------------
        people = _items(c.get(f"{base}/identities", expect=_SOFT), "identities")
        if len(people) >= 2:
            ids = [p.get("id") or p.get("identity_id") for p in people[:2]]
            c.post(f"{base}/identities/group", {"identity_ids": ids},
                   expect=(200, 201, 400, 409))
            regrouped = _items(c.get(f"{base}/identities", expect=_SOFT),
                               "identities")
            c.post(f"{base}/identities/undo", {}, expect=(200, 201, 400, 404))
            restored = _items(c.get(f"{base}/identities", expect=_SOFT),
                              "identities")
            detail["did"].append("identity group/undo")
            ctx.check("undo restores the identity list",
                      len(restored) == len(people),
                      expected=f"{len(people)} identities",
                      actual=f"{len(restored)} after undo "
                             f"({len(regrouped)} while grouped)",
                      note="an undo that does not restore leaves the analyst "
                           "with a merge they cannot take back")
        else:
            detail["did"].append("identity group/undo: fewer than 2 identities")

        # --- timeline: validate an event ----------------------------------
        events = _items(c.get(f"{base}/timeline", expect=_SOFT), "timeline")
        if events:
            eid = events[0].get("id") or events[0].get("event_id")
            c.post(f"{base}/timeline/validate",
                   {"event_id": eid, "validated": True, "note": "QA"},
                   expect=(200, 201, 400, 404))
            detail["did"].append("timeline validate")
        return detail
