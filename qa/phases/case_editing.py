"""The analyst's EDITING surface — the half of Case Analysis nothing drove.

WHY THIS EXISTS. `qa/phases/analysis.py` proved the case can be READ and that a
disposition sticks. What it never touched is everything that CHANGES the case
after it fuses: entering a fact the tooling could not know, re-scoping the case
from a macro report, and the per-occurrence drill-downs the UI opens on a click.
Seventeen `/api/cases` endpoints had no caller in this suite at all.

THE BUG CLASS THIS IS AIMED AT, stated plainly because it is not hypothetical.
Every one of these actions RE-FUSES the case. `intact-20260903` shipped an
UnboundLocalError on exactly that path — any re-fuse of a case that already had
a report answered 500 — and it reached a release because no test re-fused a
case twice. `case_mutations` catches it via dispositions; these phases catch it
via the other four doors into the same code, which is what a regression will
walk through next time.

WHAT IS ASSERTED. State, never status. A 200 that stored nothing is the failure
mode these endpoints actually have: `timeline/validate` silently ignored a
payload with the wrong key for weeks and answered 400, which the old check
accepted. So every mutation here reads the state back and compares.

ORDER. `case_zoom` runs last and is deliberately destructive — it narrows the
case to one target's hosts and window. It restores the previous scope afterwards
through the config rail (which is itself untested otherwise), but a phase that
re-scopes a case has no business running before the ones that read it whole.
"""

# Endpoints that legitimately answer 404 when the case has none of that thing.
_SOFT = (200, 201, 202, 404)


def _case(ctx):
    return ctx.get("fused_case_id")


def _items(body, key):
    if isinstance(body, list):
        return body
    if isinstance(body, dict) and isinstance(body.get(key), list):
        return body[key]
    return []


def register(runner, cfg):

    # ------------------------------------------------------------------ 1 --
    @runner.phase("case_surfaces",
                  "Open the per-click drill-downs the case UI fetches on demand",
                  needs=("case_read",))
    def case_surfaces(ctx):
        """The read endpoints `case_read` does not open. Each one backs a click
        in the UI, and each one can 500 on a real graph while the list view it
        was reached from stays perfectly healthy."""
        c, cid = ctx.get("client"), _case(ctx)
        if not cid:
            ctx.check("a fused case is available", False, actual=cid)
            return {}
        base, detail = f"/api/cases/{cid}", {"case_id": cid}

        # metrics / members / log: three separate stores, three separate ways
        # for a case to look fine and be empty.
        m = c.get(f"{base}/metrics", expect=_SOFT)
        detail["llm_enabled"] = (m or {}).get("llm_enabled")
        ctx.check("the case reports its token accounting", isinstance(m, dict)
                  and "token_ab" in m, actual=sorted(m) if isinstance(m, dict) else m,
                  note="CI configures no model, so llm_enabled is expected false; "
                       "the SHAPE still has to be there or the cost rail is blank")

        members = _items(c.get(f"{base}/members", expect=_SOFT), "members")
        detail["members"] = len(members)
        ctx.check("the case lists the runs it was built from", len(members) > 0,
                  expected=">0 member runs", actual=len(members),
                  note="a case with no members fused from nothing; the graph "
                       "assertions elsewhere would still pass on cached data")

        log = _items(c.get(f"{base}/log", expect=_SOFT), "log")
        detail["log_entries"] = len(log)
        ctx.check("the activity log has entries", len(log) > 0, actual=len(log))

        # The drill-downs. A finding id comes from the graph, so this is the
        # exact id the UI would send.
        graph = c.get(f"{base}/graph", expect=_SOFT)
        findings = _items((graph or {}).get("fusion_graph"), "findings")
        detail["findings"] = len(findings)
        if not findings:
            ctx.check("the graph carries findings to drill into", False,
                      note="nothing to click, so the drill-down endpoints could "
                           "not be exercised")
            return detail

        fid = findings[0].get("id")
        det = c.get(f"{base}/finding/{fid}", expect=_SOFT)
        ctx.check("a finding opens its per-occurrence detail",
                  isinstance(det, dict) and bool(det),
                  actual=sorted(det)[:8] if isinstance(det, dict) else det,
                  note="this is the row-click in the timeline table")

        ev = c.get(f"{base}/findings/{fid}/evidence", expect=_SOFT)
        rows = _items(ev, "rows")
        detail["evidence_rows"] = len(rows)
        # A finding whose locators resolve to nothing is a broken chain from the
        # finding back to the raw telemetry -- the thing that makes a report
        # defensible. Reported, not failed: some finding types are derived and
        # legitimately carry no single raw row.
        ctx.check("the evidence drill-down answers with a row count",
                  isinstance(ev, dict) and "count" in ev,
                  actual=(ev or {}).get("count"),
                  note="the retrieval primitive behind on-demand deepening; "
                       f"{len(rows)} raw row(s) resolved for this finding")
        return detail

    # ------------------------------------------------------------------ 2 --
    @runner.phase("case_timeline_edit",
                  "Enter an out-of-band fact, triage it, and take it back out",
                  needs=("case_read",))
    def case_timeline_edit(ctx):
        """Manual timeline events are how an analyst records what the tooling
        cannot see -- 'IT pushed a GPO at 14:05'. They are stored on the case
        rather than in the graph, so they survive re-fusion, and NOTHING tested
        that they are created, merged into the timeline, triaged or removed.

        Payloads verified against a live appliance rather than inferred: the
        route requires `title`, returns the event under `event`, and the id it
        assigns (`finding_id`, prefixed `manual:`) is what delete takes.
        """
        c, cid = ctx.get("client"), _case(ctx)
        if not cid:
            return {}
        base, detail = f"/api/cases/{cid}", {"case_id": cid}

        before = len(_items(c.get(f"{base}/timeline", expect=_SOFT), "timeline"))
        detail["timeline_before"] = before

        body = c.post(f"{base}/timeline/event",
                      {"title": "QA: IT-known maintenance window",
                       "ts": "2026-01-01T00:00:00Z",
                       "description": "Entered by the e2e suite",
                       "host": "-", "severity": "informational"},
                      expect=(200, 201))
        eid = ((body or {}).get("event") or {}).get("finding_id")
        detail["event_id"] = eid
        ctx.check("the manual event was created and given an id", bool(eid),
                  actual=body,
                  note="the operator's own account of events is a first-class "
                       "part of the report; losing it loses the context that "
                       "makes the machine findings mean anything")
        if not eid:
            return detail

        rows = _items(c.get(f"{base}/timeline", expect=_SOFT), "timeline")
        mine = [r for r in rows if r.get("finding_id") == eid]
        detail["timeline_after_add"] = len(rows)
        ctx.check("the manual event is merged into the timeline", bool(mine),
                  expected=f"{before + 1} rows including {eid}",
                  actual=f"{len(rows)} rows, {len(mine)} matching",
                  note="stored but not merged means the analyst types it in and "
                       "it never appears in the report")

        # Triage it. The route takes finding_id + status -- NOT event_id, which
        # is what this suite used to send: the endpoint answered 400, 400 was in
        # the accepted set, and the check passed having changed nothing.
        c.post(f"{base}/timeline/validate",
               {"finding_id": eid, "status": "not_real", "notes": "QA"},
               expect=(200, 201))
        rows2 = _items(c.get(f"{base}/timeline", expect=_SOFT), "timeline")
        mine2 = [r for r in rows2 if r.get("finding_id") == eid]
        got = mine2[0].get("status") if mine2 else None
        detail["status_after_validate"] = got
        ctx.check("triaging the event actually changes its status",
                  got == "not_real", expected="not_real", actual=got,
                  note="reversible triage is the whole feature; a status that "
                       "does not move means every judgement is lost on reload")

        # And it must be removable again.
        c.delete(f"{base}/timeline/event/{eid}", expect=(200, 202, 204))
        rows3 = _items(c.get(f"{base}/timeline", expect=_SOFT), "timeline")
        left = [r for r in rows3 if r.get("finding_id") == eid]
        detail["timeline_after_delete"] = len(rows3)
        ctx.check("deleting the manual event removes it from the timeline",
                  not left, expected="no matching row", actual=len(left),
                  note="a mistyped fact the analyst cannot delete ends up in "
                       "the customer's report")
        return detail

    # ------------------------------------------------------------------ 3 --
    # LAST, and destructive on purpose: it re-scopes the case.
    @runner.phase("case_zoom",
                  "Drill from the macro report into one phase, then re-scope back",
                  needs=("case_report",))
    def case_zoom(ctx):
        """THE macro-report drill-down: a zoom card carries a target's hosts and
        window, and applying it narrows the case to them and RE-FUSES.

        Two things are on test and only one of them is the zoom. The other is
        that a second fuse of a case that already holds a report does not 500 --
        the exact defect shipped in intact-20260903, which no phase reached
        through this door.
        """
        c, cid = ctx.get("client"), _case(ctx)
        if not cid:
            return {}
        base, detail = f"/api/cases/{cid}", {"case_id": cid}

        zt = c.get(f"{base}/zoom_targets", expect=_SOFT)
        targets = _items(zt, "targets")
        detail["altitude"] = (zt or {}).get("altitude")
        detail["targets"] = len(targets)
        if not targets:
            # Honest skip-shaped pass: at focused altitude there is nothing to
            # drill into, and saying so is better than inventing a window.
            ctx.check("the case offers zoom targets to drill into", True,
                      actual=f"none at altitude {detail['altitude']!r}",
                      note="a focused case is already at the bottom of the "
                           "ladder, so there is no macro card to click")
            return detail

        # Remember the scope so the case can be put back as it was found.
        case_before = c.get(base, expect=_SOFT) or {}
        acfg = case_before.get("analysis_config") or {}
        prev = {"time_window": acfg.get("time_window") or {},
                "excluded_hosts": acfg.get("excluded_hosts") or []}
        detail["scope_before"] = {"excluded": len(prev["excluded_hosts"])}

        t = targets[0]
        labels = t.get("host_labels") or []
        win = t.get("window") or {}
        ctx.check("the zoom card carries a real scope to apply",
                  bool(labels) and bool(win.get("start")) and bool(win.get("end")),
                  expected="host_labels + window.start + window.end",
                  actual={"hosts": len(labels), "window": bool(win.get("start"))},
                  note="the route rejects an incomplete scope with 400, so a "
                       "card missing either half is a dead button in the UI")
        if not (labels and win.get("start") and win.get("end")):
            return detail

        # THE RE-FUSE. expect=200 only: a 500 here is the shipped bug.
        res = c.post(f"{base}/zoom", {"host_labels": labels, "window": win},
                     expect=(200, 201, 202))
        detail["zoom_status"] = (res or {}).get("status")
        detail["scoped_to"] = len((res or {}).get("scoped_to") or [])
        ctx.check("applying a zoom re-fuses the case without erroring",
                  (res or {}).get("status") == "zoomed",
                  expected="zoomed", actual=res,
                  note="THE ASSERTION THIS PHASE EXISTS FOR. Re-fusing a case "
                       "that already has a report is what raised 500 in "
                       "intact-20260903; every door into that path needs one")

        after = c.get(base, expect=_SOFT) or {}
        cfg_after = after.get("analysis_config") or {}
        detail["excluded_after"] = len(cfg_after.get("excluded_hosts") or [])
        ctx.check("the zoom narrowed the case to the target's hosts",
                  detail["excluded_after"] >= len(prev["excluded_hosts"]),
                  expected="hosts outside the target excluded",
                  actual=f"{detail['excluded_after']} excluded "
                         f"(was {len(prev['excluded_hosts'])})",
                  note="a zoom that changes no scope re-rendered the same "
                       "report and told the analyst nothing new")

        # The report must still be readable at the new altitude -- a zoom that
        # leaves the case unrenderable has traded one view for none.
        rep = c.get(f"{base}/report", expect=_SOFT)
        md = (rep or {}).get("report_md") or (rep or {}).get("report") or ""
        detail["report_len_after_zoom"] = len(md)
        ctx.check("the case still renders a report after zooming",
                  len(md) > 500, expected=">500 chars", actual=len(md))

        # --- put it back ---------------------------------------------------
        # Also the only coverage of the plain Save on the config rail.
        saved = c.post(f"{base}/config", prev, expect=(200, 201))
        detail["restored"] = (saved or {}).get("status")
        ctx.check("the config rail saves the scope back without re-fusing",
                  (saved or {}).get("status") == "saved", actual=saved,
                  note="Save is a separate route from Rescan on purpose; it "
                       "persists settings and must NOT trigger a fuse")
        return detail
