"""Restart survival — the one thing no phase in this suite has ever done.

WHY THIS EXISTS. Every phase here writes state and reads it back **in the same
process**. That proves the API stores things; it proves nothing about whether
they were stored anywhere that outlives the container. A module-level dict and a
database table are indistinguishable over HTTP until something restarts.

Three phases already say so in their own headers and none of them acts on it:

  * `scheduler.py:12` — "a scheduler that keeps jobs in memory looks identical
    to a working one until the container restarts"
  * `blueprints.py:17` — defaults re-seed on boot, so an edit can be silently
    discarded
  * `pipelines.py:145` — behaviour that "survives exactly until the next restart"

This phase restarts `intact_backend` in the middle of a run and re-reads
everything the operator would expect to still be there.

TWO KINDS OF CHECK, and the distinction is the whole design.

  POSITIVE CONTROLS — state the product genuinely persists (SQLite at
  /app/data/intact.db, the SQLAlchemy jobstore at /app/data/scheduler_jobs.db,
  the fusion sidecars at /app/data/fusion_graphs/). These are asserted. A
  regression that moves any of them into memory fails here and nowhere else.

  RECORDED DIVERGENCES — state the product does NOT persist today. These are
  measured and written into the phase detail rather than asserted, so the board
  stays honest without going red against unchanged product code. They are listed
  explicitly below so they cannot be forgotten, and each becomes an assertion the
  day the product changes.

THE SESSION CHECK IS NOT INCIDENTAL. The session cookie is signed with
`auth_session_key` out of the `secrets` table. If a restart regenerated that key
every operator on the box would be silently logged out. Nothing tested it.

DISRUPTIVE BY DESIGN, so placement matters: registered after the phases that
create state and before `maintenance`, which deletes it all anyway. The phase
fails loudly rather than continuing against a half-started backend, because
every phase after it would then fail for the wrong reason.
"""

import time

from lib import probe, shell

BACKEND = "intact_backend"

# A backend recreate is measured at well under a minute; this is the ceiling
# before the phase gives up, matching platform.py::backend_under_test.
HEALTH_TIMEOUT_S = 300

_SOFT = (200, 201, 202, 404)

_RULE = """title: QA CI restart-survival rule
id: 6f1c0d2e-0000-4000-8000-qa0000000002
status: experimental
description: written before a restart, must still be listed after one
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventName: QaCiRestartNeverHappens
    condition: selection
level: low
"""


def _items(body, key):
    if isinstance(body, list):
        return body
    if isinstance(body, dict) and isinstance(body.get(key), list):
        return body[key]
    return []


def _case_ids(c):
    body = c.get("/api/cases", expect=_SOFT)
    rows = body if isinstance(body, list) else (body or {}).get("cases") or []
    return sorted(str(r.get("id") or r.get("case_id")) for r in rows
                  if isinstance(r, dict))


def _graph_counts(c, cid):
    """Entity and finding counts out of the fused graph sidecar."""
    g = (c.get(f"/api/cases/{cid}/graph", expect=_SOFT) or {}).get("fusion_graph") or {}
    ents = g.get("entities")
    n_ents = len(ents) if isinstance(ents, (dict, list)) else 0
    return {"entities": n_ents, "findings": len(_items(g, "findings"))}


def register(runner, cfg):
    tl = runner.ctx.tl

    @runner.phase("restart_survival",
                  "Restart the backend and prove the box did not forget",
                  needs=("case_mutations",))
    def restart_survival(ctx):
        c = ctx.get("client")
        cid = ctx.get("fused_case_id")
        detail = {"case_id": cid}

        # ---------------------------------------------------------- 1 ----
        # Write state that MUST survive, in three different stores.
        bps = c.get("/api/blueprints/velociraptor")
        items = bps if isinstance(bps, list) else (bps or {}).get("blueprints") or []
        bp = next((b for b in items if b.get("id") == "velociraptor_best_practice"),
                  items[0] if items else None)
        ctx.check("a blueprint is available to schedule against", bool(bp),
                  actual=(bp or {}).get("id"))
        if not bp:
            return detail

        try:
            return _run(ctx, c, cid, bp, detail)
        finally:
            # ALWAYS, on every path including an exception. A leftover ENABLED
            # scheduled job fires on its own schedule against a box that later
            # phases are asserting about; a leftover blueprint changes the
            # counts `blueprints` checks.
            detail["torn_down"] = probe.cleanup(c, [
                detail.get("wrote", {}).get("job")
                and f"/api/scheduler/jobs/{detail['wrote']['job']}",
                detail.get("wrote", {}).get("blueprint")
                and f"/api/blueprints/velociraptor/{detail['wrote']['blueprint']}",
                f"/api/aws/rules/custom/{detail.get('wrote', {}).get('rule')}"
                if detail.get("wrote", {}).get("rule") else None,
                detail.get("aws_run") and f"/api/aws/runs/{detail['aws_run']}",
            ])

    def _run(ctx, c, cid, bp, detail):
        """The body, so the caller's `finally` owns teardown on every path."""
        job = c.post("/api/scheduler/jobs",
                     {"name": "QA-CI-restart-survival", "blueprint_id": bp.get("id"),
                      "blueprint_type": "velociraptor", "interval_value": 1,
                      "interval_unit": "days", "start_date": "2030-01-01",
                      "run_time": "04:00"}, expect=(200, 201))
        job_id = (job or {}).get("id") or (job or {}).get("job_id")

        made = c.post("/api/blueprints/velociraptor",
                      {"name": "QA CI restart blueprint",
                       "description": "written before a restart",
                       "artifacts": ["Generic.Client.Info"]}, expect=(200, 201))
        bp_id = ((made or {}).get("blueprint") or made or {}).get("id")

        rule_name = "qa_ci_restart_rule.yml"
        c.post("/api/aws/rules/custom", {"filename": rule_name, "content": _RULE},
               expect=(200, 201))

        detail["wrote"] = {"job": job_id, "blueprint": bp_id, "rule": rule_name}
        ctx.check("the pre-restart state was written",
                  bool(job_id) and bool(bp_id),
                  actual=detail["wrote"],
                  note="without this there is nothing to lose and the phase "
                       "would pass by having tested nothing")

        # ---------------------------------------------------------- 2 ----
        # Snapshot everything else the operator would expect to keep.
        before = {
            "cases": _case_ids(c),
            "jobs": len(_items(c.get("/api/scheduler/jobs"), "jobs")),
            # NOT /api/dashboard/automations: that list is filtered to the
            # active workspace by the X-Case-Id header, so an API client that
            # sends no header reads 0 and the comparison below is vacuous.
            # Measured on a live box: automations=0, members=2.
            "members": 0,
        }
        if cid:
            before["members"] = len(_items(
                c.get(f"/api/cases/{cid}/members", expect=_SOFT), "members"))
            before["graph"] = _graph_counts(c, cid)
            before["dispositions"] = len(_items(
                c.get(f"/api/cases/{cid}/dispositions", expect=_SOFT), "dispositions"))
            before["timeline"] = len(_items(
                c.get(f"/api/cases/{cid}/timeline", expect=_SOFT), "timeline"))
        detail["before"] = before

        # A cloud run: AWS persists to PERSIST_DIR, so this is a positive
        # control for the cloud module specifically.
        aws_run = None
        try:
            import json as _json
            rec = {"Records": [{"eventTime": "2026-01-15T10:00:00Z",
                                "eventSource": "cloudtrail.amazonaws.com",
                                "eventName": "StopLogging", "awsRegion": "us-east-1",
                                "eventID": "restart-probe",
                                "recipientAccountId": "123456789012"}]}
            up = c.request("POST", "/api/aws/upload",
                           files={"files": ("cloudtrail.json", _json.dumps(rec),
                                            "application/json")},
                           expect=(200, 201))
            aws_run = (up or {}).get("run_id")
            if aws_run:
                # It must be ANALYSED, not merely uploaded. Measured: the
                # persist-to-disk in aws_routes' run_offline() happens at the
                # END of the analysis thread, so an uploaded-but-unanalysed run
                # exists only in the _aws_runs dict and IS lost on restart.
                # Asserting on an upload-only run made this positive control
                # fail against a product that is behaving correctly.
                c.post("/api/aws/analyze-offline",
                       {"run_id": aws_run, "min_severity": "informational"},
                       expect=(200, 202))
                stop = time.time() + 180
                while time.time() < stop:
                    st = c.get(f"/api/aws/status/{aws_run}", expect=_SOFT) or {}
                    if st.get("status") in ("complete", "completed", "failed", "error"):
                        break
                    time.sleep(3)
        except Exception as exc:                                  # noqa: BLE001
            detail["aws_upload_error"] = str(exc)[:120]
        detail["aws_run"] = aws_run

        # ---------------------------------------------------------- 3 ----
        t0 = time.time()
        r = shell.docker(["restart", BACKEND], timeout=300)
        ctx.check("the backend container restarted", r.ok,
                  actual=(r.out or "").strip()[-160:] or "restarted")
        if not r.ok:
            return detail

        deadline, healthy = time.time() + HEALTH_TIMEOUT_S, False
        while time.time() < deadline:
            ok, _why = shell.container_is_ok(BACKEND)
            if ok:
                try:
                    if c.get("/api/health", expect=(200,)):
                        healthy = True
                        break
                except Exception:                                 # noqa: BLE001
                    pass
            time.sleep(3)
        detail["restart_seconds"] = round(time.time() - t0, 1)
        # LOUD, because every phase after this one would otherwise fail for the
        # wrong reason and the run would read as a product collapse.
        ctx.check("the backend came back healthy", healthy,
                  expected=f"/api/health within {HEALTH_TIMEOUT_S}s",
                  actual=f"{detail['restart_seconds']}s elapsed, healthy={healthy}",
                  note="a backend that does not come back invalidates every "
                       "later phase; this failing is the phase telling you to "
                       "stop reading the rest of the run")
        if not healthy:
            return detail

        # ---------------------------------------------------------- 4 ----
        # THE SESSION. Same cookie, no re-login. If auth_session_key were
        # regenerated on boot every operator would be logged out by a restart.
        try:
            cases_after = _case_ids(c)
            session_ok = True
        except Exception as exc:                                  # noqa: BLE001
            cases_after, session_ok = [], False
            detail["session_error"] = str(exc)[:160]
        ctx.check("the operator's session survived the restart", session_ok,
                  expected="the same cookie still authenticates",
                  actual=detail.get("session_error", "authenticated"),
                  note="the cookie is signed with auth_session_key from the "
                       "secrets table; regenerating it on boot would silently "
                       "log out every operator on the box")
        if not session_ok:
            return detail

        # ---------------------------------------------------------- 5 ----
        # Positive controls.
        after = {"cases": cases_after,
                 "jobs": len(_items(c.get("/api/scheduler/jobs"), "jobs")),
                 "members": len(_items(
                     c.get(f"/api/cases/{cid}/members", expect=_SOFT), "members"))
                 if cid else 0}
        detail["after"] = after

        ctx.check("every case survived the restart",
                  set(before["cases"]) <= set(cases_after),
                  expected=f"{len(before['cases'])} case(s) still present",
                  actual=f"{len(cases_after)} present",
                  note="cases live in /app/data/intact.db; losing one loses an "
                       "entire investigation")

        one = c.get(f"/api/scheduler/jobs/{job_id}", expect=_SOFT) if job_id else None
        ctx.check("the scheduled job survived the restart",
                  isinstance(one, dict) and one.get("id") == job_id,
                  expected=job_id, actual=(one or {}).get("id"),
                  note="THE ASSERTION THIS PHASE WAS BUILT FOR. Jobs live in a "
                       "SQLAlchemy jobstore and are restored by "
                       "restore_jobs_on_startup(); a scheduler that kept them in "
                       "memory would pass every other test in this suite")
        ctx.check("the restored job kept its blueprint",
                  (one or {}).get("blueprint_id") == bp.get("id"),
                  expected=bp.get("id"), actual=(one or {}).get("blueprint_id"),
                  note="a job restored without its blueprint runs nothing, on "
                       "schedule, for ever")

        got_bp = c.get(f"/api/blueprints/velociraptor/{bp_id}", expect=_SOFT) \
            if bp_id else None
        ctx.check("the custom blueprint survived the restart",
                  isinstance(got_bp, dict) and got_bp.get("id") == bp_id,
                  expected=bp_id, actual=(got_bp or {}).get("id"),
                  note="defaults re-seed from YAML on boot; an operator's own "
                       "blueprint has to survive that re-seed rather than be "
                       "swept away by it")

        rules = (c.get("/api/aws/rules/custom", expect=_SOFT) or {}).get("rules") or []
        ctx.check("the custom SIGMA rule survived the restart",
                  any(rule_name in str(x) for x in rules),
                  expected=rule_name, actual=rules,
                  note="detection content an operator added mid-engagement")

        if cid:
            g_after = _graph_counts(c, cid)
            detail["graph_after"] = g_after
            ctx.check("the fused graph survived the restart",
                      g_after["entities"] >= before["graph"]["entities"] > 0
                      and g_after["findings"] >= before["graph"]["findings"],
                      expected=before["graph"], actual=g_after,
                      note="the graph is a sidecar at /app/data/fusion_graphs/; "
                           "losing it means re-fusing every case from scratch")

            d_after = len(_items(c.get(f"/api/cases/{cid}/dispositions", expect=_SOFT),
                                 "dispositions"))
            detail["dispositions_after"] = d_after
            ctx.check("analyst triage survived the restart",
                      d_after >= before["dispositions"],
                      expected=f">={before['dispositions']}", actual=d_after,
                      note="a disposition the analyst has to redo after every "
                           "restart is a disposition they stop making")

            t_after = len(_items(c.get(f"/api/cases/{cid}/timeline", expect=_SOFT),
                                 "timeline"))
            ctx.check("the timeline survived the restart",
                      t_after >= before["timeline"],
                      expected=f">={before['timeline']}", actual=t_after)

        ctx.check("the case's member runs survived",
                  after["members"] >= before.get("members", 0) > 0,
                  expected=f">={before.get('members', 0)}", actual=after["members"],
                  note="also covers the tus upload-run recovery path: the "
                       "in-memory upload_id map is emptied by a restart and "
                       "_resolve_upload_run() has to recover from storage")

        # A case must not be left claiming a report is being generated by a
        # thread that died with the old process. The boot sweep in
        # case_routes.py clears it on the first request after start.
        stuck = []
        for case_id in cases_after:
            info = c.get(f"/api/cases/{case_id}", expect=_SOFT) or {}
            if (info.get("info") or info).get("report_generating"):
                stuck.append(case_id)
        detail["report_generating_stuck"] = stuck
        ctx.check("no case is stuck generating a report after the restart",
                  not stuck, actual=stuck or "none",
                  note="report_generating is a DURABLE flag guarded by a "
                       "PROCESS-LOCAL lock, so a backend that dies mid-"
                       "generation leaves it True with nothing left to clear "
                       "it; the boot sweep exists for exactly that")

        # ---------------------------------------------------------- 6 ----
        # RECORDED DIVERGENCES. Measured, written down, deliberately not
        # asserted — the product has not changed and the board stays honest.
        notes = {}
        if aws_run:
            code = c.status_of(f"/api/aws/status/{aws_run}")
            notes["aws_run_readable"] = code
            ctx.check("the AWS cloud run survived the restart", code == 200,
                      expected=200, actual=code,
                      note="AWS persists runs to PERSIST_DIR and reloads them "
                           "via _load_run(); this is the positive control the "
                           "Azure note below is measured against")

        az = c.status_of("/api/azure/upload")
        notes["azure_upload_gate"] = az
        notes["azure_persistence"] = (
            "NOT EXERCISED — Azure runs live only in the module-level _azure_runs "
            "dict (routes/azure_routes.py:40, 'would use a database in "
            "production'). There is no PERSIST_DIR and no _load_run(), so an "
            "Azure analysis does not survive a restart at all, unlike AWS. "
            "Recorded rather than asserted: fixing it is a product change.")
        notes["aws_upload_only_runs"] = (
            "An AWS run that was uploaded but never analysed does NOT survive a "
            "restart — the persist happens at the end of the analysis thread, so "
            "until then the run exists only in _aws_runs. Measured here, not "
            "assumed. The uploaded files stay on disk; the run record does not.")
        notes["support_bundle_persistence"] = (
            "NOT EXERCISED — BUNDLE_OUTPUT_DIR=/data/support_bundles is not in "
            "any compose volume, so a prepared-but-undownloaded bundle is lost "
            "on a recreate.")
        notes["cancellation"] = (
            "NOT EXERCISED — workflow_service._cancel_events is in memory, so a "
            "collection running across a restart becomes uncancellable.")
        detail["recorded_divergences"] = notes

        # Teardown is the caller's `finally` — see the top of this phase.
        return detail
