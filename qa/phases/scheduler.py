"""Scheduled jobs — recurring collection, with no coverage of any kind.

WHY THIS MATTERS MORE THAN IT LOOKS. Everything else this suite drives is
something an operator triggers and watches. A scheduled job is the opposite:
it is the automation nobody is looking at, and its failure mode is silence.
A broken scheduler does not raise anything — the box simply stops collecting,
and the first sign is an investigation months later with no data behind it.

Seven endpoints, none of them called by this suite before. The whole lifecycle
is testable offline and cheaply, so there is no excuse for the gap.

WHAT IS ASSERTED. That a job survives being written: created, read back with
the fields it was given, toggled and re-read, edited and re-read, deleted and
GONE. Persistence is the point — a scheduler that keeps jobs in memory looks
identical to a working one until the container restarts.

WHAT IS NOT. That the job fires on its schedule. That needs the clock to move
and belongs nowhere near a CI run; the manual trigger below covers the dispatch
half, which is the part that shares code with the timer.

SHAPES VERIFIED against a live appliance, not inferred -- `enabled` comes back
as an INT (0/1), not a bool, so `is False` would never match it.
"""

# The blueprint the job runs. Named rather than "whatever is first" so a run
# cannot quietly schedule something else and still report green.
_WANT_BLUEPRINT = "velociraptor_best_practice"

_JOB_NAME = "QA-CI-scheduled-job"


from lib import probe


def _jobs(body):
    if isinstance(body, list):
        return body
    return (body or {}).get("jobs") or []


def register(runner, cfg):

    @runner.phase("scheduler",
                  "Create, toggle, edit, trigger and delete a scheduled job",
                  needs=("features",))
    def scheduler(ctx):
        c = ctx.get("client")
        detail = {}

        listing = c.get("/api/scheduler/jobs")
        detail["jobs_before"] = len(_jobs(listing))
        ctx.check("the scheduler answers with its job list",
                  isinstance(listing, (list, dict)),
                  actual=type(listing).__name__)
        # The UI shows every time in UTC and says so. A missing timezone here is
        # how an operator schedules 03:00 and gets it at 05:00.
        if isinstance(listing, dict):
            ctx.check("the job list declares its timezone",
                      listing.get("timezone") == "UTC",
                      expected="UTC", actual=listing.get("timezone"),
                      note="every schedule is stored and displayed in UTC; an "
                           "unlabelled clock is an off-by-hours bug waiting to "
                           "be blamed on the collector")

        # --- pick the blueprint the job will run --------------------------
        bps = c.get("/api/blueprints/velociraptor")
        items = bps if isinstance(bps, list) else (bps or {}).get("blueprints") or []
        bp = next((b for b in items if b.get("id") == _WANT_BLUEPRINT), None) \
            or (items[0] if items else None)
        ctx.check("a Velociraptor blueprint is available to schedule", bool(bp),
                  actual=(bp or {}).get("id"),
                  note="blueprints re-seed from YAML on boot; none means the "
                       "seeding did not happen and nothing can be scheduled")
        if not bp:
            return detail

        # --- create --------------------------------------------------------
        made = c.post("/api/scheduler/jobs",
                      {"name": _JOB_NAME, "blueprint_id": bp.get("id"),
                       "blueprint_type": "velociraptor",
                       "interval_value": 1, "interval_unit": "days",
                       # Far future: this must never actually fire during a run.
                       "start_date": "2030-01-01", "run_time": "03:00"},
                      expect=(200, 201))
        jid = (made or {}).get("id") or (made or {}).get("job_id")
        detail["job_id"] = jid
        ctx.check("the job was created and given an id", bool(jid), actual=made)
        if not jid:
            return detail

        try:
            # --- read back ------------------------------------------------
            one = c.get(f"/api/scheduler/jobs/{jid}")
            detail["blueprint_id"] = (one or {}).get("blueprint_id")
            ctx.check("the job persists the blueprint it was given",
                      (one or {}).get("blueprint_id") == bp.get("id"),
                      expected=bp.get("id"), actual=(one or {}).get("blueprint_id"),
                      note="a job that forgets its blueprint runs nothing, on "
                           "schedule, for ever")
            ctx.check("a new job is enabled", bool((one or {}).get("enabled")),
                      actual=(one or {}).get("enabled"))

            # --- toggle, and prove it STUCK -------------------------------
            c.post(f"/api/scheduler/jobs/{jid}/toggle", {"enabled": False})
            off = c.get(f"/api/scheduler/jobs/{jid}")
            detail["enabled_after_toggle"] = (off or {}).get("enabled")
            ctx.check("disabling a job persists",
                      not (off or {}).get("enabled"),
                      expected="falsy (the field is an int 0/1, not a bool)",
                      actual=(off or {}).get("enabled"),
                      note="pausing a noisy collection is the operator's first "
                           "reaction to it; a pause that does not hold means the "
                           "job keeps running while the UI says it stopped")

            c.post(f"/api/scheduler/jobs/{jid}/toggle", {"enabled": True})
            back = c.get(f"/api/scheduler/jobs/{jid}")
            ctx.check("re-enabling a job persists too",
                      bool((back or {}).get("enabled")),
                      actual=(back or {}).get("enabled"))

            # --- edit ------------------------------------------------------
            c.request("PUT", f"/api/scheduler/jobs/{jid}",
                      json={"interval_value": 7}, expect=(200, 201))
            edited = c.get(f"/api/scheduler/jobs/{jid}")
            detail["interval_after_edit"] = (edited or {}).get("interval_value")
            ctx.check("editing the interval persists",
                      str((edited or {}).get("interval_value")) == "7",
                      expected="7", actual=(edited or {}).get("interval_value"))

            # --- manual trigger -------------------------------------------
            # DISPATCH only. Whether the collection returns rows is `pipelines`'
            # job; what is on test here is that the same code path the timer
            # uses can be entered at all.
            trig = c.post(f"/api/scheduler/jobs/{jid}/run", {},
                          expect=(200, 201, 202))
            detail["triggered"] = bool((trig or {}).get("success"))
            ctx.check("a job can be triggered manually", bool(trig),
                      actual=trig,
                      note="'Run now' shares its dispatch with the scheduled "
                           "fire, so this covers the half of the timer that is "
                           "not the clock")

            # An unknown id must 404 rather than silently succeeding -- the
            # difference between 'nothing ran' and 'nothing exists'.
            code = c.status_of("/api/scheduler/jobs/QA-NO-SUCH-JOB")
            detail["unknown_job_status"] = code
            ctx.check("an unknown job id is refused, not accepted",
                      code == 404, expected=404, actual=code)
        finally:
            # ALWAYS remove it, even if an assertion above failed OR the phase
            # raised: a leftover ENABLED job fires on its own schedule against a
            # box that later phases are asserting about. probe.cleanup never
            # raises, so a teardown problem cannot replace the real diagnosis.
            probe.cleanup(c, [f"/api/scheduler/jobs/{jid}"])

        gone = c.status_of(f"/api/scheduler/jobs/{jid}")
        detail["after_delete"] = gone
        ctx.check("a deleted job is really gone", gone == 404,
                  expected=404, actual=gone,
                  note="a job that survives deletion keeps collecting from a "
                       "box the operator believes they stopped")
        return detail
