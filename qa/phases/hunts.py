"""A Velociraptor HUNT, dispatched against the Linux client this run enrolled.

WHY THIS EXISTS. The suite covered `GET /api/velociraptor/hunts/status` answering
200 and nothing else — no hunt was ever dispatched. Collections were, and they
are a DIFFERENT path: a collection targets one client directly, while a hunt is
the fleet-wide mechanism the platform is shipped to use, and the existing
comment on the Windows `hunt` phase says the two behave differently ("the hunt
path live-pulls, while the agentic rescan path reads a stored raw_results.json").

There has always been a `hunt` phase — it just hangs off the Windows chain
(`needs=("kape_gate",)`) and picks a Windows blueprint, so on the Linux profile
CI actually runs it skips every time. This is the same dispatch against the
client the run does have, so the mechanism is exercised rather than documented.
"""

from lib import api as api_lib


def register(runner, cfg):
    tl = runner.ctx.tl

    @runner.phase("hunt_linux",
                  "Dispatch an agentic blueprint as a hunt against the Linux client",
                  needs=("pipelines",))
    def hunt_linux(ctx):
        c = ctx.get("client")
        # endpoint_linux stores it as `client_id`; on this profile it is the
        # only endpoint there is, so there is nothing to disambiguate from.
        client_id = ctx.get("client_id")
        ctx.check("a Linux client is enrolled to hunt", bool(client_id),
                  actual=client_id,
                  note="enrol_linux registers it; without one there is no fleet "
                       "to hunt across")
        if not client_id:
            return {}

        # The Linux blueprint the appliance ships. Named rather than "whatever
        # is first" so a run cannot quietly hunt with something else and still
        # report a green hunt.
        bp = _pick_linux_blueprint(c)
        ctx.check("the shipped Linux agentic blueprint is available", bool(bp),
                  actual=(bp or {}).get("name"),
                  note="agentic_linux_triage is seeded from YAML on boot")
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
        detail = {"blueprint": bp.get("name"), "run_id": run_id,
                  "client_id": client_id}
        ctx.check("the hunt was accepted", bool(run_id), actual=body)
        if not run_id:
            return detail
        tl.ids(hunt_linux_run_id=run_id)

        run = c.wait_for_run(run_id, cfg.timeout("blueprint_hunt", 30) * 60, tl,
                             what="the Linux agentic hunt")
        status = (run or {}).get("status")
        detail["status"] = status
        ctx.check("the hunt reached a terminal state", bool(run), actual=status,
                  note="no status means it never finished; the outcome is "
                       "unknown rather than good")
        ctx.check("the hunt succeeded", api_lib.run_succeeded(run),
                  expected="completed", actual=status)

        # A hunt that completes having collected nothing has exercised dispatch
        # and not collection. Say which happened.
        rows = _collected_rows(run)
        detail["rows"] = rows
        ctx.check("the hunt collected results from the client",
                  rows is None or rows > 0,
                  expected=">0 rows", actual=rows if rows is not None else "not reported",
                  note="dispatch and completion are separate from a hunt that "
                       "actually pulled something back")
        return detail


def _pick_linux_blueprint(c):
    """The shipped Linux agentic blueprint, by name where possible."""
    for path in ("/api/blueprints/agentic", "/api/blueprints/velociraptor"):
        try:
            body = c.get(path)
        except Exception:                                     # noqa: BLE001
            continue
        items = body if isinstance(body, list) else \
            (body or {}).get("blueprints") or []
        named = [b for b in items
                 if "linux" in str(b.get("name", "")).lower()
                 or "linux" in str(b.get("id", "")).lower()]
        if named:
            return named[0]
    return None


def _collected_rows(run):
    """Rows the hunt brought back, or None when the run does not report it."""
    if not isinstance(run, dict):
        return None
    for key in ("rows", "row_count", "results", "collected"):
        v = (run.get(key) if key in run
             else (run.get("details") or {}).get(key))
        if isinstance(v, int):
            return v
        if isinstance(v, list):
            return len(v)
    return None
