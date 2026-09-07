"""Small helpers that keep a phase honest when something goes wrong.

TWO PROBLEMS THIS SOLVES, both learned from writing the phases that use it.

1. AN EXCEPTION IS A WORSE OUTCOME THAN A FAILED CHECK. `runner._run_phase`
   catches anything a phase raises, records the traceback and marks the phase
   ERROR — which is correct, but it means every assertion AFTER the raise never
   runs, and the report says "something threw" rather than "this specific thing
   is broken". `attempt()` turns an unexpected failure into a named, failed
   check and lets the phase carry on making its other assertions.

   That matters most for the checks that are only reachable late in a phase: a
   transport blip while fetching one asset should not cost the eight assertions
   that follow it.

2. AN EXCEPTION SKIPS CLEANUP. A phase that creates a scheduled job, a custom
   blueprint or a case and then fails partway leaves it on the box — and the
   next phase is now running against state the suite invented. A leftover
   ENABLED job is the worst of them: it fires on its own schedule against a box
   that later phases are asserting about. `cleanup()` never raises, so it is
   safe to call from a `finally` no matter what went wrong above it.

Neither helper hides a failure. `attempt` records one; `cleanup` is deliberately
silent because a failed teardown of something the suite created is noise, not a
product finding — and the phase has already reported whatever really went wrong.
"""

# Endpoints that legitimately answer 404 when the thing does not exist yet.
# `Client.request` raises on an unexpected status, so a bare get() would fail a
# phase for an empty list rather than for a broken one.
SOFT = (200, 201, 202, 404)

# What a DELETE may answer for something that is already gone.
GONE = (200, 202, 204, 404, 409)


def attempt(ctx, what, fn, *, note=None, default=None, expected=None):
    """Run `fn()`. On any exception, fail a check named `what` and return
    `default` so the phase can keep going.

    Use it for the calls where a failure is INFORMATIVE but not fatal to the
    rest of the phase. Do not wrap the call whose result everything else needs —
    there, an early return with a clear check is better than limping on.
    """
    try:
        return fn()
    except Exception as exc:                                  # noqa: BLE001
        ctx.check(what, False,
                  expected=expected or "the call to succeed",
                  actual=f"{type(exc).__name__}: {str(exc)[:180]}",
                  note=note)
        return default


def cleanup(c, paths, *, method="DELETE"):
    """Best-effort teardown. Never raises, never asserts.

    `paths` may contain None so a caller can write
    `cleanup(c, [job and f"/api/scheduler/jobs/{job}", ...])` without guarding
    each entry — the whole point is that this is safe to call from a `finally`
    on any failure path, including one where the ids were never assigned.

    Returns the paths it believes it removed, for the phase detail.
    """
    done = []
    for path in paths or ():
        if not path:
            continue
        try:
            c.request(method, path, expect=GONE)
            done.append(path)
        except Exception:                                     # noqa: BLE001
            # A teardown that fails is not a product finding: the phase has
            # already reported the real problem, and raising here would replace
            # that diagnosis with a misleading one.
            pass
    return done
