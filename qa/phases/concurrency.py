"""Two operators at once — a contract the product implements and nothing tested.

WHY THIS EXISTS. No phase in this suite has ever issued two requests at the same
time. Everything is strictly sequential, so every lock, every `busy` flag and
every 409 in the product is untested by construction. The upgrade engine's flock
is the sole exception, and even there the harness WAITS for the lock rather than
asserting the refusal.

Meanwhile `fuse_case`'s own docstring records, in the past tense, the two bugs
this phase guards:

  * "observed with two calls to the provider in flight for the same case at
    once, both billed, the loser's writes silently overwritten" — the reason the
    per-case lock exists at all.
  * rescan used to blank `report_md` BEFORE taking the lock, "so a FusionBusy
    raised here left the case with its report destroyed and nothing to rebuild
    it. The operator saw an error and lost the narrative."

The second is the one that matters most here, and it is why this phase asserts
the report SURVIVES the collision rather than merely that a 409 came back. A
product that returns a perfect 409 and eats the narrative on the way is worse
than one that returns 500.

THE COLLISION IS REAL, not simulated. Two threads with independent sessions fire
the same request simultaneously; the loser gets the refusal the product actually
produces. Measured on a live appliance: a re-fuse of a case that already has a
report takes ~0.6s, and the collision was observed on the first attempt.

WHY 409 AND NOT 500. The handler's docstring: "the request is well-formed, the
case is simply busy, and retrying will work. It used to fall through to the
generic handler, which returned 500 AND wrote 'crashed' into the case activity
log — so a perfectly normal collision read as a product fault." So the code is
asserted, not just the fact of a refusal.
"""

import threading

from lib import api as api_lib

# A fast box may serialise two requests without ever overlapping. Retry a few
# times before concluding the lock is not being exercised.
ATTEMPTS = 5


def register(runner, cfg):

    @runner.phase("concurrency",
                  "Fire two fuses at one case and prove the loser is refused",
                  needs=("case_report",))
    def concurrency(ctx):
        c, cid = ctx.get("client"), ctx.get("fused_case_id")
        detail = {"case_id": cid}
        if not cid:
            ctx.check("a fused case is available to contend over", False,
                      actual=cid)
            return detail

        # The report as it stands. This is the thing the collision must not
        # damage -- see the rescan bug in the module docstring.
        before = _report_len(c, cid)
        detail["report_before"] = before
        ctx.check("the case has a report to protect", before > 500,
                  expected=">500 chars", actual=before,
                  note="without one, 'the report survived' would pass by having "
                       "nothing to lose")

        # Independent sessions: requests.Session is not designed to be driven
        # from two threads at once, and a race in the CLIENT would be
        # indistinguishable from the server behaviour under test.
        two = []
        for _ in range(2):
            k = api_lib.Client(cfg.platform_host, tl=None, scheme="https")
            k.s.cookies.update(c.s.cookies)
            two.append(k)

        codes, bodies, attempts_used = [], [], 0
        for attempt in range(ATTEMPTS):
            attempts_used = attempt + 1
            out = {}

            def _fire(i):
                try:
                    r = two[i].s.post(f"{two[i].base}/api/cases/{cid}/fuse",
                                      json={}, timeout=900)
                    body = ""
                    try:
                        body = (r.json() or {}).get("error", "") or ""
                    except ValueError:
                        body = r.text[:80]
                    out[i] = (r.status_code, body)
                except Exception as exc:                      # noqa: BLE001
                    out[i] = (0, str(exc)[:80])

            threads = [threading.Thread(target=_fire, args=(i,)) for i in (0, 1)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            codes = sorted(v[0] for v in out.values())
            bodies = [v[1] for v in out.values() if v[1]]
            if 409 in codes:
                break

        detail["attempts"] = attempts_used
        detail["codes"] = codes
        ctx.check("a concurrent fuse is refused rather than run twice",
                  409 in codes,
                  expected="one 200 and one 409",
                  actual=f"{codes} after {attempts_used} attempt(s)",
                  note="the per-case lock is the only thing stopping two model "
                       "calls being billed for the same case with the loser's "
                       "writes silently overwritten. If this fails on a machine "
                       "too fast to overlap, widen the window — do not delete "
                       "the check")

        ctx.check("exactly one of the two fuses was allowed through",
                  codes.count(200) == 1,
                  expected="exactly one 200", actual=codes)

        # 409, specifically. The generic handler used to answer 500 here and
        # write "crashed" into the case activity log.
        # BOTH halves matter: no 5xx, AND both calls actually got an HTTP
        # answer. `not any(c >= 500)` alone passes on a transport error, where
        # the code is 0 and nothing was learned -- caught exactly that way while
        # writing this, when a misconfigured client never reached the server and
        # the check still went green.
        ctx.check("the collision is not reported as a server fault",
                  bool(codes) and all(200 <= c0 < 500 for c0 in codes),
                  expected="two real responses, neither 5xx", actual=codes,
                  note="a normal collision -- two operators triaging at once -- "
                       "must not read as a product fault; and a request that "
                       "never arrived must not read as one either")

        # And it has to say something an operator can act on.
        msg = " ".join(bodies)
        detail["refusal_message"] = msg[:160]
        if 409 in codes:
            ctx.check("the refusal explains itself", len(msg.strip()) > 20,
                      expected="a human-readable reason", actual=msg[:120] or "empty",
                      note="the operator needs to know it is busy and will "
                           "work on retry, not just that something returned 409")

        # ------------------------------------------------------------------
        # THE ASSERTION THE DOCSTRING'S SECOND BUG IS ABOUT.
        after = _report_len(c, cid)
        detail["report_after"] = after
        ctx.check("the report survived the collision", after >= before > 0,
                  expected=f">={before} chars", actual=after,
                  note="rescan used to blank report_md BEFORE taking the lock, "
                       "so a refusal destroyed the narrative and left nothing to "
                       "rebuild it. A perfect 409 that eats the report is worse "
                       "than a 500")

        # The graph must also still be readable — a half-applied fuse would show
        # up here rather than in the status codes.
        graph = c.get(f"/api/cases/{cid}/graph", expect=(200, 404)) or {}
        fg = graph.get("fusion_graph") or {}
        ents = fg.get("entities")
        detail["entities_after"] = len(ents) if isinstance(ents, (dict, list)) else 0
        ctx.check("the graph is intact after the collision",
                  detail["entities_after"] > 0,
                  expected=">0 entities", actual=detail["entities_after"])

        # ------------------------------------------------------------------
        # Recorded, not asserted.
        detail["recorded"] = {
            "report_generation_lock": (
                "ReportGenerationBusy guards the LLM narrative path and needs a "
                "configured model to reach, which CI deliberately has none of. "
                "Untested here. Note it is a PROCESS-LOCAL lock over a DURABLE "
                "flag, so a backend that dies mid-generation leaves the case "
                "reporting busy — see restart_survival, which asserts the boot "
                "sweep clears it."),
            "purge_has_no_guard": (
                "run_system_purge() and purge_selected_sections() both create a "
                "run and spawn a thread unconditionally — there is NO "
                "concurrency guard. Two simultaneous purges would both DELETE "
                "FROM workflows, both VACUUM the same SQLite file and both run "
                "`docker system prune -a --volumes -f`. Not exercised here "
                "because there is no refusal to assert and provoking it on a "
                "live box is not a test, it is an outage."),
        }
        return detail


def _report_len(c, cid):
    body = c.get(f"/api/cases/{cid}/report", expect=(200, 404)) or {}
    return len(body.get("report_md") or body.get("report") or "")
