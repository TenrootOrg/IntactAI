"""The scheduler's UPDATE route must validate what CREATE validates.

`POST /api/scheduler/jobs` has run `validate_client_ids_list` since the Mythos
review, because a scheduled agentic job's client IDs end up interpolated into
VQL string literals by services/agentic/collectors/_base.py:

    client_id='{client_id}'
    WHERE client_id IN ('{"', '".join(client_ids)}')

`PUT /api/scheduler/jobs/<id>` validated only `interval_unit`. So a job created
with clean IDs could be EDITED to carry a quote-bearing value, which was stored
verbatim and fired as attacker-controlled VQL on the next tick — an edit, not a
create, was enough.

Two non-obvious cases are pinned here because both are easy to reintroduce:

  * a PUT that never mentions `client_ids` must not clear them.
    `validate_client_ids_list(None)` returns `([], None)` — a *successful*
    validation of an empty list — so validating unconditionally would let a
    partial edit (say, renaming the job) silently blank its target hosts.
  * a non-list `client_ids` must be rejected at the route. Downstream,
    services/scheduler/jobs.py only json.dumps() lists; anything else is
    written raw and then kills the firing when executor.py json.loads() it.

The route is driven with a bare Flask app so validation is exercised without a
scheduler, a database row, or a live Velociraptor. Every case here returns 400
before any storage call, so no job is created, modified, or read.

Run: docker exec intact_backend python3 /app/workdir/tests/test_scheduler_update_validation.py
"""

import sys

if "/app" not in sys.path:
    sys.path.insert(0, "/app")

from flask import Flask                                    # noqa: E402
import routes.scheduler_routes as SR                       # noqa: E402

_app = Flask(__name__)
_app.register_blueprint(SR.scheduler_bp)
_client = _app.test_client()

JOB = "/api/scheduler/jobs/job_test"

POISON = "C.aaa' OR 1=1 --"


def _put(body):
    r = _client.put(JOB, json=body)
    return r.status_code, (r.get_json() or {})


def _captured_put(body):
    """PUT with the store stubbed, returning what reached update_scheduled_job.

    Used for the cases that are SUPPOSED to pass validation — we need to see
    the payload rather than let it touch real storage.
    """
    seen = {}

    def _fake_update(job_id, data):
        seen["job_id"], seen["data"] = job_id, dict(data)
        return {"job_id": job_id, **data}

    orig = SR.update_scheduled_job
    SR.update_scheduled_job = _fake_update
    try:
        r = _client.put(JOB, json=body)
    finally:
        SR.update_scheduled_job = orig
    return r.status_code, seen


# ---------------------------------------------------------------------------


def test_quote_bearing_client_id_is_rejected():
    """The injection itself."""
    code, body = _put({"client_ids": [POISON]})
    assert code == 400, f"poisoned client_id accepted with HTTP {code}"
    assert "client_id" in body.get("error", "").lower(), body


def test_non_list_client_ids_is_rejected():
    """A string here is stored raw and later crashes executor.py's json.loads."""
    code, body = _put({"client_ids": "C.abc"})
    assert code == 400, f"non-list client_ids accepted with HTTP {code}"


def test_a_malformed_id_among_valid_ones_is_rejected():
    code, _ = _put({"client_ids": ["C.abc", POISON, "C.def"]})
    assert code == 400, "one bad id in a batch must reject the whole edit"


def test_zero_interval_value_is_rejected():
    code, body = _put({"interval_value": 0})
    assert code == 400, f"interval_value=0 accepted with HTTP {code}"
    assert "interval_value" in body.get("error", ""), body


def test_non_numeric_interval_value_is_rejected():
    code, _ = _put({"interval_value": "soon"})
    assert code == 400


def test_valid_client_ids_still_pass_through():
    code, seen = _captured_put({"client_ids": ["C.abc123", "C.deadbeef"]})
    assert code == 200, f"a legitimate edit was rejected with HTTP {code}"
    assert seen["data"]["client_ids"] == ["C.abc123", "C.deadbeef"], seen


def test_a_put_that_omits_client_ids_does_not_clear_them():
    """THE trap. validate_client_ids_list(None) returns ([], None) — a
    successful validation of an empty list — so validating unconditionally
    would blank the job's targets on any unrelated edit."""
    code, seen = _captured_put({"name": "renamed"})
    assert code == 200, code
    assert "client_ids" not in seen["data"], (
        f"an edit that never mentioned client_ids would have written "
        f"{seen['data'].get('client_ids')!r} over the job's target list")


def test_interval_unit_validation_still_works():
    """The one check the route already had — must survive the additions."""
    code, _ = _put({"interval_unit": "fortnights"})
    assert code == 400


if __name__ == "__main__":
    import traceback
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn(); print(f"PASS {fn.__name__}")
        except Exception:
            failed += 1; print(f"FAIL {fn.__name__}"); traceback.print_exc()
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    sys.exit(1 if failed else 0)
