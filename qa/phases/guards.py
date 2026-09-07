"""The guards this product added AFTER something went wrong, none of them tested.

WHY THIS EXISTS. Reading the backend, a pattern repeats: a validator with a
comment explaining the incident that caused it. `services/vql_safety.py` exists
because a 2026-06-09 review found confirmed RCE through `client_id`,
`target_users`/`target_ips` and a hunt name. `_validate_logo_data_url` exists
because `file:///etc/passwd` was accepted as a report logo and then FETCHED by
the PDF renderer. `attach()` gained a case-existence check because a typo'd id
silently tagged runs to a phantom case, which the comment calls "an
evidence-contamination risk".

Every one of those is a guard on a path that was exploitable. None of them had a
test — not a unit test, not an e2e check. `features.py` asserts exactly two
injection rejections; this covers the rest.

A GUARD IS NOT TESTED BY ASSERTING IT REJECTS. A validator that refuses
everything passes a rejection-only test and breaks the product. So the logo
check below asserts a VALID logo is still accepted, and the ids that should be
refused are paired against shapes that must not be.

WHAT IS DELIBERATELY NOT EXERCISED: the masked-API-key round trip. The guard is
real — `_provider_block` keeps the stored secret when the operator saves a form
carrying the mask, because "writing the bullets through would silently destroy a
working key" — but reaching it means PUTting the LLM config, and that route
RESTARTS the Timesketch containers as a workflow. Restarting a module mid-run to
test a string comparison is not a trade worth making. Recorded below instead.

Every payload and status here was probed against a live backend first.
"""

from lib import probe

# The logo is interpolated into an <img src> in the generated PDF. Each of these
# was storable before the guard; the renderer then fetched it.
_BAD_LOGOS = (
    ("a local file URL", "file:///etc/passwd"),
    ("a link-local metadata URL", "http://169.254.169.254/latest/meta-data/"),
    ("an SVG data URL", "data:image/svg+xml;base64,PHN2Zz48L3N2Zz4="),
    ("a bare string", "not-a-data-url"),
)

# A 1x1 PNG. The point of including it: a validator that rejects everything
# passes a rejection-only test and ships a product that cannot brand a report.
_GOOD_LOGO = ("data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFc"
              "SJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==")

# (label, method, path, body) — each must be REFUSED with 400. The values are
# the shapes vql_safety was written to stop: a quote that closes a VQL string, a
# statement separator, a path traversal.
#
# A REJECTION ON ITS OWN PROVES NOTHING: an endpoint that 400s on every request
# — a missing required field, a client it cannot find — passes a rejection-only
# test while validating nothing. _CLEAN below pairs two of these with a
# well-formed payload that must get a DIFFERENT answer, which is what makes the
# 400 attributable to the validator. Measured on a live box: the clean
# equivalents answer 500 and 404 respectively, the injections 400.
_INJECTION = (
    ("a client id carrying VQL", "POST", "/api/velociraptor/timesketch",
     {"client_id": 'C.x"); --', "kape_target": "KapeFiles"}),
    ("an artifact name carrying a separator", "POST", "/api/velociraptor/timesketch",
     {"client_id": "C.0123456789abcdef", "kape_target": "a;b"}),
    ("a client id carrying a shell command", "POST", "/api/timesketch/import",
     {"client_id": "C.'; id; #", "flow_id": "F.ABC"}),
    ("a flow id carrying SQL", "POST", "/api/timesketch/import",
     {"client_id": "C.0123456789abcdef", "flow_id": "F.x' OR 1=1--"}),
    ("an adopted id that is a path traversal", "POST", "/api/velociraptor/adopt",
     {"id": "../../etc/passwd"}),
    ("an adopted id carrying VQL", "POST", "/api/velociraptor/adopt",
     {"id": "F.x'); DROP--"}),
    ("a scheduled job's client id carrying VQL", "POST", "/api/scheduler/jobs",
     {"name": "QA-CI-injection-probe", "blueprint_id": "velociraptor_best_practice",
      "blueprint_type": "velociraptor", "interval_value": 1,
      "interval_unit": "days", "client_ids": ['C.x"); --']}),
)


# (label, path, well-formed body, why it is safe to send). Only endpoints with
# NO side effect on a well-formed request. /api/velociraptor/adopt is
# deliberately absent: a valid-looking id is ACCEPTED with 202 and starts an
# adoption run, so pairing it would have this phase create work on the box to
# prove a point about a 400.
_CLEAN = (
    ("a well-formed client id", "/api/velociraptor/timesketch",
     {"client_id": "C.0123456789abcdef", "kape_target": "KapeFiles"}),
    ("a well-formed flow id", "/api/timesketch/import",
     {"client_id": "C.0123456789abcdef", "flow_id": "F.ABCDEFGH"}),
)


def register(runner, cfg):

    @runner.phase("guards",
                  "Every validator added after an incident still refuses",
                  needs=("features",))
    def guards(ctx):
        c = ctx.get("client")
        detail = {"refused": [], "accepted": []}

        # A case of this phase's own: the branding checks WRITE, and the fused
        # case is a deliverable other phases assert on.
        made = c.post("/api/cases", {"name": "QA-CI-guards",
                                     "min_severity": "informational"},
                      expect=(200, 201))
        cid = (made or {}).get("case_id") or (made or {}).get("id")
        ctx.check("a scratch case is available", bool(cid), actual=made)
        if not cid:
            return detail

        try:
            base = f"/api/cases/{cid}"

            # ------------------------------------------------------ 1 ----
            # THE ONE WITH A REAL EXPLOIT PATH. Unvalidated, the value was
            # stored and then fetched by the PDF renderer.
            for label, value in _BAD_LOGOS:
                code = _status(c, "POST", f"{base}/branding",
                               {"customer_logo_b64": value})
                detail["refused"].append(f"logo/{label}={code}")
                ctx.check(f"a report logo that is {label} is refused",
                          code == 400, expected=400, actual=code,
                          note="the logo is interpolated into an <img src> in "
                               "the generated PDF; a non-data URL here was "
                               "stored and then fetched when the report "
                               "rendered — server-side request forgery through "
                               "a branding field")

            code = _status(c, "POST", f"{base}/branding",
                           {"customer_logo_b64": _GOOD_LOGO})
            detail["accepted"].append(f"valid png={code}")
            ctx.check("a real embedded PNG logo is still accepted",
                      code in (200, 201), expected=200, actual=code,
                      note="THE OTHER HALF. A validator that refuses everything "
                           "passes every rejection test and ships a product "
                           "that cannot brand a report")

            # ------------------------------------------------------ 2 ----
            code = _status(c, "POST", "/api/cases/QA-NO-SUCH-CASE/attach",
                           {"run_ids": ["whatever"]})
            detail["refused"].append(f"attach/phantom={code}")
            ctx.check("attaching runs to a case that does not exist is refused",
                      code == 404, expected=404, actual=code,
                      note="store.attach_runs() does not raise on a bogus id, "
                           "so before this guard a typo'd case id silently "
                           "tagged runs to a phantom case — they vanished from "
                           "every real case with no error")

            # ------------------------------------------------------ 3 ----
            # vql_safety exists because a review found confirmed RCE through
            # these fields. features.py covers two of them; these are the rest.
            for label, method, path, body in _INJECTION:
                code = _status(c, method, path, body)
                detail["refused"].append(f"{path}={code}")
                ctx.check(f"{label} is refused", code == 400,
                          expected=400, actual=code,
                          note="these values reach VQL, a shell command line or "
                               "a filesystem path; the validation has to happen "
                               "at the route, before anything else runs")

            # THE COUNTERWEIGHT. Same endpoints, well-formed values: the
            # answer must NOT be 400, or the rejections above are just an
            # endpoint that refuses everything.
            for label, path, body in _CLEAN:
                code = _status(c, "POST", path, body)
                detail["accepted"].append(f"{path}={code}")
                ctx.check(f"{label} is not refused by the same validator",
                          code != 400, expected="anything but 400", actual=code,
                          note="if this is also 400 then the injection checks "
                               "above pass on an endpoint that rejects every "
                               "request, and they assert nothing")

            # ------------------------------------------------------ 4 ----
            code = _status(c, "PUT", "/api/timesketch/config/llm",
                           {"llm_mode": "definitely-not-a-provider"})
            detail["refused"].append(f"llm_provider={code}")
            ctx.check("an unknown LLM provider is refused, not defaulted",
                      code == 400, expected=400, actual=code,
                      note="llm_mode decides what is written into a file "
                           "Timesketch IMPORTS AS CODE, so guessing here "
                           "configures a provider the operator did not ask for")

            # Secrets must never come back in the clear. Asserted only when one
            # is actually set — on a box with no key configured every field is
            # empty and a mask check would pass by having nothing to mask.
            cfgbody = c.get("/api/timesketch/config/llm", expect=probe.SOFT) or {}
            secretish = {k: v for k, v in cfgbody.items()
                         if isinstance(v, str) and v
                         and ("key" in k.lower() or "secret" in k.lower())}
            detail["llm_secret_fields_set"] = sorted(secretish)
            if secretish:
                unmasked = [k for k, v in secretish.items() if "•" not in v]
                ctx.check("configured LLM secrets are masked when read back",
                          not unmasked, expected="every secret masked",
                          actual=", ".join(unmasked) or "all masked",
                          note="this endpoint is read by the settings UI; an "
                               "unmasked key is a key on screen and in any HAR "
                               "an operator attaches to a ticket")
            else:
                ctx.check("no LLM secret is configured, so none can leak", True,
                          actual="no secret fields set on this box",
                          note="the mask check is skipped rather than passed "
                               "vacuously — CI configures no model")
        finally:
            probe.cleanup(c, [f"/api/cases/{cid}"])

        detail["recorded"] = {
            "velociraptor_timesketch_500": (
                "POST /api/velociraptor/timesketch answers 500 — not 4xx — for a "
                "well-formed request naming a client that does not exist. "
                "Observed while establishing the counterweight above. Recorded, "
                "not asserted: the shape under test here is the validator, and "
                "an unhandled lookup failure is a separate product decision."),
            "masked_key_round_trip": (
                "NOT EXERCISED. _provider_block keeps the stored secret when a "
                "saved form carries the mask — 'writing the bullets through "
                "would silently destroy a working key' — but reaching it means "
                "PUTting the LLM config, and that route restarts the Timesketch "
                "containers as a workflow. Restarting a module mid-run to test "
                "a string comparison is not a trade worth making."),
        }
        return detail


def _status(c, method, path, body):
    """The status code, whatever it is.

    Driven through the session rather than `Client.request`, the way
    features.py's anonymous sweep does: `request` RAISES on anything outside
    `expect`, and here the status IS the assertion — encoding the expected
    answer in the call would mean the check could only ever agree with it.
    """
    try:
        return c.s.request(method, c.base + path, json=body,
                           timeout=60).status_code
    except Exception:                                         # noqa: BLE001
        return None
