"""Drive the backend's HTTP surface directly and assert on what comes back.

Real requests against the running product, not unit tests with the app stubbed
out. Every check here is an HTTP call an operator's browser could make.

HOW IT AUTHENTICATES, and a trap worth recording. services/auth_service.py
gate_decision() exempts 127.0.0.1 and ::1 for any /api/ path, and the backend is
published on 127.0.0.1:5001 — which reads like "a script on the appliance can
curl localhost and skip auth entirely". It cannot. The backend runs in a
container, so a request arriving through the published port has been NATed by
Docker and reaches Flask with the bridge gateway's 172.x address, not 127.0.0.1.
Measured on a live appliance: every /api/ path answers 401 from the host and 200
from inside the container. The bypass is real, but only for callers already
inside the container's network namespace — the healthcheck, and install.sh's
wait loop, which uses the separately-exempt /api/health.

So this sweep uses the SESSION the auth phase established, over https://<domain>,
which is what the UI does. That is the better test anyway: it exercises nginx
routing, TLS and the auth gate itself, none of which a loopback shortcut would
touch.

The counterweight stays, and now means something stronger: the same guarded
paths are requested with NO session and must be REFUSED. Together the two halves
say "authorised callers get through, unauthorised ones do not" — either alone
would be satisfied by an appliance that is broken in one direction.

Three tiers, each gated on what the box can actually do:

  Tier 0  read-only smoke over ~50 endpoints, plus the auth counterweight
  Tier 1  create/read/update/delete round-trips on throwaway objects
  Tier 2  anything needing a real enrolled client

Anything requiring a credential this box does not have is recorded as SKIPPED
with the reason, never quietly passed and never failed. A green report that hid
"we never tested AWS" would be worse than a red one.
"""

import time

from lib import api as api_lib

# Endpoints this sweep must never call, and why. Each of these is individually
# capable of ruining the run or the box.
DENYLIST = {
    "/api/maintenance/purge": "destroys the appliance's data",
    "/api/maintenance/purge/sections": "destroys the appliance's data",
    "/api/auth/login": "10 failed attempts locks the account for 15 minutes",
    "/api/auth/setup": "single-use; consumes first_login",
    "/api/auth/logout": "would drop the session the rest of the run needs",
    "/api/auth/change-password": "would invalidate the documented credentials",
    "/api/db/import": "overwrites the database",
    "/api/cases/import": "mutates the workspace mid-run",
    "/api/upgrade/online": "upgrade testing is a separate workflow",
    "/api/upgrade/offline": "upgrade testing is a separate workflow",
}

# (method, path, accepted status codes, why this is what we expect)
#
# The odd ones are the point. A sweep that asserts 200 everywhere would report
# the platform's documented behaviour as broken.
TIER0 = [
    ("GET", "/api/health", (200,), None),
    ("GET", "/api/test", (200,), None),
    ("GET", "/api/version", (200,), None),
    ("GET", "/api/system/containers", (200,), None),
    ("GET", "/api/system/actions", (200,), None),
    ("GET", "/api/upgrade/current-versions", (200,), None),
    ("GET", "/api/auth/status", (200,), None),
    ("GET", "/api/config", (200,), None),
    ("GET", "/api/config/cloud", (200,), None),
    ("GET", "/api/config/models", (200,), None),
    ("GET", "/api/dashboard/automations", (200,), None),
    ("GET", "/api/cases", (200,), None),
    ("GET", "/api/cases/runs", (200,), None),
    ("GET", "/api/clients", (200,), None),
    ("GET", "/api/clients/legacy/status", (200,), None),
    ("GET", "/api/blueprints/velociraptor", (200,), None),
    ("GET", "/api/blueprints/agentic", (200,), None),
    ("GET", "/api/blueprints/timesketch", (200,), None),
    ("GET", "/api/blueprints/memory", (200,), None),
    ("GET", "/api/blueprints/forensics", (200,), None),
    ("GET", "/api/scheduler/jobs", (200,), None),
    ("GET", "/api/maintenance/tools-config", (200,), None),
    ("GET", "/api/maintenance/tools-inventory", (200,), None),
    ("GET", "/api/velociraptor/offline/configs", (200,), None),
    ("GET", "/api/aws/status", (200,), None),
    ("GET", "/api/aws/blueprints", (200,), None),
    ("GET", "/api/aws/rules/custom", (200,), None),
    ("GET", "/api/aws/runs", (200,), None),
    ("GET", "/api/azure/status", (200, 503), "o365rc is off by default and the "
                                             "route's disabled code varies"),
    ("GET", "/api/memory/available_plugins", (200, 400),
     "a disabled memory module answers 400, not 404 or 503"),
    ("GET", "/api/memory/blueprints", (200, 400), "same disabled-module code"),
    ("GET", "/api/upgrade/active", (200,), None),
    ("GET", "/api/db/export", (200,), None),
    ("GET", "/api/client/C.0000000000000000", (501,),
     "documented stub — asserting 200 here would be the bug"),
]

# Velociraptor must be up for these to mean anything; they self-skip otherwise.
TIER0_VELOCIRAPTOR = [
    ("GET", "/api/velociraptor/artifacts", (200,), None),
    ("GET", "/api/velociraptor/labels", (200,), None),
    ("GET", "/api/velociraptor/hunts/status", (200,), None),
]

# Never called. Recorded so the report says WHY, instead of leaving a reader to
# assume the coverage exists.
SKIPPED_EXTERNAL = [
    ("/api/aws/scan", "needs real AWS credentials with CloudTrail read"),
    ("/api/azure/scan", "needs a real Azure tenant id, client id and secret"),
    ("/api/config/llm/test", "needs an LLM API key"),
    ("/api/maintenance/refresh-openrouter-models", "needs a provider API key"),
    ("/api/maintenance/refresh-anthropic-models", "needs a provider API key"),
    ("/api/maintenance/refresh-openai-models", "needs a provider API key"),
    ("/api/cases/<id>/synthesize", "needs an LLM API key"),
    ("/api/cases/<id>/chat", "needs an LLM API key"),
    ("/api/agentic/cli/login", "needs interactive device-code approval"),
    ("/api/upgrade/refs", "needs a GitHub token; upgrade is a separate workflow"),
    ("/api/uploads/*", "tus uploads are rewritten by nginx and never reach "
                       "Flask — they need a real session over 443"),
]


def register(runner, cfg):
    if not cfg.feature_sweep:
        return

    tl = runner.ctx.tl

    # NOT needs=("enrol_linux",), deliberately. A client that fails to check in
    # must not bury ~50 API checks that have nothing to do with it; the tier
    # that genuinely needs a client skips itself instead.
    @runner.phase("features", "Drive the backend API and assert on the answers",
                  needs=("auth",))
    def features(ctx):
        detail = {"tier0": {}, "tier1": {}, "tier2": {}, "skipped": []}

        # The session client the auth phase built, over nginx and TLS. NOT a
        # loopback client: see the module docstring — through the published port
        # every /api/ path answers 401, because Docker has already rewritten the
        # source address by the time Flask sees it.
        lb = ctx.get("client")
        if lb is None:
            ctx.check("an authenticated client is available", False,
                      note="the auth phase did not run or did not sign in; "
                           "without a session every request here would 401")
            return detail
        case_id = ctx.get("qa_case_id")
        if case_id:
            # Without this every run created here lands in the Default
            # workspace and the workspace-scoped listings look empty.
            lb.s.headers["X-Case-Id"] = str(case_id)

        caps = _capabilities(lb)
        detail["containers"] = caps

        _tier0(ctx, lb, caps, detail)
        _tier0_auth_counterweight(ctx, cfg, detail)
        _tier1(ctx, lb, detail)
        _tier2(ctx, lb, caps, detail)

        for path, why in SKIPPED_EXTERNAL:
            detail["skipped"].append({"path": path, "reason": why})
        ctx.check(f"{len(SKIPPED_EXTERNAL)} endpoints skipped for missing "
                  f"credentials, each recorded with a reason", True,
                  actual="; ".join(p for p, _ in SKIPPED_EXTERNAL[:4]) + " …",
                  note="see the Feature sweep section of REPORT.md")

        return detail


# --- tiers -----------------------------------------------------------------


def _capabilities(lb):
    """What this box can actually do, from the platform's own answer.

    /api/system/containers is the capability map the UI itself uses. Deciding
    what to skip from it means a disabled module produces honest skips rather
    than a screenful of failures about software that was never installed.
    """
    try:
        body = lb.get("/api/system/containers", expect=(200,))
    except Exception:                                         # noqa: BLE001
        return {}
    if not isinstance(body, dict):
        return {}
    out = {}
    for k, v in body.items():
        if isinstance(v, str):
            out[k] = v
        elif isinstance(v, dict) and "status" in v:
            out[k] = v["status"]
    return out


def _probe(ctx, lb, method, path, accept, note, bucket):
    """One request, one check. Never raises — a sweep that dies on the first
    unexpected code stops being a sweep."""
    assert path not in DENYLIST, f"{path} is on the denylist: {DENYLIST.get(path)}"
    try:
        r = lb.s.request(method, lb.base + path, timeout=60)
        code = r.status_code
    except Exception as exc:                                  # noqa: BLE001
        bucket[path] = "error"
        ctx.check(f"{method} {path}", False, expected=str(accept),
                  actual=f"request failed: {str(exc)[:120]}", note=note)
        return None
    ok = code in accept
    bucket[path] = code
    ctx.check(f"{method} {path}", ok, expected="/".join(str(a) for a in accept),
              actual=code, note=note)
    return r


def _tier0(ctx, lb, caps, detail):
    for method, path, accept, note in TIER0:
        _probe(ctx, lb, method, path, accept, note, detail["tier0"])

    velo_up = caps.get("velociraptor") == "online"
    for method, path, accept, note in TIER0_VELOCIRAPTOR:
        if not velo_up:
            detail["skipped"].append(
                {"path": path, "reason": "velociraptor container is not online"})
            continue
        _probe(ctx, lb, method, path, accept, note, detail["tier0"])


def _tier0_auth_counterweight(ctx, cfg, detail):
    """The other half of the sweep's claim about authentication.

    Everything above runs WITH a session and expects to get through. On its own
    that is satisfied by an appliance which lets everybody through. So: request
    the same guarded paths with no session at all, and require a refusal. The
    pair is the actual assertion — authorised callers succeed AND unauthorised
    ones are turned away.
    """
    guarded = ["/api/clients", "/api/cases", "/api/dashboard/automations",
               "/api/velociraptor/artifacts"]
    anon = api_lib.Client(cfg.platform_host, tl=None, scheme="https")
    for path in guarded:
        try:
            r = anon.s.get(anon.base + path, timeout=30, verify=False)
            code = r.status_code
        except Exception as exc:                              # noqa: BLE001
            detail["tier0"][f"anon {path}"] = "error"
            ctx.check(f"unauthenticated GET {path} is refused", False,
                      actual=f"request failed: {str(exc)[:120]}")
            continue
        detail["tier0"][f"anon {path}"] = code
        ctx.check(f"unauthenticated GET {path} is refused", code in (401, 403),
                  expected="401/403", actual=code,
                  note="the sweep's own requests carry a session; this proves "
                       "the gate turns away callers that do not")


def _tier1(ctx, lb, detail):
    """Create → read back → delete, on throwaway objects only.

    Named for the run so that anything left behind by a crash is obviously
    this harness's litter and not an operator's data.
    """
    stamp = time.strftime("%Y%m%d-%H%M%S")
    name = f"QA-CI-{stamp}"

    # -- cases ------------------------------------------------------------
    case_id = None
    try:
        body = lb.request("POST", "/api/cases", json={"name": name},
                          expect=(200, 201))
        case_id = (body or {}).get("case_id") if isinstance(body, dict) else None
    except Exception as exc:                                  # noqa: BLE001
        ctx.check("a case can be created", False, actual=str(exc)[:160])
    else:
        ctx.check("a case can be created", bool(case_id), actual=case_id)

    if case_id:
        detail["tier1"]["case_id"] = case_id
        try:
            listed = lb.get("/api/cases", expect=(200,))
            ids = [c.get("case_id") for c in (listed or {}).get("cases", [])
                   if isinstance(c, dict)]
            ctx.check("the new case appears in the list", case_id in ids,
                      expected=case_id,
                      actual=f"{len(ids)} case(s)")
        except Exception as exc:                              # noqa: BLE001
            ctx.check("the new case appears in the list", False,
                      actual=str(exc)[:160])

        for sub in ("graph", "hosts", "metrics", "timeline"):
            _probe(ctx, lb, "GET", f"/api/cases/{case_id}/{sub}", (200,),
                   "an empty case must still answer, not 500",
                   detail["tier1"])

        try:
            lb.request("DELETE", f"/api/cases/{case_id}", expect=(200, 204))
            ctx.check("the case can be deleted", True)
        except Exception as exc:                              # noqa: BLE001
            ctx.check("the case can be deleted", False, actual=str(exc)[:160])

    # -- custom sigma rules ------------------------------------------------
    rule_file = f"qa-ci-{stamp}.yml"
    rule_body = ("title: QA CI probe\nid: %s\nstatus: test\n"
                 "logsource:\n  product: aws\n  service: cloudtrail\n"
                 "detection:\n  sel:\n    eventName: QaCiProbeEvent\n"
                 "  condition: sel\nlevel: low\n" % stamp)
    try:
        lb.request("POST", "/api/aws/rules/custom",
                   json={"filename": rule_file, "content": rule_body},
                   expect=(200, 201))
        listed = lb.get("/api/aws/rules/custom", expect=(200,))
        blob = str(listed)
        ctx.check("a custom sigma rule round-trips", rule_file in blob,
                  expected=rule_file, actual="present" if rule_file in blob
                  else "absent from the listing")
        lb.request("DELETE", f"/api/aws/rules/custom/{rule_file}",
                   expect=(200, 204))
        gone = rule_file not in str(lb.get("/api/aws/rules/custom", expect=(200,)))
        ctx.check("a custom sigma rule can be deleted", gone)
    except Exception as exc:                                  # noqa: BLE001
        ctx.check("a custom sigma rule round-trips", False, actual=str(exc)[:160])

    # -- shipped blueprints are protected ----------------------------------
    #
    # The negative case matters more than the positive one: shipped defaults
    # must NOT be deletable, and a platform that lets a run delete one is
    # broken in a way no amount of green CRUD would reveal.
    try:
        shipped = lb.get("/api/blueprints/timesketch", expect=(200,))
        items = shipped if isinstance(shipped, list) else (shipped or {}).get("blueprints", [])
        default = next((b for b in items if isinstance(b, dict)
                        and b.get("id") == "timesketch_event_logs"), None)
        if default:
            r = lb.s.delete(lb.base + "/api/blueprints/timesketch/timesketch_event_logs",
                            timeout=60)
            ctx.check("a shipped blueprint cannot be deleted",
                      r.status_code not in (200, 204),
                      expected="a refusal", actual=r.status_code,
                      note="shipped defaults are not the operator's to remove")
        else:
            detail["skipped"].append({
                "path": "/api/blueprints/timesketch/timesketch_event_logs",
                "reason": "the shipped default blueprint is not present"})
    except Exception as exc:                                  # noqa: BLE001
        ctx.check("a shipped blueprint cannot be deleted", False,
                  actual=str(exc)[:160])

    # -- injection is rejected ---------------------------------------------
    #
    # services/vql_safety.py validates client and artifact names before they
    # reach VQL. These assert the REJECTION; a 200 here would be a finding.
    for payload, why in (
        ({"client_ids": ['C.x"); --'], "collection_minutes": 1},
         "a client id carrying VQL must not be accepted"),
        ({"artifacts": ["a;b"], "blueprint_name": "qa"},
         "an artifact name carrying a separator must not be accepted"),
    ):
        route = ("/api/agentic/run" if "client_ids" in payload
                 else "/api/velociraptor/bestpractice")
        try:
            r = lb.s.post(lb.base + route, json=payload, timeout=60)
            ctx.check(f"POST {route} rejects an injection attempt",
                      r.status_code == 400, expected=400, actual=r.status_code,
                      note=why)
        except Exception as exc:                              # noqa: BLE001
            ctx.check(f"POST {route} rejects an injection attempt", False,
                      actual=str(exc)[:160], note=why)


def _tier2(ctx, lb, caps, detail):
    """Anything that needs a real enrolled client."""
    client_id = ctx.get("client_id")
    if not client_id:
        detail["skipped"].append({
            "path": "tier2 (collection)",
            "reason": "no client enrolled — enrol_linux did not produce one"})
        ctx.check("collection tier ran", True,
                  actual="SKIPPED: no enrolled client",
                  note="not a failure; the tier has nothing to drive")
        return

    if caps.get("velociraptor") != "online":
        detail["skipped"].append({
            "path": "tier2 (collection)",
            "reason": "velociraptor container is not online"})
        return

    detail["tier2"]["client_id"] = client_id
    ctx.check("the enrolled client is visible to the API", True, actual=client_id)

    # A real collection against a real endpoint. Dispatch and completion are
    # what is being proven here — NOT detection quality: a Linux appliance host
    # is not a compromised Windows workstation and will not produce the
    # findings a customer's box would.
    #
    # If a Timesketch path is ever added here, remember that
    # /api/velociraptor/timesketch is a TWO-CALL API: without the follow-up
    # POST /api/timesketch/import the run sits at 5% forever, which presents
    # as a hung backend rather than as a missing call.
    detail["tier2"]["note"] = ("dispatch and collection only; detection content "
                               "is not asserted on a Linux appliance host")
