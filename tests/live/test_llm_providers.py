"""Live: the LLM provider endpoints behave against the running stack.

Deliberately spends NO vendor quota — same discipline as test_agentic.py. The
one probe that costs anything (POST /api/config/llm/test) is only fired when
the saved provider is self-hosted, where the operator owns the hardware. For a
metered provider this suite asserts the endpoint's SHAPE and stops, because a
test suite that quietly bills the operator's API key on every run is worse than
no suite.

What this covers that the unit tests cannot: that these routes are actually
REGISTERED and reachable. The unit tests import the functions directly, so a
blueprint that never got the route — or a route shadowed by another rule —
passes every one of them and 404s in the browser.

Run: docker exec intact_backend python /app/workdir/tests/live/run_all.py
     docker exec intact_backend python /app/workdir/tests/live/test_llm_providers.py
"""

import sys

if "/app/workdir/tests" not in sys.path:
    sys.path.insert(0, "/app/workdir/tests")

from live._lib import _get, _post  # noqa: E402

SELF_HOSTED = ("ollama", "openai-compatible")


def _agentic():
    r = _get("/api/config")
    r.raise_for_status()
    return (r.json() or {}).get("agentic") or {}


def check_offline_model_listing_never_500s():
    """The settings page calls this on every keystroke in the URL field, so a
    half-typed URL is a NORMAL state. It must come back 200 with a reason, not
    a 500 and a red console entry."""
    cases = [
        ("", "empty"),
        ("nonsense", "no scheme"),
        ("http://127.0.0.1:1/", "nothing listening"),
        ("http://no-such-host-here.invalid:11434", "unresolvable"),
    ]
    for url, label in cases:
        r = _get(f"/api/config/ollama/models?url={url}")
        if r.status_code != 200:
            return False, f"{label} -> HTTP {r.status_code} (must be 200 + reason)"
        body = r.json()
        if body.get("ok") is not False:
            return False, f"{label} -> reported ok={body.get('ok')}, expected a failure"
        if not body.get("reason") or not body.get("error"):
            return False, f"{label} -> no machine reason / operator message: {body}"
    return True, f"{len(cases)} bad URLs each returned 200 with an actionable reason"


def check_openai_compatible_listing_is_reachable():
    """The `kind` switch must be honoured — it selects /api/tags vs /v1/models.
    If it were ignored, a LiteLLM/vLLM server would always be probed as Ollama
    and always look empty."""
    r = _get("/api/config/ollama/models?url=http://127.0.0.1:1/v1&kind=openai-compatible")
    if r.status_code != 200:
        return False, f"HTTP {r.status_code}"
    body = r.json()
    if body.get("ok") is not False or body.get("reason") != "unreachable":
        return False, f"expected an unreachable verdict, got {body}"
    return True, "openai-compatible listing routed and reported unreachable"


def check_ollama_cloud_catalog_route_exists():
    """The online model combobox builds its URL from the provider id, so this
    route existing is the whole reason Ollama Cloud has a populated model box.
    Asserts the route is REGISTERED and returns the catalog shape — never
    contacts ollama.com without a key."""
    r = _get("/api/config/ollama-cloud/models?limit=5")
    if r.status_code == 404:
        return False, "route not registered — the model box will be empty"
    if r.status_code != 200:
        return False, f"HTTP {r.status_code}: {r.text[:150]}"
    body = r.json()
    for field in ("models", "total"):
        if field not in body:
            return False, f"missing '{field}' — combobox reads data.models/data.total: {body}"
    if not isinstance(body["models"], list):
        return False, f"models is {type(body['models']).__name__}, not a list"
    return True, f"registered, catalog-shaped ({body['total']} model(s), key-dependent)"


def check_llm_test_endpoint_reports_rather_than_raises():
    """Every failure must come back as a REPORTABLE result, not a 500. This is
    the endpoint an operator uses to diagnose a bad key, so an opaque 500 would
    hide the very thing it exists to show.

    Uses a deliberately unreachable self-hosted URL, so nothing is billed.
    """
    r = _post("/api/config/llm/test", {"agentic": {
        "llm_mode": "offline",
        "offline_llm": {"provider": "openai-compatible", "model": "probe",
                        "url": "http://127.0.0.1:1/v1", "api_key": ""},
    }})
    if r.status_code != 200:
        return False, f"HTTP {r.status_code} — failures must be reported, not raised: {r.text[:200]}"
    body = r.json()
    if body.get("success") is not False:
        return False, f"unreachable server reported success={body.get('success')}: {body}"
    if not body.get("error"):
        return False, f"failed with no error text — nothing for the operator to act on: {body}"
    if "elapsed_ms" not in body:
        return False, "no elapsed_ms; the UI shows it"
    return True, f"reported failure cleanly: {body['error'][:70]}"


def check_configured_provider_actually_answers():
    """A real single-token round-trip — but ONLY against a server the operator
    owns. Skips for metered providers so this suite never spends their quota.
    """
    ag = _agentic()
    mode = str(ag.get("llm_mode", "online")).lower()
    provider = ((ag.get("offline_llm") if mode == "offline"
                 else ag.get("online_llm")) or {}).get("provider")
    if mode != "offline" or provider not in SELF_HOSTED:
        return None, f"configured provider is '{provider}' ({mode}) — not probing a metered API"

    r = _post("/api/config/llm/test", {})
    if r.status_code != 200:
        return False, f"HTTP {r.status_code}: {r.text[:200]}"
    body = r.json()
    if not body.get("success"):
        return False, (f"{provider} did not answer: {body.get('error')} "
                       f"(stage {body.get('stage')})")
    return True, f"{provider} replied {body.get('reply')!r} in {body.get('elapsed_ms')}ms"


CHECKS = [
    ("offline_model_listing_never_500s", check_offline_model_listing_never_500s),
    ("openai_compatible_listing_reachable", check_openai_compatible_listing_is_reachable),
    ("ollama_cloud_catalog_route_exists", check_ollama_cloud_catalog_route_exists),
    ("llm_test_endpoint_reports_failures", check_llm_test_endpoint_reports_rather_than_raises),
    ("configured_provider_answers", check_configured_provider_actually_answers),
]


if __name__ == "__main__":
    failures = 0
    for name, fn in CHECKS:
        try:
            ok, msg = fn()
        except Exception as e:                      # noqa: BLE001
            ok, msg = False, f"unexpected {type(e).__name__}: {e}"
        if ok is None:
            print(f"SKIP {name}: {msg}")
        elif ok:
            print(f"PASS {name}: {msg}")
        else:
            failures += 1
            print(f"FAIL {name}: {msg}")
    print("OK" if not failures else f"{failures} FAILED")
    sys.exit(1 if failures else 0)
