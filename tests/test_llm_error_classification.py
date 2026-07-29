"""When the LLM call fails, tell the operator the truth about why.

Case Analysis chat maps a transport exception to one of a handful of reason
codes, and the message for each is the only thing the operator sees. Get the
mapping wrong and you don't just fail to help -- you actively send someone to
the wrong place.

That happened. OpenRouter refused to route `qwen/qwen3.7-flash` because the
account's data policy allowed no matching endpoint:

    HTTP 404 {"message": "No endpoints available matching your guardrail
    restrictions and data policy. Configure: .../settings/privacy"}

Nothing matched, so it fell through to the catch-all: "Could not get a
response from the LLM. Check the API key and internet connection." The key
authenticated fine (HTTP 200 on /api/v1/key, paid tier) and the same key
worked on five other models. The operator was told to check the two things
that were provably correct.

The fix is a reason code of its own, classified BEFORE the auth patterns --
those are broad enough (`api key`, `403`) to swallow a routing refusal whose
body mentions "api" or "policy".

These are pure string->code assertions: no network, no live model, no stack.

Run: docker exec intact_backend python3 /app/workdir/tests/test_llm_error_classification.py
"""

import os
import sys

REPO = os.environ.get("INTACT_PATH", "/app/workdir")
if "/app" not in sys.path:
    sys.path.insert(0, "/app")

LLM_SIM = os.path.join(REPO, "modules", "backend", "services", "fusion", "llm_sim.py")


def _load():
    """Exec just the classifier + message table.

    Importing services.fusion.llm_sim drags in the whole fusion stack; the two
    functions under test are pure, so slice them out instead.
    """
    with open(LLM_SIM, "r", encoding="utf-8") as handle:
        src = handle.read()
    start = src.index("_LLM_ERR_MESSAGES = {")
    end = src.index("def chat(")
    namespace = {}
    exec(compile(src[start:end], "<llm_sim-slice>", "exec"), namespace)  # noqa: S102
    return namespace["_classify_llm_error"], namespace["llm_error_message"]


CLASSIFY, MESSAGE = _load()


def _check(exc_text, expected):
    got = CLASSIFY(Exception(exc_text))
    assert got == expected, (
        f"classified as {got!r}, expected {expected!r}\n  input: {exc_text[:160]}")


# --- the regression that prompted this ---------------------------------------


def test_the_openrouter_data_policy_refusal_is_not_blamed_on_the_key():
    """Verbatim from the failure. The account's data policy left no routable
    endpoint for the model -- the key and the network were both fine."""
    _check(
        "OpenRouter API request failed (HTTP 404): {'error': {'message': "
        "'No endpoints available matching your guardrail restrictions and data "
        "policy. Configure: https://openrouter.ai/settings/privacy', 'code': 404}}",
        "model_not_routable")


def test_the_message_points_at_the_model_not_the_key():
    text = MESSAGE("model_not_routable").lower()
    assert "model" in text, "the message should point at the model choice"
    assert "polic" in text, "the message should name the data policy as the cause"
    # The whole point: it must NOT send someone to re-check a working key.
    assert "check the api key" not in text, \
        "this message must not blame the API key -- that is what went wrong before"


def test_routing_refusals_are_classified_before_the_auth_patterns():
    """The auth branch matches on bare 'api key' and '403', either of which can
    appear in a provider's routing-refusal body. Order is load-bearing."""
    _check("403 Forbidden: no allowed providers for this model under your api key policy",
           "model_not_routable")


# --- and the codes it must NOT have stolen -----------------------------------


def test_a_genuinely_bad_key_is_still_an_auth_error():
    for text in ("401 Unauthorized: invalid api key",
                 "AuthenticationError: invalid_api_key",
                 "403 Forbidden: user not found"):
        _check(text, "invalid_key")


def test_connectivity_and_timeout_and_rate_limit_still_classify():
    _check("Max retries exceeded: getaddrinfo failed", "no_internet")
    _check("ConnectionError: Failed to establish a new connection", "no_internet")
    _check("Read timed out after 120s", "timeout")
    _check("429 Client Error: Too Many Requests", "rate_limited")


def test_an_unrecognised_failure_still_falls_back():
    assert CLASSIFY(Exception("something entirely novel")) == "llm_error"


def test_every_reason_code_has_a_message():
    """A code with no message silently renders the generic catch-all, which is
    how a specific diagnosis turns back into 'check the API key'."""
    with open(LLM_SIM, "r", encoding="utf-8") as handle:
        src = handle.read()
    start = src.index("def _classify_llm_error")
    body = src[start:src.index("\ndef ", start + 10)]

    import re
    returned = set(re.findall(r'return "([a-z_]+)"', body))
    for code in sorted(returned):
        assert MESSAGE(code) != MESSAGE("__definitely_not_a_code__") or code == "llm_error", \
            f"reason code {code!r} has no message of its own"


if __name__ == "__main__":
    import traceback
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"PASS {fn.__name__}")
        except Exception:
            failed += 1
            print(f"FAIL {fn.__name__}")
            traceback.print_exc()
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    sys.exit(1 if failed else 0)
