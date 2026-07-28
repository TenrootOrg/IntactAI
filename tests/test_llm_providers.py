"""LLM provider dispatch: which endpoint each provider actually talks to.

`_llm.py` is the single transport seam for the whole platform, so a mistake
here is silent and total — every report, advisory and chat goes through it.

The failures this guards against are all invisible until a live call:

  * a provider pointed at the wrong base_url (OpenRouter's key sent to
    OpenAI's endpoint, say) fails as an auth error that reads like a bad key;
  * token accounting reading the wrong response fields, which silently zeroes
    the cost badge and the usage log;
  * a self-hosted endpoint constructed without an api_key, which the OpenAI SDK
    refuses outright even when the server ignores auth;
  * a helper that is not actually reachable from where it is called. That one
    is not hypothetical: the shared adapter first shipped calling
    `_wrap_decode_errors`, which was nested inside `_call_llm_online` and so
    invisible from module scope. It raised NameError on the first real
    self-hosted call.

HTTP is faked at the SDK boundary; nothing here reaches the network.

Run: docker exec intact_backend python /app/workdir/tests/test_llm_providers.py
"""

import sys
import types

if "/app" not in sys.path:
    sys.path.insert(0, "/app")

from services.agentic.analyzers import _llm  # noqa: E402


class _Resp:
    """Minimal OpenAI-SDK-shaped response."""

    def __init__(self, text="ok"):
        msg = types.SimpleNamespace(content=text)
        self.choices = [types.SimpleNamespace(message=msg)]
        self.usage = types.SimpleNamespace(prompt_tokens=11, completion_tokens=7)


class _FakeOpenAI:
    """Captures how the SDK was constructed and called."""

    last = {}

    def __init__(self, **kwargs):
        _FakeOpenAI.last = {"init": kwargs, "call": None}
        outer = self

        class _Completions:
            def create(self, **kw):
                _FakeOpenAI.last["call"] = kw
                return _Resp()

        self.chat = types.SimpleNamespace(completions=_Completions())


def _with_fake_openai(fn):
    """Swap the `openai` module the adapter imports lazily."""
    real = sys.modules.get("openai")
    sys.modules["openai"] = types.SimpleNamespace(OpenAI=_FakeOpenAI)
    try:
        return fn()
    finally:
        if real is not None:
            sys.modules["openai"] = real
        else:
            sys.modules.pop("openai", None)


def _online(provider, api_key="k", model="m"):
    cfg = {"provider": provider, "api_key": api_key, "model": model}
    return _with_fake_openai(
        lambda: _llm._call_llm_online("hello", "sys", cfg, max_tokens=5))


# --------------------------------------------------------------------------


def test_each_openai_compatible_provider_uses_its_own_base_url():
    """The whole point of the shared adapter: same code, different endpoint."""
    expected = {
        "openai": None,                                  # SDK default
        "openrouter": "https://openrouter.ai/api/v1",
        "ollama-cloud": "https://ollama.com/v1",
    }
    assert _llm.OPENAI_COMPATIBLE_BASE_URLS == expected, _llm.OPENAI_COMPATIBLE_BASE_URLS
    for provider, base in expected.items():
        _online(provider)
        got = _FakeOpenAI.last["init"].get("base_url")
        assert got == base, f"{provider} built a client for {got!r}, expected {base!r}"


def test_the_prompt_is_sent_as_system_plus_user():
    _online("openai")
    msgs = _FakeOpenAI.last["call"]["messages"]
    assert [m["role"] for m in msgs] == ["system", "user"], msgs
    assert msgs[0]["content"] == "sys" and msgs[1]["content"] == "hello"


def test_max_tokens_is_honoured():
    """The connectivity probe relies on this: max_tokens=1 must reach the API,
    or a 'free' test bills like a real report."""
    _online("openai")
    assert _FakeOpenAI.last["call"]["max_tokens"] == 5


def test_self_hosted_endpoint_gets_a_placeholder_key():
    """Local servers ignore auth, but the SDK refuses to construct without a
    key — an empty string would fail before a request is ever made."""
    cfg = {"provider": "openai-compatible", "model": "m",
           "url": "http://box:11434/v1", "api_key": ""}
    _with_fake_openai(lambda: _llm._call_llm_offline(
        "hello", "sys", cfg, context_size=4096, timeout=30))
    init = _FakeOpenAI.last["init"]
    assert init.get("base_url") == "http://box:11434/v1", init
    assert init.get("api_key"), "empty api_key reached the SDK — it will refuse to construct"


def test_offline_openai_compatible_honours_its_own_timeout():
    """Self-hosted boxes are slower than vendor APIs; the offline timeout must
    win over the online default."""
    cfg = {"provider": "openai-compatible", "model": "m",
           "url": "http://box:11434/v1", "api_key": ""}
    _with_fake_openai(lambda: _llm._call_llm_offline(
        "hello", "sys", cfg, context_size=4096, timeout=123))
    assert _FakeOpenAI.last["init"].get("timeout") == 123


def test_native_ollama_still_uses_generate_and_keeps_num_ctx():
    """The native branch is kept precisely because OpenAI's schema has no
    equivalent of num_ctx. If it ever routed through the shared adapter the
    context-size setting would silently stop applying."""
    captured = {}

    class _R:
        status_code = 200

        def raise_for_status(self): pass

        def json(self): return {"response": "ok", "prompt_eval_count": 3, "eval_count": 2}

    real_post = _llm.requests.post
    _llm.requests.post = lambda url, **kw: (captured.update(url=url, **kw), _R())[1]
    try:
        cfg = {"provider": "ollama", "model": "m", "url": "http://box:11434"}
        out = _llm._call_llm_offline("hello", "sys", cfg, context_size=65536, timeout=30)
    finally:
        _llm.requests.post = real_post
    assert out == "ok"
    assert captured["url"].endswith("/api/generate"), captured["url"]
    assert captured["json"]["options"]["num_ctx"] == 65536, captured["json"]


def test_token_accounting_covers_every_openai_shaped_provider():
    """A provider missing from _OPENAI_SHAPED records zero tokens, which zeroes
    the cost badge and the usage log without any error."""
    for provider in _llm.OPENAI_COMPATIBLE_BASE_URLS:
        assert provider in _llm._OPENAI_SHAPED, provider
    assert "openai-compatible" in _llm._OPENAI_SHAPED

    seen = {}
    real = _llm.record_llm_metrics if hasattr(_llm, "record_llm_metrics") else None
    import services.workflow_service as W
    orig = W.record_llm_metrics
    W.record_llm_metrics = lambda *a, **k: seen.update(args=a, kw=k)
    try:
        _llm._record_llm_usage("run1", "ollama-cloud", "m", _Resp())
    finally:
        W.record_llm_metrics = orig
    assert seen, "no usage recorded for an OpenAI-shaped provider"


def test_unknown_providers_are_rejected_loudly():
    """Better a clear error than a silent fallback to someone else's endpoint."""
    for fn, cfg in (
        (lambda: _llm._call_llm_online("p", "s", {"provider": "nope", "api_key": "k",
                                                  "model": "m"}, max_tokens=1), "online"),
        (lambda: _llm._call_llm_offline("p", "s", {"provider": "nope", "model": "m",
                                                   "url": "http://x"}, 4096, 30), "offline"),
    ):
        try:
            fn()
        except ValueError as e:
            assert "nsupported" in str(e), e
        except Exception as e:      # noqa: BLE001
            raise AssertionError(f"{cfg}: expected ValueError, got {type(e).__name__}: {e}")
        else:
            raise AssertionError(f"{cfg}: unknown provider was accepted")


def test_direct_gemini_model_ids_are_priced():
    """The cost table only had `google/gemini-…` (OpenRouter's id form). Once
    Gemini became directly selectable its ids arrive bare, matched nothing, and
    every Gemini run reported $0 — tokens recorded, spend invisible."""
    bare = _llm._estimate_llm_cost("gemini-2.5-flash", 1_000_000, 1_000_000)
    via_or = _llm._estimate_llm_cost("google/gemini-2.5-flash", 1_000_000, 1_000_000)
    assert bare > 0, "direct Gemini id priced at $0"
    assert abs(bare - via_or) < 1e-9, f"same model, two prices: {bare} vs {via_or}"


def test_self_hosted_models_are_priced_at_zero():
    """Nothing is billed for a box the operator already owns — a made-up rate
    would be worse than none."""
    assert _llm._estimate_llm_cost("qwen2.5:0.5b", 1_000_000, 1_000_000) == 0.0


def test_codex_subscription_reads_max_output_from_its_catalog():
    """get_model_context_length had this branch and get_model_max_output_tokens
    did not, so a subscription model silently took the constant default output
    cap instead of its real one — truncating long reports."""
    import services.llm_catalogs.codex as codex
    orig = codex.load_catalog
    codex.load_catalog = lambda: [{"id": "gpt-5-codex", "max_output_tokens": 77777}]
    try:
        got = _llm.get_model_max_output_tokens("gpt-5-codex", "codex-subscription")
    finally:
        codex.load_catalog = orig
    assert got == 77777, f"codex-subscription cap not resolved: {got!r}"


def test_ollama_cloud_lists_against_the_hosted_openai_endpoint():
    """Ollama Cloud reuses the self-hosted lister rather than a catalog module.
    If the base URL or the shape drifts, the model box goes silently empty."""
    import services.llm_catalogs.ollama as cat
    seen = {}

    class _R:
        status_code = 200

        def json(self): return {"data": [{"id": "gpt-oss:120b"}]}

    real = cat.requests.get
    cat.requests.get = lambda url, **kw: (seen.update(url=url, **kw), _R())[1]
    try:
        models = cat.list_cloud_models("sk-test")
    finally:
        cat.requests.get = real
    assert seen["url"] == "https://ollama.com/v1/models", seen["url"]
    assert seen["headers"]["Authorization"] == "Bearer sk-test", seen["headers"]
    assert [m["id"] for m in models] == ["gpt-oss:120b"], models


def test_the_subscription_provider_is_named_the_same_in_both_places():
    """Its name lives twice: the provider <option> the operator picks, and
    PROVIDERS[...]['label'] the CLI panel shows once picked. Drift between them
    reads as two different providers on one screen.

    Also asserts every dropdown entry names its VENDOR. This one used to read
    just 'Codex (Subscription)', which is a tool, not a vendor — and once plain
    'OpenAI' joined the list, nothing said the two were the same company billed
    two different ways.
    """
    import os
    import re
    from services.agentic.subscription_cli import PROVIDERS

    html = os.path.join(os.environ.get("INTACT_PATH", "/app/workdir"),
                        "modules/nginx/html/partials/settings.html")
    with open(html, encoding="utf-8") as fh:
        markup = fh.read()

    label = PROVIDERS["codex-subscription"]["label"]
    m = re.search(r'<option value="codex-subscription">([^<]+)</option>', markup)
    assert m, "the subscription provider lost its <option> in the dropdown"
    assert m.group(1) == label, (
        f"dropdown says {m.group(1)!r} but the CLI panel says {label!r}")
    assert "OpenAI" in label, (
        f"{label!r} does not name its vendor, so it cannot be told apart from "
        f"the plain OpenAI entry")


def test_one_providers_key_is_never_sent_to_another():
    """The config stores a SINGLE online_llm.api_key, owned by whichever
    provider is selected. Reading that field directly hands it to whoever asks.

    Not hypothetical: the Ollama Cloud route first read it directly, and a live
    run with OpenRouter configured posted a real `sk-or-v1-…` key to
    ollama.com as a Bearer token. Every catalog must go through
    get_provider_api_key, which returns the key only for its own provider.
    """
    import routes.config_routes as C
    import services.file_storage_service as FS
    from flask import Flask

    app = Flask(__name__)
    reached = {}

    def _must_not_be_called(*a, **kw):
        reached["called"] = True
        raise AssertionError("cross-provider key leak: contacted ollama.com "
                             "while another provider's key was saved")

    orig_load, orig_list = FS.load_frontend_config, None
    import services.llm_catalogs.ollama as cat
    orig_list = cat.list_cloud_models
    FS.load_frontend_config = lambda: {"agentic": {"online_llm": {
        "provider": "openrouter", "api_key": "sk-or-v1-SECRET"}}}
    cat.list_cloud_models = _must_not_be_called
    try:
        with app.test_request_context("/api/config/ollama-cloud/models"):
            body = C.get_ollama_cloud_models().get_json()
    finally:
        FS.load_frontend_config = orig_load
        cat.list_cloud_models = orig_list

    assert not reached.get("called"), "another provider's key was sent to ollama.com"
    assert body["models"] == [] and body["total"] == 0, body
    assert body.get("error"), "no explanation for the empty list"


def test_a_masked_api_key_resolves_to_the_saved_one():
    """GET /api/config returns the key as bullets. The probe first tested for
    '*', so the mask never matched and the bullet string itself was sent as the
    key — every test of an already-saved provider failed as an auth error, which
    reads exactly like a genuinely bad key."""
    import routes.config_routes as C
    from flask import Flask

    app = Flask(__name__)
    saved = {"agentic": {"online_llm": {"provider": "openai", "api_key": "sk-REAL",
                                        "model": "m"}, "llm_mode": "online"}}
    used = {}

    def _fake_call(prompt, system, cfg):
        used["key"] = ((cfg["agentic"].get("online_llm") or {}).get("api_key"))
        return "OK"

    # The route imports call_llm inside the function body, so patching the
    # module attribute is what it will pick up.
    orig_load, orig_call = C._load_config, _llm.call_llm
    C._load_config = lambda: {"agentic": {"online_llm": dict(
        saved["agentic"]["online_llm"]), "llm_mode": "online"}}
    _llm.call_llm = _fake_call
    try:
        masked = C._API_KEY_MASK_PREFIX + "••••REAL"
        with app.test_request_context(
                "/api/config/llm/test", method="POST",
                json={"agentic": {"online_llm": {"api_key": masked}}}):
            C.test_llm_connection()
    finally:
        C._load_config = orig_load
        _llm.call_llm = orig_call
    assert used.get("key") == "sk-REAL", (
        f"masked key was not resolved — sent {used.get('key')!r} to the provider")


def test_shared_adapter_helpers_are_importable_at_module_scope():
    """Regression: the adapter shipped calling a helper nested inside
    _call_llm_online, so it raised NameError on the first self-hosted call."""
    assert callable(getattr(_llm, "_wrap_decode_errors", None)), \
        "_wrap_decode_errors must be module-level — the shared adapter calls it"
    assert callable(getattr(_llm, "_call_openai_compatible", None))


if __name__ == "__main__":
    failures = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"PASS {name}")
            except AssertionError as e:
                failures += 1
                print(f"FAIL {name}: {e}")
            except Exception as e:      # noqa: BLE001
                failures += 1
                print(f"FAIL {name}: unexpected {type(e).__name__}: {e}")
    print("OK" if not failures else f"{failures} FAILED")
    sys.exit(1 if failures else 0)
