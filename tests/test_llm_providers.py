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
