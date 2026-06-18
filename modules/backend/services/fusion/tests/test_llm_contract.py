"""Real-LLM contract tests — mock the call_llm seam, no network.

Asserts the production path (a) sends the DISTILLED payload + the right system
prompt (never raw graph or fact tables), (b) threads run_id=case_id so tokens land
on llm_metrics, (c) falls back to the deterministic narrator on ANY LLM failure, and
(d) defaults to simulated. Airgap-safe.
"""

import sys
import contextlib
if "/app" not in sys.path:
    sys.path.insert(0, "/app")

from services.fusion import llm_sim  # noqa: E402
import services.fusion.tests.test_fusion as T  # noqa: E402


@contextlib.contextmanager
def real_mode(call_stub):
    """Force fusion_llm_mode=real and patch the call_llm seam with a stub."""
    import services.agentic.analyzers as A
    import services.memory.pipeline as P
    saved = (llm_sim._agentic_cfg, A.call_llm, P._llm_config_from_runtime)
    llm_sim._agentic_cfg = lambda: {"fusion_llm_mode": "real", "online_llm": {"api_key": "t"}}
    A.call_llm = call_stub
    P._llm_config_from_runtime = lambda: {"agentic": {}}
    try:
        yield
    finally:
        llm_sim._agentic_cfg, A.call_llm, P._llm_config_from_runtime = saved


def test_report_real_path_sends_distilled_and_threads_run_id():
    g = T.build()
    seen = {}

    def stub(prompt, system_prompt, config, run_id=None, model_override=None):
        seen.update(prompt=prompt, system=system_prompt, run_id=run_id)
        return "EXEC NARRATIVE PROSE"

    with real_mode(stub):
        out = llm_sim.generate_report(g, window=T.WINDOW, min_severity="low",
                                      case_name="X", run_id="case_42")
    assert "findings" in seen["prompt"] and "case_id" in seen["prompt"], "distilled payload sent"
    assert "Key Indicators" not in seen["prompt"], "fact tables must NOT be in the LLM payload"
    assert seen["system"] == llm_sim.REPORT_SYSTEM_PROMPT
    assert seen["run_id"] == "case_42", "run_id threaded for token accounting"
    assert "EXEC NARRATIVE PROSE" in out and "Key Indicators" in out, "narrative + deterministic facts"


def test_report_falls_back_on_llm_error():
    g = T.build()

    def boom(*a, **k):
        raise RuntimeError("api down")

    with real_mode(boom):
        out = llm_sim.generate_report(g, window=T.WINDOW, min_severity="low",
                                      case_name="X", run_id="c")
    assert "deterministic fallback" in out and "Executive" in out


def test_chat_real_path_uses_distilled_and_run_id():
    g = T.build()
    seen = {}

    def stub(prompt, system_prompt, config, run_id=None, model_override=None):
        seen.update(prompt=prompt, system=system_prompt, run_id=run_id)
        return "ANSWER"

    with real_mode(stub):
        ans = llm_sim.chat(g, "what about 5.100.251.10?", window=T.WINDOW,
                           min_severity="low", run_id="c9")
    assert ans == "ANSWER" and seen["run_id"] == "c9"
    assert seen["system"] == llm_sim.CHAT_SYSTEM_PROMPT and "findings" in seen["prompt"]


def test_chat_falls_back_to_deterministic_on_error():
    g = T.build()

    def boom(*a, **k):
        raise RuntimeError("down")

    with real_mode(boom):
        ans = llm_sim.chat(g, "how did they move laterally?", window=T.WINDOW, min_severity="low")
    assert "lateral" in ans.lower() or "cross-host" in ans.lower()  # deterministic retriever answered


def test_default_is_simulated():
    g = T.build()
    saved = llm_sim._agentic_cfg
    llm_sim._agentic_cfg = lambda: {}  # no fusion_llm_mode -> simulated
    try:
        out = llm_sim.generate_report(g, window=T.WINDOW, min_severity="low", case_name="X")
    finally:
        llm_sim._agentic_cfg = saved
    assert "simulated" in out.lower()


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    p = f = 0
    for fn in fns:
        try:
            fn(); p += 1; print(f"PASS {fn.__name__}")
        except AssertionError as e:
            f += 1; print(f"FAIL {fn.__name__}: {e}")
    print(f"{p}/{len(fns)} passed")
    sys.exit(1 if f else 0)
