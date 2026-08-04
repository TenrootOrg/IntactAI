"""The offline-LLM settings must stay usable when the server is unreachable.

The Model field was a bare <select> populated only from the server's own model
list. That is fine while the server answers -- and useless the moment it does
not, which is the common case: the field defaults people toward
`http://localhost:11434`, and inside the backend container `localhost` is the
backend itself, so nothing is ever listed.

What the operator then saw was a dropdown containing exactly one option, the
previously-saved model tagged "(not on this server)", which could not be
changed and could not be typed over. The one control needed to fix the problem
was disabled by the problem.

So: typing must always work, and the server's list is an aid rather than a
gate. These tests pin that, plus the mode label -- "Offline (Ollama)" implied
Ollama was the only choice when the server-type selector directly beneath it
also offers any OpenAI-compatible server (LiteLLM / vLLM / LM Studio).

Static assertions over the markup; no browser, no stack.

Run: docker exec intact_backend python3 /app/workdir/tests/test_agentic_offline_settings.py
"""

import os
import re
import sys

REPO = os.environ.get("INTACT_PATH", "/app/workdir")
SETTINGS = os.path.join(REPO, "modules", "nginx", "html", "partials", "settings.html")


def _agentic_tab():
    with open(SETTINGS, "r", encoding="utf-8") as handle:
        html = handle.read()
    start = html.index("settingsTab === 'agentic'")
    return html[start:html.index("<!-- Timesketch Tab -->")]


def _offline_block():
    tab = _agentic_tab()
    start = tab.index("llm_mode === 'offline'")
    return tab[start:tab.index("llm_mode === 'online'", start)]


def _strip_comments(text):
    return re.sub(r"<!--.*?-->", "", text, flags=re.DOTALL)


def test_the_model_can_always_be_typed():
    """The regression: a <select> is unusable when the list cannot be fetched."""
    block = _strip_comments(_offline_block())

    field = re.search(
        r'<input[^>]*x-model="\$store\.settings\.config\.agentic\.offline_llm\.model"[^>]*>',
        block)
    assert field, "the offline model field is not a text input -- it cannot be typed into"
    assert 'type="text"' in field.group(0), \
        f"expected a text input, got: {field.group(0)[:120]}"

    assert not re.search(
        r'<select[^>]*x-model="\$store\.settings\.config\.agentic\.offline_llm\.model"',
        block), \
        "the model field is a bare <select> again; with an unreachable server that " \
        "leaves nothing to pick and no way to type"


def test_the_server_list_is_offered_but_not_required():
    block = _strip_comments(_offline_block())
    assert "offlineModels" in block, \
        "the server's own model list should still be offered as suggestions"
    assert "loadOfflineModels" in block, \
        "there should still be a way to re-query the server"


def test_an_unreachable_server_says_you_can_still_type():
    """An error that leaves the operator stuck is worse than no error."""
    block = _offline_block()
    assert "offlineModelsError" in block, "the listing error is not surfaced"
    assert "still type" in block.lower(), (
        "when listing fails the UI must say the model can still be typed -- "
        "otherwise the operator believes the field is broken")


def test_localhost_is_called_out_as_wrong():
    """`localhost` inside the backend container is the backend. This is the
    single most common reason the model list comes back empty."""
    block = _offline_block().lower()
    assert "localhost" in block, "nothing warns about the localhost trap"
    assert "container" in block, \
        "the warning should explain that localhost resolves to the backend container"


def test_the_mode_is_not_named_after_one_server_type():
    tab = _strip_comments(_agentic_tab())
    label = re.search(r'<option value="offline">([^<]*)</option>', tab)
    assert label, "the offline mode option is missing"
    text = label.group(1).strip()
    assert "ollama" not in text.lower(), (
        f"the mode is labelled {text!r}, which implies Ollama is the only option -- "
        f"the server-type selector below it also offers OpenAI-compatible servers")
    assert text, "the offline mode option has no label"


def test_both_offline_server_types_are_still_offered():
    block = _offline_block()
    assert 'value="ollama"' in block, "the Ollama server type is gone"
    assert 'value="openai-compatible"' in block, \
        "the OpenAI-compatible (LiteLLM / vLLM / LM Studio) server type is gone"


def test_no_x_data_block_can_break_out_of_its_attribute():
    for data_block in re.findall(r'x-data="([^"]*)"', _agentic_tab(), re.DOTALL):
        assert '"' not in data_block, \
            "a double quote inside an x-data attribute terminates it"


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
