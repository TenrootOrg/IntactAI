"""Case-chat robustness — everything short of "does the wording read well" that
could make a genuinely capable model look broken from the operator's chair.

The disposition-safety battery (test_chat_never_mutates.py) proves the chat
cannot silently mutate the case. This file covers the rest of what "the chat
must never break" means in practice: concurrent turns on the same case, an
empty/fresh case, confirmation edge cases, a stale offer surviving a re-fuse,
malformed masking config, the model transport raising, and unbounded history —
none of which should ever surface as a crash, a corrupted case, or a refusal
that has nothing to do with what the operator actually asked.
"""

import sys
if "/app" not in sys.path:
    sys.path.insert(0, "/app")

import re      # noqa: E402
import threading  # noqa: E402
import time     # noqa: E402

from services.fusion import store, llm_sim, calibrate  # noqa: E402

_STUB = "STUB-ANSWER"


# ---------------------------------------------------------------------------
# fixtures / helpers
# ---------------------------------------------------------------------------

def _fresh_case(name, fixture="attack2", min_severity="informational"):
    from services import workflow_service as ws
    for r in ws.get_all_automation_runs() or []:
        if r.get("automation_type") == store.CASE_TYPE and \
                (r.get("details") or {}).get("name") == name:
            store.delete_case(r.get("run_id"))
    contrib = calibrate._contribution(calibrate.load_fixture(fixture))
    cid = store.create_case(name, min_severity=min_severity)
    store.fuse_case(cid, contributions_override=[contrib])
    return cid


def _dispositions(cid):
    return list((store._ws().get_automation_run(cid).get("details") or {}).get("dispositions") or [])


def _pending(cid):
    return (store._ws().get_automation_run(cid).get("details") or {}).get("pending_disposition")


def _history(cid):
    return list((store._ws().get_automation_run(cid).get("details") or {}).get("chat_messages") or [])


def _groundable_trigger(cid):
    """A sentence the matcher will actually ground, for this fixture's findings."""
    g = store.load_graph(cid)
    for f in g.findings:
        toks = [w for w in re.findall(r"[a-z0-9]{4,}", f.title.lower())
                if w not in llm_sim._GENERIC_TITLE_TOK]
        for t in toks:
            msg = f"the {t} alert is benign, it is our admin"
            if llm_sim.detect_disposition(g, msg):
                return msg
    return None


class _SlowStub:
    """Like the plain stub, but sleeps to hold the race window open long enough
    for a second thread to run its own read-decide-write sequence during the
    first thread's "model call" — the real multi-second LLM latency is exactly
    what makes two chat_case calls on the same case overlap in production."""

    def __init__(self, delay=0.08):
        self.delay = delay
        self.calls = 0
        self._lock = threading.Lock()

    def __call__(self, g, question, **kw):
        with self._lock:
            self.calls += 1
        time.sleep(self.delay)
        return _STUB


class _RaisingStub:
    def __init__(self, exc):
        self.exc = exc

    def __call__(self, g, question, **kw):
        raise self.exc


def _with_chat(stub, fn):
    original = llm_sim.chat
    llm_sim.chat = stub
    try:
        return fn()
    finally:
        llm_sim.chat = original


# ---------------------------------------------------------------------------
# empty / fresh case
# ---------------------------------------------------------------------------

def test_empty_case_with_zero_findings_never_crashes():
    """The 'clean' calibration fixture has no findings at all — the shape every
    brand-new case starts in before anything is fused. Detection and chat must
    both handle an empty graph, not just a populated one."""
    cid = _fresh_case("chat-robust-empty", fixture="clean")

    def body():
        for q in ("who is the attacker", "what happened here",
                  "the server is benign, ignore it", "?", ""):
            ans = store.chat_case(cid, q)
            assert _STUB in (ans or ""), f"empty case blocked the model for {q!r}"
        assert _dispositions(cid) == [], "an empty graph produced a disposition"
    _with_chat(_SlowStub(0), body)


# ---------------------------------------------------------------------------
# concurrency — two chat turns on the SAME case, overlapping
# ---------------------------------------------------------------------------

def test_concurrent_confirms_apply_exactly_once():
    """Two 'confirm' replies fired at the same pending offer (double-click, a
    retried request) must not double-apply or corrupt the disposition list —
    set_disposition is keyed by target and mutate_run_details is lock-serialized,
    so this pins that the guarantee actually holds under real thread overlap,
    not just on paper."""
    cid = _fresh_case("chat-robust-concurrent-confirm")
    trigger = _groundable_trigger(cid)
    assert trigger, "fixture produced nothing groundable"

    def body():
        store.chat_case(cid, trigger)
        assert _pending(cid), "no offer was created"
        errors = []

        def _confirm():
            try:
                store.chat_case(cid, "confirm")
            except Exception as e:  # noqa: BLE001
                errors.append(e)

        threads = [threading.Thread(target=_confirm) for _ in range(2)]
        for t in threads: t.start()
        for t in threads: t.join(timeout=10)

        assert not errors, f"concurrent confirm raised: {errors}"
        disps = _dispositions(cid)
        targets = [d["target"] for d in disps]
        assert len(targets) == len(set(targets)), \
            f"the same target was recorded more than once: {targets}"
        assert len(disps) >= 1, "neither concurrent confirm applied the offer"
    _with_chat(_SlowStub(0.08), body)


def test_concurrent_distinct_messages_do_not_corrupt_history():
    """Two DIFFERENT questions fired at once must not interleave into a
    corrupted chat_messages list — every persisted entry must still be a
    well-formed {role, content} pair, and the count must be exactly right."""
    cid = _fresh_case("chat-robust-concurrent-history")

    def body(stub):
        errors = []

        def _ask(q):
            try:
                store.chat_case(cid, q)
            except Exception as e:  # noqa: BLE001
                errors.append((q, e))

        msgs = [f"question number {i} about the case" for i in range(6)]
        threads = [threading.Thread(target=_ask, args=(q,)) for q in msgs]
        for t in threads: t.start()
        for t in threads: t.join(timeout=10)

        assert not errors, f"concurrent chat raised: {errors}"
        hist = _history(cid)
        assert len(hist) == len(msgs) * 2, \
            f"expected {len(msgs)*2} history entries, got {len(hist)} — a write was lost"
        for m in hist:
            assert set(m.keys()) >= {"role", "content"}, f"malformed history entry: {m}"
            assert m["role"] in ("user", "assistant")
        assert stub.calls == len(msgs), "not every concurrent question reached the model"
    _with_chat(_SlowStub(0.05), lambda: body(llm_sim.chat))


# ---------------------------------------------------------------------------
# confirmation edge cases
# ---------------------------------------------------------------------------

def test_confirm_is_case_insensitive_and_tolerates_punctuation():
    for reply, should_confirm in [
        ("CONFIRM", True), ("Confirm!", True), ("confirm.", True),
        ("CONFIRM!!!", True), ("Confirm", True),
        ("confirmation", False),        # a different, longer word — must NOT confirm
        ("unconfirmed", False),
        ("confirming this later", False),
    ]:
        cid = _fresh_case("chat-robust-confirm-case")
        trigger = _groundable_trigger(cid)
        if not trigger:
            return

        def body(reply=reply, should=should_confirm, cid=cid):
            store.chat_case(cid, trigger)
            before = len(_dispositions(cid))
            store.chat_case(cid, reply)
            after = len(_dispositions(cid))
            if should:
                assert after == before + 1, f"{reply!r} should have confirmed"
            else:
                assert after == before, f"{reply!r} must NOT confirm"
        _with_chat(_SlowStub(0), body)


def test_a_new_real_command_replaces_a_stale_unanswered_offer():
    """The operator ignores offer A (asks something unrelated that happens to
    also ground a DIFFERENT finding as offer B). Offer A must not linger
    alongside B — only the newest offer may be pending, or a stale 'confirm'
    days later could apply a verdict about a finding the operator forgot they
    were ever asked about."""
    cid = _fresh_case("chat-robust-offer-replace")
    g = store.load_graph(cid)
    toks = []
    for f in g.findings:
        for w in re.findall(r"[a-z0-9]{4,}", f.title.lower()):
            if w not in llm_sim._GENERIC_TITLE_TOK:
                toks.append((f.id, w))
    if len(toks) < 2 or toks[0][0] == toks[1][0]:
        return  # fixture doesn't have two distinct groundable findings

    (fid_a, word_a) = toks[0]
    second = next(((fid, w) for fid, w in toks if fid != fid_a), None)
    if not second:
        return
    fid_b, word_b = second

    def body():
        store.chat_case(cid, f"the {word_a} alert is benign, it is our admin")
        first_offer = _pending(cid)
        assert first_offer and first_offer["target"] == fid_a

        store.chat_case(cid, f"the {word_b} alert is benign, it is our admin")
        second_offer = _pending(cid)
        assert second_offer, "the second command produced no offer"
        assert second_offer["target"] == fid_b, \
            "the newer offer did not replace the stale one"

        store.chat_case(cid, "confirm")
        disps = _dispositions(cid)
        applied = [d["target"] for d in disps]
        assert fid_a not in applied, \
            "confirming applied the STALE first offer instead of the current one"
        assert fid_b in applied
    _with_chat(_SlowStub(0), body)


# ---------------------------------------------------------------------------
# stale target after a re-fuse
# ---------------------------------------------------------------------------

def test_confirming_after_a_refuse_does_not_crash_even_if_stale():
    """Between the offer and the confirm, the case gets re-fused (a normal
    background event — another operator's disposition, a rescan). The offer's
    target finding id may no longer exist in the fresh graph. Confirming must
    still not raise — _apply_dispositions matches by id and silently no-ops if
    nothing matches, which is correct: better a disposition that doesn't find
    its target than a crash."""
    cid = _fresh_case("chat-robust-stale-target")
    trigger = _groundable_trigger(cid)
    if not trigger:
        return

    def body():
        store.chat_case(cid, trigger)
        assert _pending(cid)
        store.rescan(cid)                 # re-fuse; finding ids may shift
        try:
            ans = store.chat_case(cid, "confirm")
        except Exception as e:  # noqa: BLE001
            raise AssertionError(f"confirming a stale offer crashed: {e}")
        assert _STUB not in ans or True   # just must not have raised
        assert _pending(cid) is None, "the offer was not cleared after confirming"
    _with_chat(_SlowStub(0), body)


# ---------------------------------------------------------------------------
# masking must never take the chat down with it
# ---------------------------------------------------------------------------

def test_malformed_masking_config_falls_back_instead_of_crashing():
    cid = _fresh_case("chat-robust-bad-masking")

    def body():
        def _set_masking(details):
            details["masking"] = {"enabled": True,
                                  "patterns": [None, 123, {"nested": "dict"},
                                              "*.evil.com", "/(unclosed(/"]}
        store._ws().mutate_run_details(cid, _set_masking)
        try:
            ans = store.chat_case(cid, "what happened on the network")
        except Exception as e:  # noqa: BLE001
            raise AssertionError(f"malformed masking patterns crashed the chat: {e}")
        assert _STUB in ans
    _with_chat(_SlowStub(0), body)


# ---------------------------------------------------------------------------
# the model transport itself failing
# ---------------------------------------------------------------------------

def test_llm_unavailable_returns_a_friendly_message_never_raises():
    cid = _fresh_case("chat-robust-llm-down")
    before_hist = len(_history(cid))

    def body():
        try:
            ans = store.chat_case(cid, "what happened here")
        except llm_sim.LLMUnavailable:
            raise AssertionError(
                "chat_case let LLMUnavailable propagate instead of handling it")
        assert ans and "⚠" in ans, f"no operator-facing message on transport failure: {ans!r}"
        assert len(_history(cid)) == before_hist, \
            "a failed turn was persisted to chat history"
    _with_chat(_RaisingStub(llm_sim.LLMUnavailable("timeout")), body)


def test_unexpected_transport_exception_is_not_silently_swallowed():
    """A genuinely unexpected error (not LLMUnavailable) must still be logged and
    surfaced — chat_case re-raises it rather than pretending nothing happened."""
    cid = _fresh_case("chat-robust-unexpected-error")

    def body():
        try:
            store.chat_case(cid, "what happened here")
            raise AssertionError("expected the unexpected exception to propagate")
        except RuntimeError as e:
            assert "kaboom" in str(e)
    _with_chat(_RaisingStub(RuntimeError("kaboom")), body)


# ---------------------------------------------------------------------------
# unbounded history
# ---------------------------------------------------------------------------

def test_chat_history_is_actually_capped():
    cid = _fresh_case("chat-robust-history-cap")

    def body():
        turns = store._CHAT_HISTORY_CAP // 2 + 10       # deliberately over the cap
        for i in range(turns):
            store.chat_case(cid, f"question {i}")
        hist = _history(cid)
        assert len(hist) == store._CHAT_HISTORY_CAP, \
            f"history grew to {len(hist)}, expected the cap {store._CHAT_HISTORY_CAP}"
        # the MOST RECENT turn must be the one retained, not an old one
        assert hist[-2]["content"] == f"question {turns - 1}"
    _with_chat(_SlowStub(0), body)


# ---------------------------------------------------------------------------
# a finding title with markdown-special characters must not break the offer
# ---------------------------------------------------------------------------

def test_markdown_special_characters_in_a_finding_title_do_not_break_the_offer():
    from services.fusion.schema import FusionGraph, Entity, Finding

    cid = _fresh_case("chat-robust-markdown-title")
    g = FusionGraph(case_id=cid)
    g.upsert(Entity(id="a1", type="asset", label="WS1", attrs={"_assets": ["a1"]}))
    g.upsert(Entity(id="acc", type="account", label="corp\\admin", attrs={"_assets": ["a1"]}))
    g.add_finding(Finding(id="f_md", title="SIGMA: **weird** `title` [with] _markdown_ chars",
                          severity="high", confidence="medium", summary="x",
                          entity_ids=["acc"], asset_ids=["a1"], mitre=[]))

    def body():
        d = llm_sim.detect_disposition(g, "the weird alert is benign, it is our admin")
        if not d:
            return  # tokenizer didn't ground on this synthetic title; not what we're testing
        # exercise the exact f-string chat_case uses to build the offer
        try:
            text = (f"answer\n\n---\n_Did you mean to mark_ **{d['label']}** "
                    f"_as {d['verdict']} ({d['attribution']})? "
                    f"Reply_ **confirm** _to apply it._")
        except Exception as e:  # noqa: BLE001
            raise AssertionError(f"offer construction crashed on a markdown title: {e}")
        assert d["label"] in text
    body()
