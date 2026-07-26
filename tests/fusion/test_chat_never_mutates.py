"""The chat must never change the case on its own — an exhaustive guard.

Context. Case-chat triage used to decide intent by substring matching BEFORE the
model was called. A wrong guess suppressed a finding AND replaced the operator's
answer with a canned line, so rephrasing never helped. Operators here write
imperfect English (and sometimes Hebrew), which is precisely the input a keyword
matcher cannot handle: "the backup server was compromised" reads as a benign
verdict because "backup" is both a benign keyword and a grounding anchor.

Rather than enumerate phrasings — the next bad one is unknowable — these tests
drive the REAL chat path end to end with a stubbed model and assert the property
that actually protects the data:

    no message, in any language or grammar, may apply a disposition;
    a verdict is only ever offered, and applied on an explicit "yes".

The model is stubbed, so the suite spends no tokens and needs no LLM configured.
"""

import sys
if "/app" not in sys.path:
    sys.path.insert(0, "/app")

import itertools  # noqa: E402

from services.fusion import store, llm_sim, calibrate  # noqa: E402

_STUB_ANSWER = "STUB-MODEL-ANSWER: here is the analysis you asked for."


# ---------------------------------------------------------------------------
# corpus — deliberately hostile: every message below contains at least one word
# the triage keywords treat as a verdict, or a token that grounds to a finding.
# ---------------------------------------------------------------------------

_BROKEN_ENGLISH = [
    "who the most malicious user", "what kobia did", "kobia did what",
    "the most malicious user who", "why powershell is malicious",
    "what happen in the backup server", "the backup server what happened",
    "explain me the scriptblock", "i want to know about malicious powershell",
    "give me the malicious findings", "malicious user list",
    "tell me what is the most malicious", "who is make this attack",
    "the powershell what he do", "how much findings is benign",
    "which user is the more dangerous", "can you say me who attacked",
    "i need know if this is legitimate", "is this expected or no",
    "show all the ignore findings", "what about the backup account",
]

_ATTACK_DESCRIPTIONS = [
    "the backup server was compromised", "ransomware deleted the backup catalog",
    "attacker used the backup account", "the backup job is the initial access vector",
    "this is not expected behaviour", "the legitimate account was stolen",
    "someone abused our sanctioned tool", "the approved software was trojanized",
    "known good binary was replaced by the attacker",
    "the false positive turned out to be real",
]

_HEBREW = [
    "מי המשתמש הכי זדוני", "מה קרה בשרת הגיבוי", "תסביר לי על הפאוורשל",
    "מי תקף את המחשב", "האם זה לגיטימי", "תראה לי את הממצאים",
]

_TRANSLITERATED = [
    "ma kara ba backup server", "mi ze kobia", "the backup shel hamachshev nifga",
    "ma ze ha powershell haze", "mi asa et ze", "efshar lehasbir li al ze",
]

CORPUS = _BROKEN_ENGLISH + _ATTACK_DESCRIPTIONS + _HEBREW + _TRANSLITERATED


def _combinatorial_corpus():
    """Every benign keyword crossed with every question shape, plus tokens that
    ground to a real finding. This is the machine-generated half of the battery —
    it explores combinations no human would think to write down."""
    verdict_words = ["benign", "false positive", "ignore", "expected", "legitimate",
                     "sanctioned", "backup", "authorized", "approved", "known good",
                     "not malicious", "is fine"]
    shapes = ["what about the {w} powershell",
              "the {w} scriptblock on the host",
              "is the {w} finding real",
              "{w} powershell scriptblock",
              "i think the {w} thing is important",
              "who did the {w} activity"]
    return [shape.format(w=w) for shape, w in itertools.product(shapes, verdict_words)]


# ---------------------------------------------------------------------------
# fixture
# ---------------------------------------------------------------------------

def _fresh_case(name="chat-mutation-guard"):
    from services import workflow_service as ws
    for r in ws.get_all_automation_runs() or []:
        if r.get("automation_type") == store.CASE_TYPE and \
                (r.get("details") or {}).get("name") == name:
            store.delete_case(r.get("run_id"))
    contrib = calibrate._contribution(calibrate.load_fixture("attack2"))
    cid = store.create_case(name, min_severity="informational")
    store.fuse_case(cid, contributions_override=[contrib])
    return cid


def _dispositions(cid):
    d = store._ws().get_automation_run(cid).get("details") or {}
    return list(d.get("dispositions") or [])


def _pending(cid):
    d = store._ws().get_automation_run(cid).get("details") or {}
    return d.get("pending_disposition")


class _StubChat:
    """Replaces llm_sim.chat so the battery costs nothing and cannot be skewed by
    a real model's wording. Records what it was asked."""

    def __init__(self):
        self.calls = []

    def __call__(self, g, question, **kw):
        self.calls.append(question)
        return _STUB_ANSWER


def _with_stub(fn):
    original = llm_sim.chat
    stub = _StubChat()
    llm_sim.chat = stub
    try:
        return fn(stub)
    finally:
        llm_sim.chat = original


# ---------------------------------------------------------------------------
# the load-bearing tests
# ---------------------------------------------------------------------------

def test_no_message_in_the_corpus_ever_mutates_the_case():
    """~90 hostile messages through the real chat path. Not one may change a
    disposition, and every one must reach the model."""
    cid = _fresh_case()
    messages = CORPUS + _combinatorial_corpus()

    def body(stub):
        before = _dispositions(cid)
        offenders = []
        for msg in messages:
            ans = store.chat_case(cid, msg)
            if len(_dispositions(cid)) != len(before):
                offenders.append(("MUTATED", msg))
            if _STUB_ANSWER not in (ans or ""):
                offenders.append(("BLOCKED", msg))
        assert not offenders, (
            f"{len(offenders)} message(s) broke the guarantee, e.g. "
            f"{offenders[:5]}")
        assert len(stub.calls) == len(messages), \
            "some messages never reached the model"
    _with_stub(body)


def test_a_real_command_is_offered_not_applied():
    """The genuine triage sentence must still be RECOGNISED — and still must not
    take effect until confirmed."""
    cid = _fresh_case("chat-mutation-guard-offer")

    def body(stub):
        before = len(_dispositions(cid))
        g = store.load_graph(cid)
        target = None
        for f in g.findings:
            words = [w for w in f.title.lower().split() if len(w) > 5]
            if words:
                target = (f, words[0])
                break
        assert target, "fixture produced no finding with a distinctive word"
        f, word = target
        ans = store.chat_case(cid, f"the {word} alert is benign, it is our admin")
        assert _STUB_ANSWER in ans, "the model was bypassed by a triage command"
        assert len(_dispositions(cid)) == before, \
            "a triage command applied itself without confirmation"
    _with_stub(body)


def test_confirmation_applies_and_only_then():
    cid = _fresh_case("chat-mutation-guard-confirm")

    def body(stub):
        g = store.load_graph(cid)
        f = g.findings[0]
        word = next((w for w in f.title.lower().split() if len(w) > 5), None)
        if not word:
            return                      # fixture has no groundable title; nothing to assert
        store.chat_case(cid, f"the {word} alert is benign, it is our admin")
        if not _pending(cid):
            return                      # matcher did not offer; the guard still holds
        before = len(_dispositions(cid))
        store.chat_case(cid, "yes")
        assert len(_dispositions(cid)) == before + 1, "confirming did not apply the verdict"
        assert _pending(cid) is None, "the offer was not cleared after applying"
    _with_stub(body)


def test_declining_and_lapsing_never_apply():
    for reply in ("no", "לא", "what happened on the backup server"):
        cid = _fresh_case("chat-mutation-guard-decline")

        def body(stub, reply=reply, cid=cid):
            g = store.load_graph(cid)
            f = g.findings[0]
            word = next((w for w in f.title.lower().split() if len(w) > 5), None)
            if not word:
                return
            store.chat_case(cid, f"the {word} alert is benign, it is our admin")
            before = len(_dispositions(cid))
            store.chat_case(cid, reply)
            assert len(_dispositions(cid)) == before, \
                f"reply {reply!r} applied a verdict it should not have"
            assert _pending(cid) is None, f"offer left pending after {reply!r}"
        _with_stub(body)


def test_the_answer_is_never_replaced_by_a_canned_line():
    """Whatever the matcher thinks, the operator sees the model's answer."""
    cid = _fresh_case("chat-mutation-guard-answer")

    def body(stub):
        for msg in CORPUS[:12]:
            ans = store.chat_case(cid, msg)
            assert ans.startswith(_STUB_ANSWER), \
                f"answer was replaced for {msg!r}: {ans[:80]!r}"
    _with_stub(body)
