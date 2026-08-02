"""A memory run with no evidence must not be fetched from VolWeb.

Found by the QA harness. A cancelled memory run is still a member of the case,
and its details carry `evidence_id: None`. Fusion passed that straight into
`/api/evidence/{evid}/plugins/`, requesting the literal path
`/api/evidence/None/plugins/`, which 404s — and the 404's HTML body was then
surfaced verbatim as a case warning:

    fuse: run memory_... (memory) skipped: GET /api/evidence/None/plugins/
    -> HTTP 404: <!doctype html><html ...

So a run that simply had nothing to contribute read like a VolWeb outage. The
graph was fine; the warning was noise that would send someone to debug a
healthy service.

Run: python3 tests/test_fusion_skips_evidenceless_memory.py
"""

import os
import re
import sys

REPO = os.environ.get("INTACT_PATH") or os.path.dirname(
    os.path.dirname(os.path.abspath(__file__)))
STORE = os.path.join(REPO, "modules", "backend", "services", "fusion", "store.py")


def _source():
    with open(STORE, encoding="utf-8") as fh:
        return fh.read()


def _memory_contribution_body():
    src = _source()
    start = src.index("def _memory_contribution(")
    nxt = src.find("\ndef ", start + 1)
    return src[start:nxt if nxt != -1 else len(src)]


def _strip_comments(body):
    """The guard's own comment explains the bug and names the bad path, so a
    naive search would match the documentation rather than the code."""
    body = re.sub(r'""".*?"""', "", body, flags=re.S)
    return "\n".join(l for l in body.splitlines()
                     if not l.lstrip().startswith("#"))


def test_the_evidence_id_is_checked_before_use():
    code = _strip_comments(_memory_contribution_body())
    assert re.search(r"if\s+not\s+evid\b", code), \
        "evidence_id is used without a falsy check; a cancelled memory run " \
        "will request /api/evidence/None/plugins/ again"


def test_the_volweb_client_is_not_built_when_there_is_no_evidence():
    """Constructing the client is harmless, but calling it is not — the guard
    has to sit BEFORE the fetch, not after."""
    code = _strip_comments(_memory_contribution_body())
    guard = code.find("if not evid")
    # The CALL, not the name — `_build_plugin_payload` also appears in the
    # `from ... import` line above the guard, and matching that reported the
    # fetch as happening first when it does not.
    fetch = code.find("_build_plugin_payload(client")
    assert guard != -1 and fetch != -1, "guard or fetch missing"
    assert guard < fetch, \
        "the evidence_id guard runs after the VolWeb fetch, so the doomed " \
        "request still happens"


def test_the_function_still_returns_through_map_memory():
    """The guard must fall through rather than return early: the caller expects
    whatever map_memory produces, and an early `return [], []` would hand back
    a tuple instead."""
    body = _memory_contribution_body()
    code = _strip_comments(body)
    guard_at = code.find("if not evid")
    tail = code[guard_at:]
    early = re.search(r"^\s{8}return (?!map_memory)", tail, re.M)
    assert not early, \
        f"the guard returns early ({early.group(0).strip()!r}); it must fall " \
        f"through so the asset anchor is still built and the return shape holds"
    assert "return map_memory(" in code, \
        "_memory_contribution no longer returns through map_memory"


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
