"""Event identity is generic + per-identity + collection-independent.

The rule (operator): every module's data inserts unless it's the EXACT same
data — and "same" is per IDENTITY. Re-running an artifact (e.g.
Windows.Hayabusa.Rules) and getting the same line back must NOT create a
duplicate; the only thing that changed is when the artifact ran. The same line
on a DIFFERENT host must be kept.

This is enforced by keys.event_id anchoring on the ASSET + the event's own
content (NOT the collection run / run_id), identically for every mapper.
"""

import sys
if "/app" not in sys.path:
    sys.path.insert(0, "/app")

from services.fusion import keys  # noqa: E402

_TS = "2026-06-07T09:33:19"
_EVT = "sigma:Log File Cleared:1572"   # title + RecordID — a real Hayabusa line
_A = "asset:endpoint:C.aaa"
_B = "asset:endpoint:C.bbb"


def test_event_id_is_collection_independent():
    # Same event, same host — the id is identical no matter which collection run
    # produced it (event_id takes no run_id), so re-collecting collapses to one
    # node. The collection run/time can never appear in the key.
    e1 = keys.event_id(_A, _TS, _EVT)
    e2 = keys.event_id(_A, _TS, _EVT)
    assert e1 == e2, "same event must produce the same identity across runs"
    assert "run" not in e1.lower(), "the key must not carry a collection-run token"


def test_event_id_is_per_identity():
    # The SAME event on a DIFFERENT host stays a distinct node.
    assert keys.event_id(_A, _TS, _EVT) != keys.event_id(_B, _TS, _EVT)


def test_event_id_distinguishes_different_events():
    # A genuinely different event (different RecordID) on the same host is kept.
    assert keys.event_id(_A, _TS, "sigma:Log File Cleared:1572") != \
           keys.event_id(_A, _TS, "sigma:Log File Cleared:1573")


def test_event_id_distinguishes_event_time():
    # Different EVENT time (not collection time) = different event.
    assert keys.event_id(_A, "2026-06-07T09:33:19", _EVT) != \
           keys.event_id(_A, "2026-06-07T10:00:00", _EVT)
