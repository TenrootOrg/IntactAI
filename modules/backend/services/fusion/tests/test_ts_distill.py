"""Tests for _distill_ts_events — the TimeSketch tagged-event distiller.

A KAPE timeline can return thousands of tagged rows; this collapses them to at
most `per_tag` highest-anomaly events PER distinct tag, so every detection class
survives but the noisy ones are capped (keeps the 2500-entity graph signal-rich).

Run:  docker exec intact_backend python /app/services/fusion/tests/test_ts_distill.py
"""

import sys
if "/app" not in sys.path:
    sys.path.insert(0, "/app")

from services.fusion import store as S       # noqa: E402
from services.fusion import anomaly          # noqa: E402


def test_empty_and_none():
    assert S._distill_ts_events(None) == []
    assert S._distill_ts_events([]) == []


def test_non_dict_rows_skipped():
    assert S._distill_ts_events(["nope", 42, None]) == []


def test_per_tag_cap_applied():
    evs = [{"tag": ["logon-event"], "i": i} for i in range(10)]
    out = S._distill_ts_events(evs, per_tag=3)
    assert len(out) == 3


def test_distinct_tags_each_get_a_bucket():
    evs = ([{"tag": ["a"], "i": i} for i in range(2)] +
           [{"tag": ["b"], "i": i} for i in range(2)])
    out = S._distill_ts_events(evs, per_tag=5)
    assert len(out) == 4          # all kept (each tag under the cap)


def test_multi_tag_event_appears_once():
    e = {"tag": ["a", "b"], "i": 1}
    out = S._distill_ts_events([e], per_tag=5)
    assert out == [e]             # deduped by identity across its two tags


def test_scalar_tag_is_handled():
    out = S._distill_ts_events([{"tag": "single", "i": 1}], per_tag=5)
    assert len(out) == 1


def test_untagged_events_bucketed():
    out = S._distill_ts_events([{"i": 1}, {"i": 2}], per_tag=5)
    assert len(out) == 2          # fall into the _untagged bucket


def test_keeps_highest_anomaly_per_tag(monkeypatch=None):
    # Force a deterministic score = the event's "s" field, then assert the cap keeps
    # the top scorers. Patch the symbol the function imports (services.fusion.anomaly).
    saved = anomaly.score_row
    anomaly.score_row = lambda e: e.get("s", 0)
    try:
        evs = [{"tag": ["t"], "s": s} for s in (1, 9, 5, 7, 3)]
        out = S._distill_ts_events(evs, per_tag=2)
        kept = sorted(e["s"] for e in out)
        assert kept == [7, 9]     # the two highest
    finally:
        anomaly.score_row = saved


def test_score_failure_does_not_crash():
    saved = anomaly.score_row
    def boom(e):
        raise ValueError("bad row")
    anomaly.score_row = boom
    try:
        out = S._distill_ts_events([{"tag": ["t"], "i": 1}], per_tag=5)
        assert len(out) == 1      # scored 0 on failure, still kept
    finally:
        anomaly.score_row = saved


if __name__ == "__main__":
    import traceback
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn(); print(f"PASS {fn.__name__}")
        except Exception:
            failed += 1; print(f"FAIL {fn.__name__}"); traceback.print_exc()
    print(f"\n{len(fns)-failed}/{len(fns)} passed")
    sys.exit(1 if failed else 0)
