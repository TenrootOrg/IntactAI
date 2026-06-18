"""End-to-end time filtering — per-artifact collection params (token savings at the
source) + the fusion window cutting the distilled payload.
"""

import sys
import json
if "/app" not in sys.path:
    sys.path.insert(0, "/app")

from services.agentic.collectors import build_artifact_spec  # noqa: E402
from services.fusion import calibrate, render, budget  # noqa: E402

WIN = {"enabled": True, "mode": "between",
       "start_datetime": "2026-06-18T00:00:00Z", "end_datetime": "2026-06-19T00:00:00Z"}


def test_hayabusa_gets_date_and_level_params():
    spec = build_artifact_spec(["Windows.Hayabusa.Rules", "Windows.System.Pslist"],
                               {"time_filter": WIN, "min_severity": "medium"})
    assert "DateAfter='2026-06-18T00:00:00Z'" in spec
    assert "DateBefore='2026-06-19T00:00:00Z'" in spec
    assert "RuleLevel='medium'" in spec
    assert "`Windows.System.Pslist`=dict()" in spec, "non-allow-listed artifact stays empty"


def test_no_window_is_noop():
    assert build_artifact_spec(["Windows.Hayabusa.Rules"], {}) == "`Windows.Hayabusa.Rules`=dict()"


def test_severity_below_medium_omits_rule_level():
    spec = build_artifact_spec(["Windows.Hayabusa.Rules"],
                               {"time_filter": WIN, "min_severity": "informational"})
    assert "RuleLevel" not in spec and "DateAfter" in spec


def test_operator_override_wins():
    spec = build_artifact_spec(["Windows.Hayabusa.Rules"],
                               {"time_filter": WIN, "min_severity": "medium",
                                "artifact_params": {"Windows.Hayabusa.Rules": {"RuleLevel": "high"}}})
    assert "RuleLevel='high'" in spec and "RuleLevel='medium'" not in spec


def test_vql_quote_escapes():
    spec = build_artifact_spec(["Windows.Hayabusa.Rules"],
                               {"artifact_params": {"Windows.Hayabusa.Rules": {"X": "a'b"}}})
    assert "\\'" in spec, "single quotes in a param value must be escaped"


def test_window_reduces_distilled_tokens():
    # the fusion window cuts the LLM payload (the other half of the token saving)
    g = calibrate.fuse("attack2")
    full = budget.approx_tokens(render.distilled(g))
    windowed = budget.approx_tokens(render.distilled(
        g, window={"start": "2026-06-18T17:50:00Z", "end": "2026-06-18T18:20:00Z"}))
    assert windowed <= full, "windowing must not increase the distilled payload"


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
