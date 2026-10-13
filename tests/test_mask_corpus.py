"""Masking must hide every identifier AND leave every other word alone.

Masking a word the model needs ("we will monitor", a rule title, a version)
changes what it concludes, so over-masking is a bug as real as a leak. Each class
pins one finding of `scripts/dev/mask_eval.py corpus` (the full labelled stress
test, run inside the backend); this is its fast, deterministic-layer slice."""
import json
import os
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (_HERE, os.path.join(os.path.dirname(_HERE), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.data_anonymizer import DataAnonymizer  # noqa: E402
from services.fusion import llm_sim  # noqa: E402
from services.fusion.schema import Entity, FusionGraph  # noqa: E402


def _graph(*ents):
    g = FusionGraph(case_id="t")
    for i, (t, label, attrs, flags) in enumerate(ents):
        g.entities[f"{t}:{i}"] = Entity(id=f"{t}:{i}", type=t, label=label, attrs=attrs or {}, flags=flags or [])
    return g


def _ent(t, label, attrs=None, flags=None):
    return (t, label, attrs, flags)


def _mask(*ents):
    m = DataAnonymizer()
    llm_sim._build_mask_mapping(_graph(*ents), m)
    return m


def _json_masked(m, text):
    """The production shape: the payload is masked as json.dumps text."""
    return json.loads(llm_sim._apply_mask(json.dumps({"v": text}), m, ner=False))["v"]


class EscapeEndsAToken(unittest.TestCase):
    """json.dumps turns a newline into \\n and a Hebrew letter into \\u05dc, so the
    character before the name is a letter/digit and the boundary used to refuse it."""
    def test_glued_to_escapes_still_masked(self):
        m = _mask(_ent("account", "GALIL\\dana.levi"))
        for text in ("x\ndana.levi reset it", "x\tdana.levi", "נשלח לdana.levi", "GALIL%5Cdana.levi"):
            out = _json_masked(m, text)
            self.assertNotIn("dana.levi", out.lower(), (text, out))
        self.assertNotIn("dana.levi", llm_sim._apply_mask("x\ndana.levi", m, ner=False))

    def test_pseudonym_after_escape_reverts(self):
        m = _mask(_ent("account", "GALIL\\dana.levi"))
        masked = llm_sim._apply_mask(json.dumps({"v": "a\ndana.levi"}), m, ner=False)
        self.assertEqual("a\ndana.levi", json.loads(llm_sim._revert_mask(masked, m))["v"])

    def test_hebrew_survives(self):
        m = _mask(_ent("account", "GALIL\\dana.levi"), _ent("asset", "GL-WS-014"))
        text = "הערת אנליסט: המשתמש dana.levi התחבר מ-GL-WS-014 בשעה 08:14"
        out = _json_masked(m, text)
        for part in ("הערת אנליסט: המשתמש", "התחבר", "בשעה 08:14"):
            self.assertIn(part, out)
        self.assertNotIn("dana.levi", out)
        self.assertNotIn("GL-WS-014", out)


if __name__ == "__main__":
    unittest.main()
