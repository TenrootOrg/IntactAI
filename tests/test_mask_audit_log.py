"""The masking audit log must not repeat itself.

Two real annoyances on a live report: (1) case variants of one value
(Attacked-WIN11 / attacked-win11) were listed twice though they map to the same
pseudonym; (2) the identity list was re-logged for every model call (report,
then checklist) sharing one mask. Both are log-only — masking is unchanged."""
import os
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (_HERE, os.path.join(os.path.dirname(_HERE), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.fusion import llm_sim  # noqa: E402


class _Mask:
    def __init__(self, mapping):
        self.mapping = mapping


class CaseVariantsCollapse(unittest.TestCase):
    def test_same_value_different_case_listed_once(self):
        out = llm_sim._mask_audit_lines({
            "Attacked-WIN11": "SAM7", "attacked-win11": "SAM7",
            "DESKTOP-2175T02": "Hostname1", "desktop-2175t02": "Hostname1"})
        self.assertEqual(1, out.count("SAM7"), out)
        self.assertEqual(1, out.count("Hostname1"), out)

    def test_distinct_pseudonyms_both_kept(self):
        # not a case variant — different pseudonyms for one person's forms stay.
        out = llm_sim._mask_audit_lines({"corp\\almogs": "USER1", "almogs": "SAM1"})
        self.assertIn("USER1", out)
        self.assertIn("SAM1", out)


class LoggedOncePerReport(unittest.TestCase):
    def test_second_call_on_same_mask_is_silent(self):
        from services.fusion import store
        logs = []
        orig = store.log_case_event
        store.log_case_event = lambda cid, act, lvl, msg, **kw: logs.append(act)
        try:
            m = _Mask({"host-a": "Hostname1", "almogs": "SAM1"})
            llm_sim._log_mask_audit("run1", m)     # logs
            llm_sim._log_mask_audit("run1", m)     # same mask, nothing new -> silent
        finally:
            store.log_case_event = orig
        self.assertEqual(1, len(logs), logs)


if __name__ == "__main__":
    unittest.main()
