"""Identity decisions made in the Identities tab reach the report, chat and correlation.

They were applied only by the tab: resolve_identities() was called with no overrides
everywhere else, so a switched-off account or a confirmed merge changed nothing the
model or the cross-host correlation saw.
"""
import os
import sys
import unittest

for _p in (os.path.dirname(os.path.abspath(__file__)),
           os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.fusion import identities, schema  # noqa: E402


def _graph():
    g = schema.FusionGraph(case_id="c")
    for aid, host in (("asset:endpoint:C.01", "HOSTA"), ("asset:endpoint:C.02", "HOSTB")):
        g.upsert(schema.Entity(id=aid, type="asset", label=host, attrs={"hostname": host}))
    g.upsert(schema.Entity(id="account:a:srv", type="account", label="srv",
                           attrs={"_assets": ["asset:endpoint:C.01"], "user": "srv"}))
    g.upsert(schema.Entity(id="account:b:srv", type="account", label="srv",
                           attrs={"_assets": ["asset:endpoint:C.02"], "user": "srv"}))
    return g


def _people(g):
    return sorted(sorted(a["id"] for a in p["accounts"]) for p in identities.resolve_identities(g))


class DecisionsApplyWithoutBeingPassed(unittest.TestCase):
    def test_no_decisions_attached_keeps_the_old_grouping(self):
        self.assertEqual(_people(_graph()), [["account:a:srv", "account:b:srv"]])

    def test_a_switched_off_account_is_its_own_person_for_the_report_too(self):
        g = _graph()
        g.identity_decisions = {"split:account:b:srv": {"id": "split:account:b:srv", "kind": "split",
                                                        "account_id": "account:b:srv"}}
        self.assertEqual(_people(g), [["account:a:srv"], ["account:b:srv"]])

    def test_the_tab_and_the_default_path_agree(self):
        g = _graph()
        dec = {"split:account:b:srv": {"id": "split:account:b:srv", "kind": "split",
                                       "account_id": "account:b:srv"}}
        g.identity_decisions = dec
        inp = identities.analyst_inputs(g, dec)
        explicit = identities.resolve_identities(g, merges=inp["merges"], splits=inp["splits"],
                                                 host_excludes=inp["host_excludes"])
        self.assertEqual(sorted(sorted(a["id"] for a in p["accounts"]) for p in explicit), _people(g))


if __name__ == "__main__":
    unittest.main()
