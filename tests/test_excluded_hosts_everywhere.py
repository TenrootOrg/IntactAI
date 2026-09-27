"""A host excluded in Configuration must be gone from every Case Analysis view.

Reported live: DESKTOP-16OJFO6 was excluded on a case and still showed in the Risk
tab and a timeframe card. The report and the Timeline applied the exclusion; the
other views read the unfiltered graph.
"""
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _src(rel):
    return open(os.path.join(ROOT, rel), encoding="utf-8").read()


def _body(src, start):
    i = src.index(start)
    j = src.find("\n@case_bp.route", i + 1)
    k = src.find("\ndef ", i + 1)
    ends = [x for x in (j, k) if x != -1]
    return src[i:min(ends) if ends else len(src)]


class EveryViewReadsTheFilteredGraph(unittest.TestCase):
    def test_routes(self):
        routes = _src("modules/backend/routes/case_routes.py")
        for fn in ("def get_case_risk(", "def get_zoom_targets("):
            body = _body(routes, fn)
            # get_zoom_targets delegates to store.scope_cards (shared with Jev's
            # scope estimate); that function is held to the same rule below.
            self.assertTrue("store.view_graph(" in body or "store.scope_cards(" in body, fn)
            self.assertNotIn("store.load_graph(", body, fn)

    def test_store_views(self):
        store = _src("modules/backend/services/fusion/store.py")
        for fn in ("def identity_view(", "def chat_case(", "def get_timeline(", "def scope_cards("):
            body = _body(store, fn)
            self.assertTrue("view_graph(" in body or "_filter_graph_by_hosts(" in body, fn)

    def test_chat_tools(self):
        self.assertNotIn("store.load_graph(case_id)\n        ",
                         _src("modules/backend/services/fusion/investigate.py").replace(
                             "_mask_for_case(d, store.load_graph(case_id)", ""))



class SharedFindingText(unittest.TestCase):
    """A finding shared with an excluded host named it in its text and so sent it
    to the model (found by tests/live_case_integration.py)."""

    def test_the_excluded_name_is_gone_and_the_stored_finding_untouched(self):
        import os as _os, sys as _sys
        _root = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
        for _p in (_os.path.join(_root, "tests"), _os.path.join(_root, "modules/backend")):
            if _p not in _sys.path:
                _sys.path.insert(0, _p)
        import _optional_deps  # noqa: F401
        from services.fusion import schema, store
        g = schema.FusionGraph(case_id="c")
        for h in ("ALCA01", "ALMECM01"):
            g.upsert(schema.Entity(id=f"asset:{h}", type="asset", label=h))
        f = schema.Finding(id="x", title="Account 'srv' used across 2 hosts", severity="high", confidence="h",
                           summary="executed on multiple assets (ALCA01, ALMECM01)",
                           asset_ids=["asset:ALCA01", "asset:ALMECM01"])
        g.findings = [f]
        v = store._filter_graph_by_hosts(g, ["almecm01"])
        self.assertEqual(len(v.findings), 1)
        self.assertNotIn("ALMECM01", v.findings[0].summary)
        self.assertIn("[excluded host]", v.findings[0].summary)
        self.assertEqual(v.findings[0].asset_ids, ["asset:ALCA01"])
        self.assertEqual(v.findings[0].id, "x")                     # verdicts still bind
        self.assertIn("ALMECM01", f.summary)                        # the stored graph is untouched

if __name__ == "__main__":
    unittest.main()
