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
            self.assertIn("store.view_graph(", body, fn)
            self.assertNotIn("store.load_graph(", body, fn)

    def test_store_views(self):
        store = _src("modules/backend/services/fusion/store.py")
        for fn in ("def identity_view(", "def chat_case(", "def get_timeline("):
            body = _body(store, fn)
            self.assertTrue("view_graph(" in body or "_filter_graph_by_hosts(" in body, fn)

    def test_chat_tools(self):
        self.assertNotIn("store.load_graph(case_id)\n        ",
                         _src("modules/backend/services/fusion/investigate.py").replace(
                             "_mask_for_case(d, store.load_graph(case_id)", ""))


if __name__ == "__main__":
    unittest.main()
