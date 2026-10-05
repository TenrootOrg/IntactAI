"""Force regenerate: the analyst's way out of a report that looks stuck.

Asked for on 2026-10-05 after a slow model kept win11-test on "Generating the
report… running 14 min": keep the 600s per-call limit, but give the operator a
button. The real route function runs here with a fake store and request (Flask
is a container dependency): `force` retires the attempt in flight BEFORE a new
one starts, and without `force` nothing is retired — a busy case stays busy.
"""
import ast
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = open(os.path.join(ROOT, "modules/backend/routes/case_routes.py"), encoding="utf-8").read()


def route(store, body):
    tree = ast.parse(SRC)
    fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "regenerate_report"
              and any("/report\"" in ast.get_source_segment(SRC, d) and "POST" in ast.get_source_segment(SRC, d)
                      for d in n.decorator_list))
    fn.decorator_list = []
    ns = {"store": store, "jsonify": lambda d: d,
          "request": type("R", (), {"get_json": staticmethod(lambda silent=True: body)})()}
    exec(compile(ast.Module(body=[fn], type_ignores=[]), "case_routes.py", "exec"), ns)
    return ns["regenerate_report"]("case_1")


class FakeStore:
    class ReportGenerationBusy(Exception):
        pass

    def __init__(self, generating):
        self.generating, self.calls = generating, []

    def get_case(self, cid):
        return {"case_id": cid}

    def _retire_generation(self, cid, action, detail, gen_id=None):
        self.calls.append(("retire", action))
        self.generating = False
        return True

    def regenerate_report_async(self, cid, **kw):
        if self.generating:
            raise self.ReportGenerationBusy("a report is already being generated for this case")
        self.calls.append(("start", kw.get("use_llm")))
        return {"status": "started"}

    def log_case_event(self, *a, **k):
        self.calls.append(("log", a[1] if len(a) > 1 else ""))


class ForceRegenerate(unittest.TestCase):
    def test_force_retires_the_stuck_attempt_then_starts_a_new_one(self):
        st = FakeStore(generating=True)
        route(st, {"use_llm": True, "force": True})
        kinds = [c[0] for c in st.calls]
        self.assertEqual(kinds[:2], ["retire", "start"])
        self.assertIn("Force regenerate", st.calls[0][1])

    def test_without_force_a_busy_case_is_left_alone(self):
        st = FakeStore(generating=True)
        try:
            route(st, {"use_llm": True})
        except Exception:                      # the route's busy path may answer or raise
            pass
        self.assertNotIn("retire", [c[0] for c in st.calls])
        self.assertNotIn("start", [c[0] for c in st.calls])


if __name__ == "__main__":
    unittest.main()
