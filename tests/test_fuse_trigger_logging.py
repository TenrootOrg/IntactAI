"""Every fuse must say what caused it, and a failed fuse must say it failed.

A fuse costs ~33s on a real case (measured: 9 hosts, 18,749 entities) and the log
used to open with a bare "Refusion · starting". An operator watching the box
spend half a minute could not tell whether they had caused it, a colleague had,
or something had run on its own -- and if it died, the log simply stopped at
whatever phase it reached, reading like a job still in progress.

Two failure modes these guard against, both of which cost real information:

  - a new fuse_case() call site added without a trigger, so one path in the
    product goes quiet again while the rest stay labelled;
  - the background paths going back to swallowing their outcome. watch_and_fuse
    wrapped its fuse in a bare `except: pass`, so an automatic fuse could vanish
    entirely, leaving the graph stale with no banner and nothing in the log.

Checked against the real source, with comments stripped, so prose describing the
intent can never satisfy an assertion.
"""

import ast
import os
import re
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STORE = os.path.join(ROOT, "modules/backend/services/fusion/store.py")
ROUTES = os.path.join(ROOT, "modules/backend/routes/case_routes.py")
CASES_HTML = os.path.join(ROOT, "modules/nginx/html/cases.html")

# Call sites that legitimately carry no trigger, with the reason.
#   _record=False -> the fuse writes NO log lines at all, so a label would have
#                    nowhere to appear (used to derive a baseline fingerprint).
_NO_TRIGGER_OK = ("_record=False",)


def _src(p):
    with open(p, encoding="utf-8") as f:
        return f.read()


def _code(src, node):
    """Source of a node with its docstring and comments removed."""
    body = list(getattr(node, "body", []))
    if (body and isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant)
            and isinstance(body[0].value.value, str)):
        body = body[1:]
    out = []
    for st in body:
        for line in (ast.get_source_segment(src, st) or "").splitlines():
            c = line.split("#", 1)[0]
            if c.strip():
                out.append(c)
    return "\n".join(out)


def _fn(tree, name):
    for n in ast.walk(tree):
        if isinstance(n, ast.FunctionDef) and n.name == name:
            return n
    return None


class TestEveryCallSiteIsLabelled(unittest.TestCase):

    def test_no_fuse_runs_anonymously(self):
        for path in (STORE, ROUTES):
            src = _src(path)
            tree = ast.parse(src)
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                fname = getattr(node.func, "attr", None) or getattr(node.func, "id", None)
                if fname != "fuse_case":
                    continue
                seg = ast.get_source_segment(src, node) or ""
                if any(x in seg for x in _NO_TRIGGER_OK):
                    continue
                self.assertIn(
                    "trigger=", seg,
                    "%s:%d fuse_case() with no trigger= — this fuse would log as "
                    "'an unlabelled caller'" % (os.path.basename(path), node.lineno))

    def test_the_fallback_label_is_visible_not_silent(self):
        """An unlabelled caller must be obvious in the log, not blend in."""
        src = _src(STORE)
        m = re.search(r'_TRIGGER_UNKNOWN\s*=\s*"([^"]+)"', src)
        self.assertIsNotNone(m, "_TRIGGER_UNKNOWN is gone")
        self.assertIn("unlabelled", m.group(1))


class TestTriggerVocabulary(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.src = _src(STORE)
        cls.consts = dict(re.findall(r'^(TRIGGER_\w+)\s*=\s*"([^"]*)"', cls.src, re.M))

    def test_manual_and_automatic_labels_both_exist(self):
        for name in ("TRIGGER_MANUAL_REFUSION", "TRIGGER_MANUAL_RESCAN",
                     "TRIGGER_AUTOMATIC_RUN_LANDED", "TRIGGER_AUTOMATIC_FIRST_VIEW"):
            self.assertIn(name, self.consts, name + " is missing")

    def test_automatic_triggers_announce_themselves(self):
        """The operator's first question is 'did I do that?' — answer it loudly."""
        for name, text in self.consts.items():
            if "AUTOMATIC" in name:
                self.assertIn("AUTOMATIC", text,
                              "%s does not say AUTOMATIC in the text operators read" % name)

    def test_manual_triggers_do_not_claim_to_be_automatic(self):
        for name, text in self.consts.items():
            if "MANUAL" in name:
                self.assertNotIn("AUTOMATIC", text)


class TestTheLogLinesCarryIt(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.src = _src(STORE)
        cls.tree = ast.parse(cls.src)

    def test_the_opening_line_names_the_trigger(self):
        code = _code(self.src, _fn(self.tree, "_fuse_case_locked"))
        i = code.find('"Refusion · starting"')
        self.assertNotEqual(i, -1, "the Refusion · starting line is gone")
        self.assertIn("trig", code[i:i + 300])

    def test_the_completion_line_names_the_trigger(self):
        code = _code(self.src, _fn(self.tree, "_fuse_case_locked"))
        i = code.find('"Refusion complete"')
        self.assertNotEqual(i, -1, "the Refusion complete line is gone")
        self.assertIn("trig", code[i:i + 400])

    def test_a_failed_fuse_is_logged_and_re_raised(self):
        code = _code(self.src, _fn(self.tree, "fuse_case"))
        self.assertIn('"Refusion failed"', code,
                      "a fuse that dies leaves the log ending mid-progress")
        self.assertIn("raise", code, "the failure must still reach the caller")

    def test_the_failure_names_where_it_died(self):
        code = _code(self.src, _fn(self.tree, "fuse_case"))
        self.assertIn("phase[", code, "the failure should name the phase reached")

    def test_fusion_busy_is_not_logged_as_a_failure(self):
        """Nothing was attempted — the route records it as deferred instead."""
        node = _fn(self.tree, "fuse_case")
        code = _code(self.src, node)
        busy = code.index("FusionBusy")
        failed = code.index('"Refusion failed"')
        self.assertLess(busy, failed,
                        "FusionBusy must be raised before the try that logs failures")


class TestBackgroundPathsDoNotSwallow(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.src = _src(STORE)
        cls.tree = ast.parse(cls.src)

    def test_watch_and_fuse_records_both_outcomes(self):
        code = _code(self.src, _fn(self.tree, "watch_and_fuse"))
        self.assertIn("Refusion skipped", code, "a busy skip must be recorded")
        self.assertIn("Refusion failed", code, "a failure must be recorded")

    def test_watch_and_fuse_has_no_bare_pass(self):
        node = _fn(self.tree, "watch_and_fuse")
        for h in ast.walk(node):
            if isinstance(h, ast.ExceptHandler):
                only_pass = len(h.body) == 1 and isinstance(h.body[0], ast.Pass)
                self.assertFalse(
                    only_pass,
                    "`except: pass` is back — an automatic fuse can vanish with the "
                    "graph left stale, no banner, and nothing in the log")

    def test_watch_and_fuse_labels_itself_automatic(self):
        code = _code(self.src, _fn(self.tree, "watch_and_fuse"))
        self.assertIn("TRIGGER_AUTOMATIC_RUN_LANDED", code)


class TestTheUiNamesTheButton(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.html = _src(CASES_HTML)
        cls.routes = _src(ROUTES)

    def test_both_buttons_identify_themselves(self):
        self.assertIn("cfg.trigger = 'refusion'", self.html)
        self.assertIn("cfg.trigger = 'rescan_llm'", self.html)

    def test_the_route_maps_them_to_real_constants(self):
        self.assertIn('"refusion": store.TRIGGER_MANUAL_REFUSION', self.routes)
        self.assertIn('"rescan_llm": store.TRIGGER_MANUAL_RESCAN', self.routes)

    def test_an_unknown_trigger_falls_back_rather_than_crashing(self):
        """An API caller sending nothing must not 500."""
        node = _fn(ast.parse(self.routes), "rescan")
        code = _code(self.routes, node)
        self.assertIn("_trigs.get(", code,
                      "use .get() so an absent/unknown trigger has a default")


if __name__ == "__main__":
    unittest.main(verbosity=2)
