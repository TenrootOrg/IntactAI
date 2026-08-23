"""Two ways a background fuse could destroy an operator's work.

Both bugs are real on the code that preceded this file, and both were only ever
hard to hit because the single thing that triggers a fuse today is an operator
clicking Refusion -- and an operator does not tick checkboxes during their own
refusion. Anything that fuses on a schedule (or a second operator on the same
case) opens both windows at arbitrary moments.

  0a  disposition_checklist is the ONE details field that both the fuse and the
      operator write. _fuse_case_locked read it into a local at the TOP of the
      function, ran for ~33 s on a real case (measured: 9 hosts, 18,749
      entities), then blind-wrote that stale copy back in its bulk patch. A
      decision recorded in between was silently overwritten.

  0b  FusionBusy escaped as a 500 and was logged to the case activity log as
      "crashed". It is not a crash -- the request is well-formed and the case is
      merely busy -- so it must be a 409.

The store/route modules cannot be imported here (that pulls the whole backend,
and this suite is stdlib-only by design -- see run_tests.sh). So each fix is
covered twice: the SEMANTICS are proven behaviourally against a model of both
the old and the new shape, and the real files are then checked statically to
confirm they actually use the new shape. The behavioural half is what keeps the
static half honest: it fails if the model of the bug is wrong.
"""

import ast
import copy
import os
import re
import threading
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STORE = os.path.join(ROOT, "modules/backend/services/fusion/store.py")
ROUTES = os.path.join(ROOT, "modules/backend/routes/case_routes.py")


def _src(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def _code_only(src, node):
    """A function's source with its docstring and every comment removed.

    Assertions in this file are about what the code DOES. Matching raw source
    lets prose decide the verdict in both directions -- a comment mentioning the
    old behaviour can fail a correct fix, and a comment describing the intent can
    pass a missing one. Both have happened in this repo.
    """
    body = list(node.body)
    if (body and isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant)
            and isinstance(body[0].value.value, str)):
        body = body[1:]                      # drop the docstring
    out = []
    for stmt in body:
        seg = ast.get_source_segment(src, stmt) or ""
        for line in seg.splitlines():
            code = line.split("#", 1)[0] if not _in_string(line) else line
            if code.strip():
                out.append(code)
    return "\n".join(out)


def _in_string(line):
    """Crude but sufficient: only skip comment-stripping when a '#' sits inside
    quotes on that line (none of the code checked here does, but a URL or a
    format string would otherwise be truncated mid-assertion)."""
    before = line.split("#", 1)[0]
    return before.count('"') % 2 == 1 or before.count("'") % 2 == 1


def _fn(tree, name):
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    return None


# ---------------------------------------------------------------------------
# 0a -- semantics: a locked fill-if-empty survives a concurrent tick; the old
#       snapshot-then-blind-write does not.
# ---------------------------------------------------------------------------

class _CaseRow:
    """The details dict plus the per-run lock that mutate_run_details holds."""

    def __init__(self, details=None):
        self.details = dict(details or {})
        self._lock = threading.Lock()

    def mutate(self, fn):
        """workflow_service.mutate_run_details: read + mutate + write under ONE lock."""
        with self._lock:
            fn(self.details)

    def merge(self, patch):
        """update_run_status(details=patch): merges keys, but the VALUES were
        computed by the caller from a snapshot taken earlier."""
        with self._lock:
            self.details.update(patch)


def _tick(row, item_id):
    """store.decide_checklist_item -- the operator's write."""
    def _m(details):
        for it in details.get("disposition_checklist") or []:
            if it.get("id") == item_id:
                it["status"] = "accepted"
    row.mutate(_m)


def _run_fuse(row, shape, generated, operator_acts):
    """One fuse, with the operator acting in the middle of it.

    `operator_acts` is called at the exact point the real fuse is busy building
    the graph -- i.e. after it has read the case row and before it persists.
    Sequenced with events rather than sleeps so the test is deterministic.
    """
    # get_case() deserialises the row's JSON out of SQLite, so the fuse holds a
    # genuine DEEP copy. Modelling it with dict() would share the item dicts with
    # the live row, the operator's in-place tick would appear in the "stale" copy,
    # and the bug would look fixed when it is not.
    snapshot = copy.deepcopy(row.details)     # d = get_case(case_id), at the top

    if shape == "old":
        checklist = snapshot.get("disposition_checklist")
        if not checklist:
            checklist = generated
        operator_acts()                        # ~33 s of graph building happens here
        row.merge({"report_dirty": True, "disposition_checklist": checklist})
    elif shape == "new":
        fresh = generated if not snapshot.get("disposition_checklist") else None
        operator_acts()
        row.merge({"report_dirty": True})
        if fresh:
            row.mutate(lambda d: d.__setitem__(
                "disposition_checklist",
                (d.get("disposition_checklist") or []) or fresh))
    else:                                      # pragma: no cover
        raise AssertionError(shape)


def _statuses(row):
    return [it.get("status") for it in row.details.get("disposition_checklist") or []]


class TestChecklistLostUpdate(unittest.TestCase):

    def _row_with_checklist(self):
        return _CaseRow({"disposition_checklist": [
            {"id": "q1", "status": "pending", "finding_id": "f1"},
            {"id": "q2", "status": "pending", "finding_id": "f2"},
        ]})

    def test_the_old_shape_loses_the_tick(self):
        """Non-vacuity: if this ever passes, the bug being fixed was not real."""
        row = self._row_with_checklist()
        _run_fuse(row, "old", generated=[], operator_acts=lambda: _tick(row, "q1"))
        self.assertEqual(_statuses(row), ["pending", "pending"],
                         "expected the old shape to overwrite the operator's tick")

    def test_the_new_shape_keeps_the_tick(self):
        row = self._row_with_checklist()
        _run_fuse(row, "new", generated=[], operator_acts=lambda: _tick(row, "q1"))
        self.assertEqual(_statuses(row), ["accepted", "pending"])

    def test_the_new_shape_still_fills_an_empty_checklist(self):
        """The fix must not stop a first fuse from generating one."""
        row = _CaseRow({})
        gen = [{"id": "q1", "status": "pending"}]
        _run_fuse(row, "new", generated=gen, operator_acts=lambda: None)
        self.assertEqual(_statuses(row), ["pending"])

    def test_a_generated_checklist_never_replaces_an_existing_one(self):
        """Two fuses racing: the loser must not clobber the winner's list."""
        row = _CaseRow({})
        first = [{"id": "a", "status": "accepted"}]
        second = [{"id": "b", "status": "pending"}]
        _run_fuse(row, "new", generated=first, operator_acts=lambda: None)
        # second fuse decided to generate from an empty snapshot, then lands late
        row.mutate(lambda d: d.__setitem__(
            "disposition_checklist", (d.get("disposition_checklist") or []) or second))
        self.assertEqual([it["id"] for it in row.details["disposition_checklist"]], ["a"])

    def test_a_failed_generation_writes_nothing(self):
        """generate_disposition_checklist raising must not stamp an empty list."""
        row = _CaseRow({})
        _run_fuse(row, "new", generated=None, operator_acts=lambda: None)
        self.assertNotIn("disposition_checklist", row.details)

    def test_the_tick_survives_under_real_thread_interleaving(self):
        """The model above sequences by hand; this one uses actual threads."""
        row = self._row_with_checklist()
        read_done, tick_done = threading.Event(), threading.Event()

        def fuse():
            snapshot = copy.deepcopy(row.details)
            fresh = None if snapshot.get("disposition_checklist") else [{"id": "x"}]
            read_done.set()
            tick_done.wait(5)
            row.merge({"report_dirty": True})
            if fresh:
                row.mutate(lambda d: d.__setitem__(
                    "disposition_checklist",
                    (d.get("disposition_checklist") or []) or fresh))

        def operator():
            read_done.wait(5)
            _tick(row, "q2")
            tick_done.set()

        t1, t2 = threading.Thread(target=fuse), threading.Thread(target=operator)
        t1.start(); t2.start(); t1.join(5); t2.join(5)
        self.assertEqual(_statuses(row), ["pending", "accepted"])


# ---------------------------------------------------------------------------
# 0a -- wiring: store.py must actually use the new shape.
# ---------------------------------------------------------------------------

class TestChecklistWiring(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.src = _src(STORE)
        cls.tree = ast.parse(cls.src)

    def _fuse_fn(self):
        for node in ast.walk(self.tree):
            if isinstance(node, ast.FunctionDef) and node.name == "_fuse_case_locked":
                return node
        self.fail("_fuse_case_locked not found -- was it renamed?")

    def test_the_bulk_patch_does_not_carry_the_checklist(self):
        """The whole bug: a stale value riding along in update_run_status(details=)."""
        for node in ast.walk(self._fuse_fn()):
            if not isinstance(node, ast.Call):
                continue
            if getattr(node.func, "attr", None) != "update_run_status":
                continue
            for kw in node.keywords:
                if kw.arg != "details" or not isinstance(kw.value, ast.Dict):
                    continue
                keys = [k.value for k in kw.value.keys
                        if isinstance(k, ast.Constant)]
                self.assertNotIn(
                    "disposition_checklist", keys,
                    "the checklist is back in the bulk patch -- it is computed from a "
                    "snapshot read ~33 s earlier and will overwrite operator decisions")

    def test_the_checklist_is_written_through_the_locked_helper(self):
        body = ast.get_source_segment(self.src, self._fuse_fn()) or ""
        self.assertIn('_mutate_list_field(case_id, "disposition_checklist"', body,
                      "the fuse must persist the checklist under the run lock")

    def test_the_write_only_fills_an_empty_checklist(self):
        """`cur or fresh` is what preserves operator decisions -- not decoration."""
        body = ast.get_source_segment(self.src, self._fuse_fn()) or ""
        m = re.search(r'_mutate_list_field\(case_id,\s*"disposition_checklist",\s*'
                      r'lambda (\w+): \1 or (\w+)\)', body)
        self.assertIsNotNone(
            m, "expected a fill-if-empty mutator (lambda cur: cur or <fresh>)")

    def test_generation_is_still_skipped_when_one_exists(self):
        body = ast.get_source_segment(self.src, self._fuse_fn()) or ""
        self.assertIn('if not d.get("disposition_checklist"):', body,
                      "an existing checklist must not be regenerated on every fuse")

    def test_mutate_list_field_reads_and_writes_under_one_lock(self):
        """The helper the fix leans on must not itself be a snapshot-then-write."""
        node = _fn(self.tree, "_mutate_list_field")
        self.assertIsNotNone(node, "_mutate_list_field not found")
        code = _code_only(self.src, node)
        self.assertIn("mutate_run_details", code)
        self.assertNotIn("get_case(", code,
                         "an unlocked read is back inside the helper the fix relies on")


# ---------------------------------------------------------------------------
# 0c -- Rescan must not destroy the report it is about to rebuild.
#
# rescan() wrote `report_md = ""` to force a rebuild and only THEN called
# fuse_case. The blanking happened outside the fuse lock, so when the case was
# already fusing, the FusionBusy raised inside fuse_case left the report erased
# with nothing left to regenerate it -- the operator saw an error and the
# narrative was simply gone. Found by hitting the window on a live case: the
# report went from 75,402 chars to 0. The generator was never at fault; asked
# again afterwards it produced 75,270 chars from the same graph.
# ---------------------------------------------------------------------------

def _rescan(row, shape, busy, generated="NEW REPORT"):
    """One rescan against a case that may already be fusing."""
    class Busy(RuntimeError):
        pass

    if shape == "old":
        row.merge({"report_md": ""})            # blank FIRST, outside the lock
        if busy:
            raise Busy("a fuse is already running for this case")
        row.merge({"report_md": generated})
    elif shape == "new":
        if busy:                                # the lock is taken inside fuse_case
            raise Busy("a fuse is already running for this case")
        row.merge({"report_md": generated})     # nothing cleared until we have a replacement
    else:                                       # pragma: no cover
        raise AssertionError(shape)


class TestRescanDoesNotDestroyTheReport(unittest.TestCase):

    def _row(self):
        return _CaseRow({"report_md": "THE OPERATOR'S REPORT"})

    def test_the_old_shape_erases_the_report_when_busy(self):
        """Non-vacuity: this is the data loss that was actually observed."""
        row = self._row()
        with self.assertRaises(RuntimeError):
            _rescan(row, "old", busy=True)
        self.assertEqual(row.details["report_md"], "",
                         "expected the old shape to leave the report erased")

    def test_the_new_shape_keeps_the_report_when_busy(self):
        row = self._row()
        with self.assertRaises(RuntimeError):
            _rescan(row, "new", busy=True)
        self.assertEqual(row.details["report_md"], "THE OPERATOR'S REPORT")

    def test_the_new_shape_still_rebuilds_when_not_busy(self):
        """The fix must not turn Rescan into a no-op -- rebuilding IS the point."""
        row = self._row()
        _rescan(row, "new", busy=False)
        self.assertEqual(row.details["report_md"], "NEW REPORT")


class TestRescanWiring(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.src = _src(STORE)
        cls.tree = ast.parse(cls.src)

    def test_rescan_does_not_blank_the_report_first(self):
        node = _fn(self.tree, "rescan")
        self.assertIsNotNone(node, "rescan() not found")
        code = _code_only(self.src, node)
        self.assertNotIn('"report_md": ""', code,
                         "rescan blanks the report before taking the fuse lock again")

    def test_rescan_asks_for_the_rebuild_through_the_flag(self):
        code = _code_only(self.src, _fn(self.tree, "rescan"))
        self.assertIn("force_report=True", code)

    def test_both_fuse_entry_points_accept_the_flag(self):
        for name in ("fuse_case", "_fuse_case_locked"):
            node = _fn(self.tree, name)
            self.assertIsNotNone(node, name + " not found")
            names = [a.arg for a in node.args.kwonlyargs] + [a.arg for a in node.args.args]
            self.assertIn("force_report", names, name + " does not accept force_report")

    def test_fuse_case_forwards_the_flag(self):
        """A silently dropped kwarg would make Rescan stop rebuilding entirely."""
        code = _code_only(self.src, _fn(self.tree, "fuse_case"))
        self.assertIn("force_report=force_report", code)

    def test_the_report_branch_honours_the_flag(self):
        code = _code_only(self.src, _fn(self.tree, "_fuse_case_locked"))
        self.assertIn('if d.get("report_md") and not force_report:', code)

    def test_regenerate_report_writes_only_after_generating(self):
        """The same hazard one door along: it must never clear then generate."""
        node = _fn(self.tree, "regenerate_report")
        if node is None:
            self.skipTest("regenerate_report not found")
        code = _code_only(self.src, node)
        self.assertNotIn('"report_md": ""', code)


# ---------------------------------------------------------------------------
# 0b -- FusionBusy must be a 409, on every route rather than one.
# ---------------------------------------------------------------------------

class TestFusionBusyHandler(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.src = _src(ROUTES)
        cls.tree = ast.parse(cls.src)

    def _handler(self):
        for node in ast.walk(self.tree):
            if not isinstance(node, ast.FunctionDef):
                continue
            for dec in node.decorator_list:
                if not isinstance(dec, ast.Call):
                    continue
                if getattr(dec.func, "attr", None) != "errorhandler":
                    continue
                arg = dec.args[0] if dec.args else None
                if getattr(arg, "attr", None) == "FusionBusy":
                    return node
        return None

    def test_a_blueprint_level_handler_exists(self):
        self.assertIsNotNone(
            self._handler(),
            "no @case_bp.errorhandler(store.FusionBusy) -- a busy case would fall "
            "through to the catch-all and return 500")

    def test_it_returns_409_and_flags_busy(self):
        code = _code_only(self.src, self._handler())
        self.assertIn("409", code)
        self.assertIn('"busy": True', code)
        self.assertNotIn("500", code, "the busy handler must not return 500")

    def test_it_is_registered_on_the_same_blueprint_as_the_catch_all(self):
        """Flask prefers the most specific class in the MRO, but only among the
        handlers registered on the SAME blueprint -- a mismatch here silently
        hands every busy response back to the catch-all."""
        def owner(fn_name, exc_attr):
            for node in ast.walk(self.tree):
                if not (isinstance(node, ast.FunctionDef) and node.name == fn_name):
                    continue
                for dec in node.decorator_list:
                    if isinstance(dec, ast.Call) and getattr(dec.func, "attr", None) == "errorhandler":
                        return getattr(dec.func.value, "id", None)
            return None
        self.assertEqual(owner("_case_busy", "FusionBusy"),
                         owner("_audit_case_exception", "Exception"))

    def test_no_route_builds_its_own_busy_response(self):
        """One shape for this response, so the front-end has one thing to handle.

        Catching FusionBusy locally is allowed -- the read-only /graph endpoint
        opportunistically fuses a case that has none yet, and a READ should not
        fail just because a write holds the lock; it recovers by returning what it
        has. What must not come back is a route inventing its own status code and
        body, which is how /rescan drifted apart from every other route in the
        first place. So the rule is narrower than "never catch it": a local
        handler must not RETURN a response.
        """
        for node in ast.walk(self.tree):
            if not isinstance(node, ast.ExceptHandler):
                continue
            names = ([node.type] if not isinstance(node.type, ast.Tuple)
                     else list(node.type.elts))
            if not any(getattr(n, "attr", None) == "FusionBusy" for n in names):
                continue
            for inner in ast.walk(node):
                self.assertNotIsInstance(
                    inner, ast.Return,
                    "a route is shaping its own FusionBusy response again (line %d) "
                    "-- let the blueprint handler do it so every route agrees"
                    % node.lineno)

    def test_the_catch_all_still_returns_500_for_everything_else(self):
        """Guard against 'fixing' the 500 by making the catch-all lenient."""
        for node in ast.walk(self.tree):
            if isinstance(node, ast.FunctionDef) and node.name == "_audit_case_exception":
                self.assertIn("500", _code_only(self.src, node))
                return
        self.fail("_audit_case_exception not found")


# ---------------------------------------------------------------------------
# 0b -- the Flask assumption the fix rests on, checked against real Flask.
# ---------------------------------------------------------------------------

try:
    from flask import Blueprint, Flask, jsonify
    _HAVE_FLASK = True
except ImportError:                                   # dev box / CI: stdlib only
    _HAVE_FLASK = False


@unittest.skipUnless(_HAVE_FLASK, "flask not installed (runs in intact_backend)")
class TestFlaskPrefersTheSpecificHandler(unittest.TestCase):
    """If Flask ever resolved to the catch-all first, the fix would be a no-op
    and nothing else in this file would notice."""

    def setUp(self):
        class Busy(RuntimeError):
            pass
        self.Busy = Busy
        bp = Blueprint("t", __name__)

        @bp.errorhandler(Exception)
        def _catch_all(e):
            return jsonify({"error": str(e)}), 500

        @bp.errorhandler(Busy)
        def _busy(e):
            return jsonify({"error": str(e), "busy": True}), 409

        @bp.route("/busy")
        def _r_busy():
            raise Busy("a fuse is already running for this case")

        @bp.route("/boom")
        def _r_boom():
            raise ValueError("something genuinely broke")

        app = Flask(__name__)
        app.register_blueprint(bp)
        self.client = app.test_client()

    def test_busy_resolves_to_409(self):
        r = self.client.get("/busy")
        self.assertEqual(r.status_code, 409)
        self.assertTrue(r.get_json().get("busy"))

    def test_other_errors_still_resolve_to_500(self):
        self.assertEqual(self.client.get("/boom").status_code, 500)


if __name__ == "__main__":
    unittest.main(verbosity=2)
