"""The version on screen must be the version that is RUNNING.

The sidebar read `Version: intact-20260903` on a box whose backend was a
hand-built image from main. Both were true and neither was the whole truth:
VERSION is stamped by the release installer and by nothing else, so a deployed
image never moves it. A support bundle from the same box said the same thing,
which is how a fix that WAS deployed can look like one that was not -- and it
cost a round trip working out whether a QA box had upgraded.

/api/version now reports the release AND the running backend image tag, and
`display` shows both only when they disagree, so an ordinary appliance stays
quiet. `version` keeps its old meaning exactly: the upgrade dropdown filters
releases on it and must never be handed a `main-*` tag.
"""

import ast
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (os.path.dirname(os.path.abspath(__file__)),
           os.path.join(ROOT, "modules", "backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

SRC = os.path.join(ROOT, "modules", "backend", "routes", "system_routes.py")


def _version_payload():
    """The real function, lifted out of the module.

    routes/system_routes.py imports flask at module scope and the offline suite
    runs on stdlib python only (tests/run_tests.sh), so the module cannot be
    imported here. version_payload takes no flask of its own -- the route is one
    line around it -- so compile just that function and call it.
    """
    tree = ast.parse(open(SRC, encoding="utf-8").read())
    fn = next((n for n in tree.body
               if isinstance(n, ast.FunctionDef) and n.name == "version_payload"), None)
    assert fn is not None, "version_payload has gone from system_routes.py"
    ns = {}
    exec(compile(ast.Module(body=[fn], type_ignores=[]), SRC, "exec"), ns)
    return ns["version_payload"]


def ask(version_file_text, backend_env, tmpdir):
    """The real decision, with a fake workdir and a chosen BACKEND_VERSION."""
    if version_file_text is not None:
        with open(os.path.join(tmpdir, "VERSION"), "w") as fh:
            fh.write(version_file_text)
    return _version_payload()(tmpdir, backend_env)


class AnOrdinaryAppliance(unittest.TestCase):
    """Release tree and running image agree — say it once."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.r = ask("intact-20260915\n", "intact-20260915", self.d)

    def test_the_release_is_reported(self):
        self.assertEqual("intact-20260915", self.r["version"])

    def test_the_display_is_just_the_release_with_no_noise(self):
        self.assertEqual("intact-20260915", self.r["display"])

    def test_it_is_not_flagged_as_a_hybrid(self):
        self.assertFalse(self.r["hybrid"])


class ADevBoxRunningAHandDeployedImage(unittest.TestCase):
    """This is the case that misled us: a 0903 tree running main's backend."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.r = ask("intact-20260903\n", "main-681652a3", self.d)

    def test_the_display_names_both(self):
        self.assertEqual("intact-20260903 (backend main-681652a3)", self.r["display"])

    def test_it_is_flagged_as_a_hybrid(self):
        self.assertTrue(self.r["hybrid"])

    def test_the_running_image_tag_is_reported_on_its_own(self):
        self.assertEqual("main-681652a3", self.r["backend"])

    def test_version_still_carries_ONLY_the_release(self):
        """The upgrade dropdown filters on this — a main-* tag there would let
        the operator 'upgrade' to something that is not a release."""
        self.assertEqual("intact-20260903", self.r["version"])


class WhenSomethingIsMissing(unittest.TestCase):

    def test_no_VERSION_file_reads_as_unknown_not_a_500(self):
        r = ask(None, "main-abc", tempfile.mkdtemp())
        self.assertEqual("unknown", r["version"])
        self.assertEqual("unknown (backend main-abc)", r["display"])

    def test_an_empty_VERSION_file_reads_as_unknown(self):
        r = ask("\n", "intact-20260915", tempfile.mkdtemp())
        self.assertEqual("unknown", r["version"])

    def test_no_BACKEND_VERSION_falls_back_to_the_release_alone(self):
        r = ask("intact-20260915\n", None, tempfile.mkdtemp())
        self.assertIsNone(r["backend"])
        self.assertFalse(r["hybrid"])
        self.assertEqual("intact-20260915", r["display"])


class TheRouteIsOnlyAWrapper(unittest.TestCase):

    def test_the_endpoint_returns_the_payload_unchanged(self):
        src = open(SRC, encoding="utf-8").read()
        self.assertIn("return jsonify(version_payload(", src,
                      "the route must hand back version_payload's dict as-is, or "
                      "these tests stop describing what the endpoint serves")


class TheSidebarRendersTheHonestOne(unittest.TestCase):

    def test_index_html_reads_display_first(self):
        src = open(os.path.join(ROOT, "modules/nginx/html/index.html")).read()
        self.assertIn("d.display || d.version", src,
                      "the sidebar must prefer `display`, or a hand-deployed "
                      "build keeps reading as a clean release")

    def test_the_upgrade_dropdown_still_filters_on_the_plain_release(self):
        src = open(os.path.join(ROOT, "modules/nginx/html/js/stores/settings.js")).read()
        self.assertIn("(d && d.version) ? d.version : ''", src,
                      "currentIntactVersion must stay the bare release string")


if __name__ == "__main__":
    unittest.main(verbosity=2)
