"""Memory findings must land on the machine they came from.

The Risk table listed hosts called `memory_1790168052142` — run ids — sitting
beside DESKTOP-566AT85, which was the very same machine. The fuse keyed the
asset off `client_id or run_id`, and an uploaded or re-analysed image has no
client_id, so the run id became both the key and the label. Two consequences,
both bad: the operator sees a "host" that is not a host, and that node can
never merge with the Velociraptor collection for the real endpoint, so the
memory evidence sits apart from everything else known about it.

The graph has always known how to do this — `_resolve_host_assets` folds an
`asset:endpoint:host=<name>` node into the canonical client_id asset when the
hostnames match. The memory contribution simply never produced one.
"""

import ast
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STORE = os.path.join(ROOT, "modules/backend/services/fusion/store.py")
ROUTES = os.path.join(ROOT, "modules/backend/routes/memory_routes.py")


def _read(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as fh:
        return fh.read()


def _load(path, name, extra=None):
    with open(path, encoding="utf-8") as fh:
        src = fh.read()
    fn = next(n for n in ast.parse(src).body
              if isinstance(n, ast.FunctionDef) and n.name == name)
    ns = {"os": os, "Any": object}
    ns.update(extra or {})
    exec(compile(ast.get_source_segment(src, fn), path, "exec"), ns)
    return ns[name]


host_from_name = _load(ROUTES, "_host_from_dump_name")


class TestTheAssetIsKeyedByWhatWeActuallyKnow(unittest.TestCase):
    """Executes the key choice from _memory_contribution against each of the
    three states a memory run can be in."""

    @staticmethod
    def _key(client_id, client_name, rid="memory_123"):
        # The same ordering the contribution applies.
        cid = (client_id or "").strip()
        host = (client_name or "").strip() or None
        if cid:
            return f"asset:endpoint:{cid}"
        if host:
            return f"asset:endpoint:host={host.strip().lower()}"
        return f"asset:endpoint:{rid}"

    def test_an_acquisition_uses_the_velociraptor_client_id(self):
        """Same key that host's collection uses, so they are one node."""
        self.assertEqual(self._key("C.fe85a6ed0f357dc8", "DESKTOP-566AT85"),
                         "asset:endpoint:C.fe85a6ed0f357dc8")

    def test_an_upload_with_a_host_is_keyed_by_host(self):
        """That prefix is what _resolve_host_assets looks for."""
        self.assertEqual(self._key("", "DESKTOP-566AT85"),
                         "asset:endpoint:host=desktop-566at85")

    def test_only_a_run_with_no_host_at_all_falls_back_to_the_run_id(self):
        self.assertEqual(self._key("", ""), "asset:endpoint:memory_123")

    def test_the_contribution_implements_that_order(self):
        src = _read("modules/backend/services/fusion/store.py")
        blk = src[src.index("def _memory_contribution"):][:1800]
        self.assertIn("keys.asset_id(cid)", blk)
        self.assertIn("keys.asset_id_from_host(host)", blk)
        self.assertLess(blk.index("keys.asset_id(cid)"),
                        blk.index("keys.asset_id_from_host(host)"),
                        "a client_id must win over a hostname")

    def test_the_merge_target_prefix_is_the_one_the_graph_looks_for(self):
        """If keys.py and correlate.py ever disagree the merge silently stops
        happening and the duplicate host comes back."""
        keys_src = _read("modules/backend/services/fusion/keys.py")
        corr = _read("modules/backend/services/fusion/correlate.py")
        self.assertIn('f"asset:endpoint:host={norm_host(hostname)}"', keys_src)
        self.assertIn('a.id.startswith("asset:endpoint:host=")', corr)


class TestAReanalysisInheritsTheHostItCameFrom(unittest.TestCase):
    """Re-analysing a kept image is the same machine as the acquisition that
    captured it — the run that made the file knows exactly which."""

    SRC = _read("modules/backend/routes/memory_routes.py")

    def test_the_origin_is_consulted(self):
        blk = self.SRC[self.SRC.index("if dump_path and not (client_name and client_id):"):][:900]
        self.assertIn("_dump_origins().get(dump_path)", blk)
        self.assertIn('origin.get("client_name")', blk)
        self.assertIn('origin.get("client_id")', blk)

    def test_origins_carry_the_client_id(self):
        """Without it a re-analysis can only match by name, so it lands beside
        the host's collection instead of on it."""
        blk = self.SRC[self.SRC.index("def _dump_origins"):][:1500]
        self.assertIn('"client_id"', blk)

    def test_an_explicit_host_is_not_overwritten(self):
        blk = self.SRC[self.SRC.index("if dump_path and not (client_name and client_id):"):][:900]
        self.assertIn("client_name = client_name or", blk)


class TestTheFilenameIsTheLastResortNotTheRunId(unittest.TestCase):

    def test_an_acquisition_filename_gives_up_its_host(self):
        self.assertEqual(host_from_name("DESKTOP-566AT85-F.DAPQED9223N0Q.raw"),
                         "DESKTOP-566AT85")

    def test_a_hostname_containing_dashes_survives(self):
        self.assertEqual(host_from_name("WIN-UK1GV882OK6-F.ABC123.raw"),
                         "WIN-UK1GV882OK6")

    def test_an_ordinary_name_keeps_its_stem(self):
        self.assertEqual(host_from_name("MemoryDump_Lab6.raw"), "MemoryDump_Lab6")

    def test_every_accepted_extension_is_stripped(self):
        for ext in ("raw", "bin", "mem", "dmp", "dd", "zip", "RAW"):
            self.assertEqual(host_from_name(f"BOX.{ext}"), "BOX")

    def test_nothing_in_nothing_out(self):
        self.assertIsNone(host_from_name(""))
        self.assertIsNone(host_from_name(None))

    def test_the_upload_paths_use_it(self):
        self.assertIn("_host_from_dump_name(safe_name)",
                      _read("modules/backend/routes/memory_routes.py"))
        self.assertIn("_host_from_dump_name(original_filename)",
                      _read("modules/backend/routes/upload_routes.py"))

    def test_the_operator_can_name_the_host_on_the_upload_tab(self):
        self.assertIn("uploadHost", _read("modules/nginx/html/partials/memory.html"))
        js = _read("modules/nginx/html/js/memory.js")
        self.assertIn("client_name: (this.uploadHost || '').trim()", js)


if __name__ == "__main__":
    unittest.main(verbosity=2)
