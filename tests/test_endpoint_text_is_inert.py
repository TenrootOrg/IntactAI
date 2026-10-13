"""Text an endpoint or an operator controls must stay data.

1. The client picker put endpoint-reported OS/label text into the page raw, and
   escapeHtml left quotes alone, so a hostname could close an attribute and add an
   event handler. tests/client_picker_endpoint_text.js renders the real picker in
   jsdom with a booby-trapped host (it created an <img onerror> before the fix).
2. A scheduled hunt spliced the job name into a single-quoted VQL string: a ' in
   the name ended it and the rest ran as server-side VQL.
"""
import os
import shutil
import subprocess
import sys
import types
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (os.path.join(ROOT, "tests"), os.path.join(ROOT, "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: E402



def _load_executor():
    """executor.py on its own: the scheduler package's __init__ needs apscheduler
    and opens the database, neither of which this test is about."""
    import importlib.util
    path = os.path.join(ROOT, "modules/backend/services/scheduler/executor.py")
    spec = importlib.util.spec_from_file_location("intact_test_executor", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class ClientPickerShowsEndpointTextAsText(unittest.TestCase):
    @unittest.skipIf(shutil.which("node") is None, "node is not installed")
    def test_booby_trapped_host_os_and_label(self):
        r = subprocess.run(["node", os.path.join(ROOT, "tests", "client_picker_endpoint_text.js"), ROOT],
                           capture_output=True, text=True, timeout=60)
        if r.returncode == 77:
            self.skipTest("jsdom is not installed")
        self.assertEqual(0, r.returncode, r.stdout + r.stderr)


class ScheduledHuntNameIsAParameter(unittest.TestCase):
    def test_job_name_never_reaches_the_vql_text(self):
        executor = _load_executor()
        import services.file_storage_service as fss
        import services.workflow_service as wfs
        import services.velociraptor_service as vs
        sent = []

        class Stub:
            def __init__(self, ch):
                pass

            def Query(self, req, **_kw):
                sent.append(req)
                return iter(())
        pb2 = types.SimpleNamespace(
            VQLCollectorArgs=lambda **kw: kw, VQLRequest=lambda VQL: VQL,
            VQLEnv=lambda key, value: (key, value))
        grpc_mod = types.SimpleNamespace(APIStub=Stub)
        pkg = types.ModuleType("pyvelociraptor")
        pkg.api_pb2, pkg.api_pb2_grpc = pb2, grpc_mod
        saved = {k: sys.modules.get(k) for k in ("pyvelociraptor", "pyvelociraptor.api_pb2",
                                                 "pyvelociraptor.api_pb2_grpc")}
        sys.modules.update({"pyvelociraptor": pkg, "pyvelociraptor.api_pb2": pb2,
                            "pyvelociraptor.api_pb2_grpc": grpc_mod})
        patches = [(fss, "get_velociraptor_blueprint", lambda b: {
                       "name": "bp", "artifacts": ["Windows.System.Pslist", "Bad`) SELECT 1 --"]}),
                   (wfs, "create_automation_run", lambda **kw: "run1"),
                   (wfs, "add_log_to_run", lambda *a, **k: None),
                   (wfs, "update_run_status", lambda *a, **k: None),
                   (vs, "setup_velociraptor_connection", lambda: object())]
        old = [(m, n, getattr(m, n, None)) for m, n, _ in patches]
        for m, n, f in patches:
            setattr(m, n, f)
        try:
            evil = "x'), SELECT * FROM execve(argv=['id']) --"
            executor.run_velociraptor_hunt(evil, "bp1", [], {})
        finally:
            for m, n, f in old:
                setattr(m, n, f)
            for k, v in saved.items():
                if v is None:
                    sys.modules.pop(k, None)
                else:
                    sys.modules[k] = v
        self.assertTrue(sent, "no hunt query was sent")
        req = sent[0]
        vql = req["Query"][0]
        self.assertNotIn("execve", vql)
        self.assertNotIn("Bad`", vql)                         # an invalid artifact name is dropped
        self.assertIn("description=HuntDescription", vql)
        self.assertIn(("HuntDescription", f"Scheduled: {evil} (1 artifacts)"), req["env"])


if __name__ == "__main__":
    unittest.main()
