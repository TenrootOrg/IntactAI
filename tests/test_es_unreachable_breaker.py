"""An unreachable Elasticsearch must not cost every request half a second.

With ELK stopped while config.yaml still says enabled, each Elasticsearch call paid a
name lookup plus the client's retries before falling back to SQLite (2.2 s measured
with a fresh client). Listing runs does that twice per request, so the Case
Management page -- which lists cases several times on load -- took seconds.

These tests run the real services/elasticsearch_service.py against a fake
`elasticsearch` package, so they need neither the client library nor a cluster.
"""

import importlib.util
import os
import sys
import types
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVICE = os.path.join(ROOT, "modules", "backend", "services", "elasticsearch_service.py")


class FakeConnectionError(Exception):
    pass


class FakeConnectionTimeout(Exception):
    pass


class FakeNotFoundError(Exception):
    """A missing document: a normal answer, not an outage."""


def load_service():
    fake = types.ModuleType("elasticsearch")
    fake.Elasticsearch = object
    fake.ConnectionError = FakeConnectionError
    fake.ConnectionTimeout = FakeConnectionTimeout
    with mock.patch.dict(sys.modules, {"elasticsearch": fake}):
        spec = importlib.util.spec_from_file_location("es_service_under_test", SERVICE)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    return mod


class FakeClient:
    def __init__(self, raises=None):
        self.raises = raises
        self.calls = 0

    def _call(self, *_a, **_k):
        self.calls += 1
        if self.raises:
            raise self.raises
        return {"hits": {"hits": [{"_source": {"run_id": "r1"}}]}, "_source": {"run_id": "r1"}}

    search = get = update = _call


class AnUnreachableClusterIsSkippedForACoolDown(unittest.TestCase):

    def setUp(self):
        self.es = load_service()
        self.clock = [1000.0]
        patcher = mock.patch.object(self.es.time, "monotonic", side_effect=lambda: self.clock[0])
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_after_one_connection_failure_calls_return_at_once(self):
        client = FakeClient(raises=FakeConnectionError("Failed to resolve 'intact_elasticsearch'"))
        self.es.es_client = client
        self.assertEqual([], self.es.get_all_workflow_runs())
        self.assertEqual(1, client.calls, "the first call really tried")
        for _ in range(5):
            self.assertEqual([], self.es.get_all_workflow_runs())
        self.assertEqual(1, client.calls, "the next five did not wait on the cluster")

    def test_every_elasticsearch_call_honours_it(self):
        client = FakeClient(raises=FakeConnectionTimeout("timed out"))
        self.es.es_client = client
        self.es.get_all_workflow_runs()
        self.assertIsNone(self.es.get_workflow_run("r1"))
        self.assertFalse(self.es.update_workflow_status("r1", "completed"))
        self.assertEqual(1, client.calls)

    def test_it_tries_again_after_the_cool_down(self):
        client = FakeClient(raises=FakeConnectionError("down"))
        self.es.es_client = client
        self.es.get_all_workflow_runs()
        self.clock[0] += self.es._UNREACHABLE_COOLDOWN_S + 1
        self.es.get_all_workflow_runs()
        self.assertEqual(2, client.calls, "ELK coming back is noticed within a minute")

    def test_a_recovered_cluster_answers_normally(self):
        self.es.es_client = FakeClient(raises=FakeConnectionError("down"))
        self.es.get_all_workflow_runs()
        self.clock[0] += self.es._UNREACHABLE_COOLDOWN_S + 1
        self.es.es_client = FakeClient()
        self.assertEqual([{"run_id": "r1"}], self.es.get_all_workflow_runs())

    def test_a_missing_document_never_trips_it(self):
        client = FakeClient(raises=FakeNotFoundError("404 not found"))
        self.es.es_client = client
        self.assertIsNone(self.es.get_workflow_run("gone"))
        self.assertIsNone(self.es.get_workflow_run("gone"))
        self.assertEqual(2, client.calls, "a real answer is not an outage")

    def test_a_healthy_cluster_is_asked_every_time(self):
        client = FakeClient()
        self.es.es_client = client
        for _ in range(3):
            self.assertEqual([{"run_id": "r1"}], self.es.get_all_workflow_runs())
        self.assertEqual(3, client.calls)

    def test_the_outage_is_logged_once_not_per_call(self):
        self.es.es_client = FakeClient(raises=FakeConnectionError("down"))
        with mock.patch("builtins.print") as printed:
            for _ in range(10):
                self.es.get_all_workflow_runs()
        lines = [c.args[0] for c in printed.call_args_list if "unreachable" in str(c.args[0])]
        self.assertEqual(1, len(lines), "one line, not 114")


if __name__ == "__main__":
    unittest.main(verbosity=2)
