"""True Positive / Pending on a finding that was never marked benign changes nothing,
so it must not re-fuse the case. It did: ~30 s per click, then a page reload."""
import os
import sys
import unittest
from unittest import mock

for _p in (os.path.dirname(os.path.abspath(__file__)),
           os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.fusion import store  # noqa: E402


class ClearDisposition(unittest.TestCase):
    def _clear(self, dispositions):
        ws = mock.Mock()
        with mock.patch.object(store, "get_case", return_value={"dispositions": dispositions}), \
             mock.patch.object(store, "_ws", return_value=ws), \
             mock.patch.object(store, "log_case_event"), \
             mock.patch.object(store, "fuse_case") as fuse:
            store.clear_disposition("c1", "f1")
        return fuse.call_count, ws.mutate_run_details.call_count

    def test_nothing_to_clear_does_not_refuse(self):
        self.assertEqual(self._clear([{"target": "other"}]), (0, 0))

    def test_a_real_suppression_is_cleared_and_refused(self):
        self.assertEqual(self._clear([{"target": "f1"}]), (1, 1))


if __name__ == "__main__":
    unittest.main()
