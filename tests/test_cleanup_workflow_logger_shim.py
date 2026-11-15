#!/usr/bin/env python3
"""services.workflow_logger survives only as an import path for add_log_to_run.

The aws/azure pipelines and routes still import add_log_to_run from it, so
deleting the module (rather than just the dead WorkflowLogger class) would
break those blueprints at boot.
"""
import os
import sys
import unittest

for _p in (os.path.dirname(os.path.abspath(__file__)),
           os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402


class WorkflowLoggerShim(unittest.TestCase):
    def test_shim_reexports_the_real_add_log_to_run(self):
        from services import workflow_logger, workflow_service
        self.assertIs(workflow_logger.add_log_to_run, workflow_service.add_log_to_run)

    def test_dead_logger_is_gone(self):
        import services
        from services import workflow_logger
        for name in ("WorkflowLogger", "create_logger"):
            self.assertFalse(hasattr(workflow_logger, name), name)
            self.assertNotIn(name, services.__all__)


if __name__ == "__main__":
    unittest.main()
