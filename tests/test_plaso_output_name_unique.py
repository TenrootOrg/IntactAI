"""Two Plaso runs for same-named hosts must not share an output file (F23).

The output was {client_name}_Artifacts.plaso, and a run deleted any file of that
name before starting. Two concurrent pipelines for hosts with the same name --
every host without one is 'Unknown' -- deleted each other's .plaso mid-run.
"""
import io
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

for _p in (os.path.dirname(os.path.abspath(__file__)),
           os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services import kape_upload_service as kus  # noqa: E402


class FakePlaso:
    """Stands in for `docker run ... log2timeline`: writes the storage file."""

    def __init__(self, out_dir):
        self.out_dir = out_dir
        self.cmds = []

    def __call__(self, cmd, **_kw):
        self.cmds.append(cmd)
        storage = cmd[cmd.index('--storage-file') + 1]
        with open(os.path.join(self.out_dir, os.path.basename(storage)), 'w') as f:
            f.write('plaso')
        proc = mock.Mock()
        proc.stdout = io.StringIO('')
        proc.wait.return_value = 0
        return proc


class UniquePlasoOutput(unittest.TestCase):
    def run_twice(self, name):
        out = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, out, True)
        fake = FakePlaso(out)
        with mock.patch.object(kus, 'PLASO_OUTPUT_DIR', out), \
                mock.patch.object(kus.subprocess, 'Popen', fake):
            first = kus.process_local_with_plaso('/src', name)
            second = kus.process_local_with_plaso('/src', name)
        return out, first, second

    def test_same_name_gives_two_files_and_neither_is_deleted(self):
        out, first, second = self.run_twice('Unknown')
        self.assertNotEqual(first, second)
        self.assertTrue(os.path.isfile(first))
        self.assertTrue(os.path.isfile(second))     # the second run did not eat the first
        self.assertEqual(os.path.dirname(first), out)

    def test_endpoint_supplied_name_cannot_leave_the_output_dir(self):
        out, first, _ = self.run_twice('../../etc/x y')
        self.assertEqual(os.path.dirname(first), out)
        self.assertNotIn('/', os.path.basename(first))
        self.assertTrue(os.path.basename(first).endswith('_Artifacts.plaso'))


if __name__ == '__main__':
    unittest.main()
