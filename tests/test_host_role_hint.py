"""The role hint is read from the SHORT host name, never from the domain.

'ca' was found in '.local', so every host of a .local domain was hinted to the
model as a "certificate authority" (a test-case chat called a desktop the CA).
"""
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (os.path.join(ROOT, "tests"), os.path.join(ROOT, "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services.fusion import render  # noqa: E402


class HostRoleHint(unittest.TestCase):
    def test_roles_from_real_lab_names(self):
        r = render._host_role
        self.assertEqual("domain controller", r("ALDC02"))
        self.assertEqual("domain controller", r("CITADEL-DC01.C137.local"))
        self.assertEqual("certificate authority", r("ALCA01"))
        self.assertEqual("config manager / software distribution", r("ALMECM01.AdatumLab.local"))
        self.assertEqual("database server", r("SQL01.corp.local"))

    def test_the_domain_and_ordinary_words_are_not_roles(self):
        r = render._host_role
        for host in ("DESKTOP-SDN1RPT.C137.local", "SCRANTON.dmevals.local", "NASHUA.dmevals.local",
                     "VACATION-PC", "ALClient04.AdatumLab.local"):
            self.assertEqual("", r(host), host)


if __name__ == "__main__":
    unittest.main()
