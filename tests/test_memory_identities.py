"""Memory contributes people, not just things.

A memory-only case had a Risk table, a Timeline and an EMPTY Identities tab:
"1 hosts, 362 entities, 146 links, 3 findings — 0 identities". Every entity the
memory mapper emitted was a thing (process, service, connection, asset) and
nothing was an account, so identity resolution had nothing to resolve.

`windows.sessions.Sessions` is the one plugin that names people: it lists the
user of every running process. Measured on a real 5 GB image: 6 seconds, 177
rows, three distinct principals.

Keyed through the Velociraptor mapper's own `_account_eid`, deliberately, so
`DESKTOP-566AT85/vagrant` out of a memory image and `vagrant` out of SAM are
ONE person in the Identities tab rather than two entries for the same account.

Row shapes below are copied from that extraction.
"""

import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as fh:
        return fh.read()


# Verbatim from evidence 14 (DESKTOP-566AT85, 5 GB), one row per shape seen.
REAL_ROWS = [
    {"Process": "System", "User Name": "N/A", "Process ID": 4,
     "Session ID": "N/A", "Session Type": "N/A", "Create Time": "2026-09-23T10:00:29+00:00"},
    {"Process": "explorer.exe", "User Name": "DESKTOP-566AT85/vagrant", "Process ID": 1944,
     "Session ID": 1, "Session Type": "Interactive", "Create Time": "2026-09-23T10:01:02+00:00"},
    {"Process": "svchost.exe", "User Name": "NT AUTHORITY/LOCAL SERVICE", "Process ID": 1120,
     "Session ID": 0, "Session Type": "Service", "Create Time": "2026-09-23T10:00:31+00:00"},
    {"Process": "lsass.exe", "User Name": "/SYSTEM", "Process ID": 700,
     "Session ID": 0, "Session Type": "Service", "Create Time": "2026-09-23T10:00:30+00:00"},
    {"Process": "MsMpEng.exe", "User Name": "WORKGROUP/DESKTOP-566AT85$", "Process ID": 2460,
     "Session ID": 0, "Session Type": "Service", "Create Time": "2026-09-23T10:00:33+00:00"},
]


class TestTheMapperEmitsAccounts(unittest.TestCase):
    """Source-level: the live-mapper run needs the backend's deps (grpc), which
    this box does not have — tests/test_memory_identities_live.sh drives the
    real map_memory inside the image."""

    SRC = _read("modules/backend/services/fusion/mappers/memory.py")

    def test_sessions_rows_are_read(self):
        self.assertIn('by_short.get("sessions", [])', self.SRC)

    def test_it_reuses_the_velociraptor_account_key(self):
        """A separate keying scheme would give one person two identities — the
        whole point of the Identities tab is that it is one list."""
        self.assertIn("from .agentic import _account_eid", self.SRC)
        self.assertIn("_account_eid(asset, None, user", self.SRC)

    def test_the_account_is_linked_to_what_it_ran(self):
        blk = self.SRC[self.SRC.index('by_short.get("sessions"'):][:2200]
        self.assertIn('"executed"', blk)

    def test_na_is_rejected_before_the_separator_is_rewritten(self):
        """Sessions writes DOMAIN/user and the graph speaks DOMAIN\\user, so
        rewriting first turns the literal "N/A" into the DOMAIN ACCOUNT "n\\a"
        — 38 processes' worth of a person who does not exist. Caught by
        driving the real mapper over the real rows."""
        blk = self.SRC[self.SRC.index('by_short.get("sessions"'):][:2200]
        self.assertLess(blk.index('user.lower() in ("", "n/a"'),
                        blk.index('user.strip("/\\\\").replace("/", "\\\\")'))

    def test_an_unqualified_account_loses_its_separator(self):
        """"/SYSTEM" would otherwise arrive as the user "\\system" — the same
        principal under a second name."""
        self.assertIn('user.strip("/\\\\")', self.SRC)

    def test_the_machine_account_is_not_a_person(self):
        blk = self.SRC[self.SRC.index('by_short.get("sessions"'):][:2200]
        self.assertIn('endswith("$")', blk)


class TestTheDefaultRunProducesIdentities(unittest.TestCase):
    """The mapper only helps if the plugin runs. Without sessions in the
    curated set a default memory run still shows an empty Identities tab."""

    def test_sessions_is_in_the_curated_set(self):
        src = _read("modules/backend/services/memory/defaults.py")
        start = src.index("CURATED_PLUGINS")
        blk = src[start:src.index("\n)", start)]
        self.assertIn("sessions.Sessions", blk)

    def test_it_is_in_the_catalog_volweb_can_actually_run(self):
        """A plugin VolWeb does not register silently produces nothing."""
        src = _read("modules/backend/services/memory/defaults.py")
        self.assertIn('"volatility3.plugins.windows.sessions.Sessions"', src)


class TestTheRowShapesThisWasBuiltAgainst(unittest.TestCase):
    """Guards the field names. If `User Name` or `Process ID` are renamed by a
    volatility upgrade the mapper goes quiet rather than wrong, and a quiet
    Identities tab is exactly the bug this fixes."""

    def test_the_fields_the_mapper_reads_are_the_ones_volatility_writes(self):
        src = _read("modules/backend/services/fusion/mappers/memory.py")
        blk = src[src.index('by_short.get("sessions"'):][:2200]
        for field in ("User Name", "Process ID", "Session Type", "Create Time"):
            self.assertIn(field, blk, f"{field} is in the real output but unread")
        for row in REAL_ROWS:
            self.assertIn("User Name", row)


if __name__ == "__main__":
    unittest.main(verbosity=2)
