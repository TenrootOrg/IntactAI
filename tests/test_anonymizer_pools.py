"""Every masking category draws from its own pool, cycles, and is stable.

WHY THIS EXISTS. _get_or_create_pseudo held an eight-branch if/elif chain whose
arms were identical except for the pool constant, while `category` was already
the parameter -- a lookup table written as control flow. Folding it needs a test,
because tests/test_investigate_v2.py:279 exercised only `user` and `host`: five
of the eight categories had no coverage at all.

What this pins, for all eight:
  - each category draws from its OWN pool (no cross-contamination)
  - the same input maps to the same pseudo every time (the mapping is a cache)
  - distinct inputs advance the counter, and the pool wraps rather than running out
  - an unknown category is redacted, not passed through
"""

import os
import sys
import types
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKEND = os.path.join(ROOT, "modules/backend")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BACKEND)

import _optional_deps  # noqa: E402
# Deliberately NOT stubbing flask: a process-wide flask stub makes
# tests/test_case_fuse_races.py stop SKIPPING two tests and fail against the
# fake instead. Measured. Stub only what these modules actually import.
_optional_deps.stub("requests", "grpc", "pyvelociraptor", "yaml")

if "services" not in sys.modules:
    _svc = types.ModuleType("services")
    _svc.__path__ = [os.path.join(BACKEND, "services")]
    sys.modules["services"] = _svc

from services import data_anonymizer as da  # noqa: E402

CATEGORIES = {
    "ip_ext": "PSEUDO_EXTERNAL_IPS",
    "ip_int": "PSEUDO_INTERNAL_IPS",
    "user": "PSEUDO_USERS",
    "host": "PSEUDO_HOSTS",
    "email": "PSEUDO_EMAILS",
    "domain": "PSEUDO_DOMAINS",
    "guid": "PSEUDO_GUIDS",
    "credential": "PSEUDO_CREDENTIALS",
}


class TestEveryCategoryUsesItsOwnPool(unittest.TestCase):
    def test_draws_from_the_right_pool(self):
        for cat, pool_name in CATEGORIES.items():
            with self.subTest(category=cat):
                a = da.DataAnonymizer()
                pool = getattr(da, pool_name)
                got = a._get_or_create_pseudo(f"real-{cat}", cat)
                self.assertIn(got, pool)

    def test_the_same_input_is_stable(self):
        for cat in CATEGORIES:
            with self.subTest(category=cat):
                a = da.DataAnonymizer()
                first = a._get_or_create_pseudo("same-value", cat)
                self.assertEqual(first, a._get_or_create_pseudo("same-value", cat))

    def test_distinct_inputs_advance_and_wrap(self):
        for cat, pool_name in CATEGORIES.items():
            with self.subTest(category=cat):
                a = da.DataAnonymizer()
                pool = getattr(da, pool_name)
                got = [a._get_or_create_pseudo(f"v{i}", cat)
                       for i in range(len(pool) + 2)]
                # first len(pool) are the pool in order, then it wraps
                self.assertEqual(list(pool), got[:len(pool)])
                self.assertEqual(pool[0], got[len(pool)])
                self.assertEqual(len(pool) + 2, a.counters[cat])

    def test_an_unknown_category_is_redacted(self):
        a = da.DataAnonymizer()
        self.assertEqual("<REDACTED>", a._get_or_create_pseudo("x", "not-a-category"))

    def test_the_reverse_mapping_round_trips(self):
        a = da.DataAnonymizer()
        p = a._get_or_create_pseudo("secret-host", "host")
        self.assertEqual("secret-host", a.reverse_mapping[p])


if __name__ == "__main__":
    unittest.main(verbosity=2)
