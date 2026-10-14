"""Every major vendor's export reads right with the ONE generic reader.

tests/external_log_providers.py holds a sample per product (EDR/XDR, identity,
firewall, proxy/DNS, SIEM exports, e-mail, cloud, host logs) in that product's
own field names and format, and the values the reader must get out of it. A miss
here is fixed in the reader -- a name in the schema table, a shape, a time form,
a severity scale -- never with code for one vendor.
"""
import os
import sys
import unittest

for _p in (os.path.dirname(os.path.abspath(__file__)),
           os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from external_log_providers import SAMPLES  # noqa: E402
from services.fusion import external_logs as X  # noqa: E402
from services.fusion.mappers.external import map_external  # noqa: E402


def read(text):
    """What ingest() does without a model: parse, or keep indicator lines."""
    fmt, rows = X.parse(text)
    norm = X.normalize(rows, X.detect_columns(rows)) if rows else []
    if norm and X.recognized(norm):
        return "parser", norm
    return "indicators", X.indicator_rows(text.splitlines())


class EveryVendor(unittest.TestCase):

    def test_the_values_come_out_right(self):
        for name, _dt, text, want in SAMPLES:
            with self.subTest(name):
                _, rows = read(text)
                self.assertTrue(rows, "nothing kept")
                n = rows[0]["n"]
                for k, v in want.items():
                    if isinstance(v, list):
                        self.assertLessEqual(set(v), set(n.get(k) or []), (k, n))
                    elif k == "ts":
                        self.assertEqual(v, str(n.get("ts") or "")[:19], n)
                    else:
                        self.assertEqual(v, n.get(k), (k, n))

    def test_structured_exports_are_parsed_not_guessed(self):
        free = {"Cisco ASA - syslog", "Cisco Firepower (FTD) - intrusion syslog", "Windows DNS debug log",
                "Linux auth.log"}
        for name, _dt, text, _w in SAMPLES:
            if name in free:
                continue
            with self.subTest(name):
                self.assertEqual("parser", read(text)[0])

    def test_every_vendor_alert_reaches_fusion(self):
        for name, dt, text, _w in SAMPLES:
            with self.subTest(name):
                _, rows = read(text)
                ents, rels = map_external({X.artifact_name(dt): rows}, run_id="r", data_type=dt, label="f")
                alert = any(r["n"].get("severity") in ("medium", "high", "critical") for r in rows)
                events = [e for e in ents if e.type == "event"]
                self.assertEqual(alert, bool(events), name)
                for e in events:
                    self.assertIn("detection", e.flags)
                    self.assertTrue(e.attrs.get("_assets"))


class Times(unittest.TestCase):
    def test_every_time_form_is_utc(self):
        for v in ("2026-10-01T10:05:00Z", "2026-10-01T12:05:00+02:00", "2026-10-01T10:05:00.123456+0000",
                  "1790849100", "1790849100000", "1790849100000000", "1790849100000000000", "1790849100.123",
                  "Oct 01 2026 10:05:00 GMT", "Wed Oct 01 10:05:00 2026", "2026/10/01 10:05:00",
                  "10/01/2026 10:05:00", "10/1/2026 10:05:00 AM", "10/1/2026, 10:05:00.000 AM",
                  "Oct 1, 2026, 10:05:00 AM", "01-Oct-2026 10:05:00", "audit(1790849100.123:456):",
                  "01/Oct/2026:10:05:00"):
            with self.subTest(v):
                self.assertEqual("2026-10-01T10:05:00", X._ts(v))

    def test_nonsense_is_no_time(self):
        for v in ("", "abc", "42", "10:05:00", True, "999999999999999999999"):
            self.assertIsNone(X._ts(v), v)


class NoFalseAlerts(unittest.TestCase):
    def test_operational_numbers_are_not_severities(self):
        """A syslog level 7 is debug, a PRI 134 is facility+level: neither is an alert."""
        for text in ("\n".join(f'{{"timestamp": "2026-10-01T10:0{i}:00Z", "host": "WS01", "level": 7, '
                               f'"message": "x"}}' for i in range(3)),
                     "\n".join(f'{{"timestamp": "2026-10-01T10:0{i}:00Z", "host": "WS01", "priority": 134}}'
                               for i in range(3))):
            fmt, rows = X.parse(text)
            norm = X.normalize(rows, X.detect_columns(rows))
            self.assertFalse([r for r in norm if r["n"].get("severity")], norm[0])


class Robust(unittest.TestCase):
    def test_odd_files_never_crash(self):
        for text in ("", "\n\n", "\x00\x01binary\xff", "[1, 2, 3]", '{"a": 1}', "a,b\n", "x" * 100000,
                     '"unterminated,csv\n1,2', "<Events><Event></Event></Events>", "<not xml",
                     "CEF:0|broken", "LEEF:1.0|x", "#fields\tts\n"):
            fmt, rows = X.parse(text)
            norm = X.normalize(rows, X.detect_columns(rows)) if rows else []
            X.recognized(norm)
            X.indicator_rows(text.splitlines())


if __name__ == "__main__":
    unittest.main()
