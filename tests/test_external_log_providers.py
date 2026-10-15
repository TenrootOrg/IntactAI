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



class ProductChangesUnderUs(unittest.TestCase):
    """A vendor update adds columns, renames a field or changes a value's type --
    often in the middle of one export. Whatever can be read is read; nothing that
    broke takes the rest of the file with it."""

    def _ingest(self, text):
        import tempfile
        from unittest import mock
        d = tempfile.mkdtemp()
        src = os.path.join(d, "in.log")
        with open(src, "w") as f:
            f.write(text)
        logs = []
        with mock.patch.object(X, "downloads_dir", lambda rid: os.path.join(d, rid)), \
                mock.patch.object(X, "_model", lambda *a: None):
            s = X.ingest("c", "r1", src, "edr", lambda m, l="info": logs.append(m))
        import json as _j
        with open(os.path.join(d, "r1", "raw_results.json")) as f:
            return s, _j.load(f)["External.edr"], logs

    def test_a_field_renamed_halfway_still_fills(self):
        import json as _j
        old = [{"timestamp": f"2026-10-01T10:{i % 60:02d}:00Z", "hostname": "WS01", "src_ip": "185.220.101.4"}
               for i in range(400)]
        new = [{"timestamp": f"2026-10-02T10:{i % 60:02d}:00Z", "hostname": "WS01",
                "source": {"ip": "185.220.101.9"}, "new_field_v2": {"x": [1, 2]}} for i in range(400)]
        s, rows, _ = self._ingest("\n".join(_j.dumps(o) for o in old + new))
        self.assertEqual(800, s["rows"])
        self.assertEqual("185.220.101.4", rows[0]["n"]["src_ip"])
        self.assertEqual("185.220.101.9", rows[-1]["n"]["src_ip"], "the renamed field fills src_ip too")

    def test_a_csv_that_changes_its_columns(self):
        text = ("Timestamp,DeviceName,RemoteIP\n"
                "2026-10-01T10:00:00Z,WS01,185.220.101.4\n"
                "2026-10-01T10:01:00Z,WS01,185.220.101.4,UNEXPECTED_EXTRA\n"     # a column too many
                "2026-10-01T10:02:00Z,WS02\n"                                    # one too few
                "Timestamp,DeviceName,AccountName,RemoteIP\n"                    # second export pasted in
                "2026-10-01T10:03:00Z,WS03,CORP\\jdoe,185.220.101.5\n")
        s, rows, _ = self._ingest(text)
        self.assertEqual(4, s["rows"])
        by = {r["n"].get("host"): r["n"] for r in rows}
        self.assertEqual("185.220.101.4", by["WS01"]["dst_ip"])
        self.assertIn("WS02", by)
        self.assertEqual(("CORP\\jdoe", "185.220.101.5"), (by["WS03"]["user"], by["WS03"]["dst_ip"]),
                         "after the new header the columns are the new ones")

    def test_values_of_an_unexpected_type(self):
        import json as _j
        odd = [{"timestamp": "2026-10-01T10:00:00Z", "hostname": "WS01", "severity": "high", "src_ip": "185.220.101.4"},
               {"timestamp": 1790849100, "hostname": ["WS01", "WS02"], "severity": {"level": 9}, "src_ip": None},
               {"timestamp": None, "hostname": 12345, "severity": True, "src_ip": ["185.220.101.4"]},
               {"timestamp": "2026-10-01T10:05:00Z", "hostname": "WS01", "severity": "high", "src_ip": "185.220.101.4"}]
        s, rows, _ = self._ingest("\n".join(_j.dumps(o) for o in odd))
        self.assertEqual(4, s["rows"])
        self.assertEqual("high", rows[3]["n"]["severity"])

    def test_one_row_that_breaks_the_reader_is_kept_as_text(self):
        from unittest import mock
        import json as _j
        real = X._ts

        def flaky(v):
            if "10:03" in str(v):
                raise ValueError("unreadable")
            return real(v)
        text = "\n".join(_j.dumps({"timestamp": f"2026-10-01T10:0{i}:00Z", "hostname": "WS01",
                                   "src_ip": "185.220.101.4"}) for i in range(6))
        with mock.patch.object(X, "_ts", flaky):
            s, rows, logs = self._ingest(text)
        self.assertEqual((6, 1), (s["rows"], s["row_errors"]))
        self.assertEqual(["185.220.101.4"], rows[3]["n"]["ips"], "the broken row keeps its indicators")
        self.assertTrue(any("could not take" in m for m in logs), logs)

    def test_lines_of_another_shape_are_not_dropped(self):
        cef = ("Oct  1 10:05:00 pa01 CEF:0|Palo Alto Networks|PAN-OS|10.1|threat|C2|8|"
               "rt=2026-10-01T10:05:00Z src=10.0.0.5 dst=185.220.101.4\n") * 7
        plain = "Oct  1 10:06:00 pa01 kernel: link down on eth1, peer 185.220.101.77\n"
        broken = "Oct  1 10:07:00 pa01 CEF:0|half a line\n"
        s, rows, logs = self._ingest(cef + plain + broken)
        self.assertEqual("parser", s["via"])
        self.assertEqual(2, s["leftover_lines"])
        self.assertIn("185.220.101.77", [ip for r in rows for ip in r["n"].get("ips", [])],
                      "the plain syslog line is kept with its indicator")
        self.assertTrue(any("did not fit the CEF structure" in m for m in logs), logs)

    def test_broken_json_lines_among_good_ones(self):
        import json as _j
        good = [_j.dumps({"timestamp": f"2026-10-01T10:0{i}:00Z", "hostname": "WS01", "src_ip": "185.220.101.4"})
                for i in range(8)]
        s, rows, _ = self._ingest("\n".join(good[:4] + ['{"timestamp": "2026-10-01T10:09:00Z", "src_ip": "185.220.101.66"',
                                                        "not json at all"] + good[4:]))
        self.assertEqual(8, sum(1 for r in rows if r["n"].get("host") == "WS01"))
        self.assertIn("185.220.101.66", [ip for r in rows for ip in r["n"].get("ips", [])])


if __name__ == "__main__":
    unittest.main()
