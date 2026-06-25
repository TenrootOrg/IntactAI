"""Tests for the external-log parsers (services/agentic/external_data.py).

These turn an uploaded third-party log file (CSV / TSV / JSON / JSONL / XML / text)
into a list of record dicts for the agentic pipeline. All pure (file -> list), so
we exercise every format + the dispatch/validation/hint helpers with temp files.

Run:  docker exec intact_backend python /app/services/agentic/tests/test_external_data.py
"""

import os
import sys
import tempfile
if "/app" not in sys.path:
    sys.path.insert(0, "/app")

import services.agentic.external_data as E   # noqa: E402


def _tmp(name, content):
    d = tempfile.mkdtemp(prefix="extdata_")
    p = os.path.join(d, name)
    with open(p, "w", encoding="utf-8") as fh:
        fh.write(content)
    return p


# --------------------------------------------------------------------------
# dispatch + edge cases
# --------------------------------------------------------------------------
def test_missing_file_raises():
    try:
        E.parse_external_file("/no/such/file.csv", "file.csv")
        assert False, "expected ValueError"
    except ValueError:
        pass


def test_empty_file_returns_empty():
    p = _tmp("empty.csv", "")
    assert E.parse_external_file(p, "empty.csv") == []


def test_dispatch_by_extension():
    csv_p = _tmp("a.csv", "name,val\nx,1\n")
    assert E.parse_external_file(csv_p, "a.csv") == [{"name": "x", "val": "1"}]
    jsonl_p = _tmp("a.jsonl", '{"a":1}\n{"a":2}\n')
    assert E.parse_external_file(jsonl_p, "a.jsonl") == [{"a": 1}, {"a": 2}]


def test_unknown_extension_falls_back_to_text_lines():
    p = _tmp("a.weirdext", "line one\nline two\n")
    out = E.parse_external_file(p, "a.weirdext")
    assert [r["content"] for r in out] == ["line one", "line two"]


# --------------------------------------------------------------------------
# CSV / TSV
# --------------------------------------------------------------------------
def test_csv_basic():
    p = _tmp("c.csv", "host,sev\nws1,high\nws2,low\n")
    assert E.parse_csv(p) == [{"host": "ws1", "sev": "high"}, {"host": "ws2", "sev": "low"}]


def test_csv_semicolon_delimiter_detected():
    p = _tmp("c.csv", "host;sev\nws1;high\n")
    assert E.parse_csv(p) == [{"host": "ws1", "sev": "high"}]


def test_tsv_basic():
    p = _tmp("c.tsv", "host\tsev\nws1\thigh\n")
    assert E.parse_tsv(p) == [{"host": "ws1", "sev": "high"}]


# --------------------------------------------------------------------------
# text lines
# --------------------------------------------------------------------------
def test_text_lines_skip_blanks_and_number():
    p = _tmp("l.log", "first\n\n  \nsecond\n")
    out = E.parse_text_lines(p)
    assert out == [{"line_number": 1, "content": "first"},
                   {"line_number": 4, "content": "second"}]


# --------------------------------------------------------------------------
# JSON
# --------------------------------------------------------------------------
def test_json_array_of_objects():
    p = _tmp("j.json", '[{"a":1},{"a":2}]')
    assert E.parse_json(p) == [{"a": 1}, {"a": 2}]


def test_json_single_object_wrapped():
    p = _tmp("j.json", '{"a":1}')
    assert E.parse_json(p) == [{"a": 1}]


def test_json_nested_results_key_extracted():
    p = _tmp("j.json", '{"results":[{"a":1}],"meta":"x"}')
    assert E.parse_json(p) == [{"a": 1}]


def test_json_array_filters_non_dicts():
    p = _tmp("j.json", '[{"a":1}, 5, "str", {"b":2}]')
    assert E.parse_json(p) == [{"a": 1}, {"b": 2}]


def test_json_invalid_raises():
    p = _tmp("j.json", "{not json")
    try:
        E.parse_json(p); assert False
    except ValueError:
        pass


def test_json_unexpected_scalar_raises():
    p = _tmp("j.json", "42")
    try:
        E.parse_json(p); assert False
    except ValueError:
        pass


# --------------------------------------------------------------------------
# JSONL
# --------------------------------------------------------------------------
def test_jsonl_basic_and_blank_lines():
    p = _tmp("j.jsonl", '{"a":1}\n\n{"a":2}\n')
    assert E.parse_jsonl(p) == [{"a": 1}, {"a": 2}]


def test_jsonl_bad_line_is_skipped():
    p = _tmp("j.jsonl", '{"a":1}\n{bad}\n{"a":3}\n')
    assert E.parse_jsonl(p) == [{"a": 1}, {"a": 3}]


def test_jsonl_non_dict_line_skipped():
    p = _tmp("j.jsonl", '{"a":1}\n[1,2,3]\n')
    assert E.parse_jsonl(p) == [{"a": 1}]


# --------------------------------------------------------------------------
# XML
# --------------------------------------------------------------------------
def test_xml_repeating_elements():
    xml = "<logs><event><host>ws1</host></event><event><host>ws2</host></event></logs>"
    p = _tmp("x.xml", xml)
    out = E.parse_xml(p)
    hosts = [r.get("host") for r in out if "host" in r]
    assert "ws1" in hosts and "ws2" in hosts


def test_xml_attributes_captured():
    xml = '<logs><event id="1" sev="high"/><event id="2" sev="low"/></logs>'
    p = _tmp("x.xml", xml)
    out = E.parse_xml(p)
    ids = [r.get("id") for r in out if "id" in r]
    assert "1" in ids and "2" in ids


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def test_source_hint_titlecases_and_strips_ext():
    assert E.get_source_hint("crowdstrike_detections.csv") == "Crowdstrike Detections"
    assert E.get_source_hint("fortinet-fw-logs.json") == "Fortinet Fw Logs"


def test_validate_accepts_supported_and_rejects_others():
    for ok in ("a.csv", "a.json", "a.jsonl", "a.xml", "a.tsv", "a.log", "a.txt", "a.evtx"):
        assert E.validate_external_file(ok) is True
    try:
        E.validate_external_file("a.exe"); assert False
    except ValueError:
        pass


if __name__ == "__main__":
    import traceback
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn(); print(f"PASS {fn.__name__}")
        except Exception:
            failed += 1; print(f"FAIL {fn.__name__}"); traceback.print_exc()
    print(f"\n{len(fns)-failed}/{len(fns)} passed")
    sys.exit(1 if failed else 0)
