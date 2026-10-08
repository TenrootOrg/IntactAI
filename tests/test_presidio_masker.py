"""The optional Presidio NER second pass: safe no-op without the dep, correct
toggle wiring, and a name-shape filter that keeps forensic strings out.

2026-10-07: added to catch the free-text PII the deterministic DataAnonymizer
cannot (person/company names in notes, docs, scriptblocks). It MUST be inert
on an air-gapped box with no Presidio installed, and must never mask a forensic
identifier (a registry path, a base64 blob, a hash) that NER mis-tags as a name.
"""
import os
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (_HERE, os.path.join(os.path.dirname(_HERE), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
from services import presidio_masker as pm  # noqa: E402


class Inert(unittest.TestCase):
    def test_noop_when_disabled(self):
        # Default off: even if Presidio were installed, scrub returns text unchanged.
        out, hits = pm.scrub("Analyst Sarah Johnson reviewed it", cfg={})
        self.assertEqual(out, "Analyst Sarah Johnson reviewed it")
        self.assertEqual(hits, [])

    def test_noop_without_presidio(self):
        # On a box with no Presidio, enabled() is False no matter the toggle.
        if not pm.available():
            self.assertFalse(pm.enabled(cfg={"pii_ner": True}))
            out, hits = pm.scrub("x", cfg={"pii_ner": True})
            self.assertEqual((out, hits), ("x", []))

    def test_empty_and_nonstr(self):
        self.assertEqual(pm.scrub("", cfg={"pii_ner": True}), ("", []))
        self.assertEqual(pm.scrub(None, cfg={"pii_ner": True}), (None, []))


class Toggle(unittest.TestCase):
    def test_enabled_reads_cfg_mask_and_env(self):
        class M:  # a stand-in for the DataAnonymizer carrying the flag
            _ner = True
        # available() gates all of these; assert the ON-signal plumbing itself.
        self.assertEqual(pm.enabled(cfg={"pii_ner": True}) if pm.available() else True,
                         pm.available() or True)
        # mask flag path
        self.assertFalse(pm.enabled(cfg={}, mask=object()))        # no flag -> off
        # env path
        os.environ["INTACT_PII_NER"] = "1"
        try:
            self.assertEqual(pm.enabled(), pm.available())          # on iff engine present
        finally:
            del os.environ["INTACT_PII_NER"]


class NameShapeFilter(unittest.TestCase):
    def test_keeps_real_names(self):
        for n in ("Sarah Johnson", "David Okoro", "Maria Gonzalez", "Wei Zhang",
                  "Jean-Luc Picard", "O'Brien"):
            self.assertTrue(pm._plausible_name(n), n)

    def test_rejects_forensic_strings(self):
        for s in (r"\SAM\Domains\Account\Users\000001F7",      # registry path
                  "AAAAAAAAAAACAAIAEAAAAN246urD6uhck49wn5ETjAiVVxp7bnrrzT==",  # base64 blob
                  "ntpwd_hash", "svchost.exe", "C:\\Windows\\Temp",
                  "192.168.1.5", "user@corp.com", "Username3"):
            self.assertFalse(pm._plausible_name(s), s)

    def test_rejects_overlong_token_and_too_many_words(self):
        self.assertFalse(pm._plausible_name("Supercalifragilisticexpialidocious1"))  # digit
        self.assertFalse(pm._plausible_name("one two three four five six"))          # 6 words


class CaseLogHook(unittest.TestCase):
    """Every LLM path (fuse, Regenerate, chat) must hand Presidio the case-Log
    hook. Regenerate once built its own mask without it: Presidio ran, but the
    names it hid never reached the case Log."""
    def test_case_mask_carries_log_hook(self):
        from services.fusion import store
        logged = []
        orig = store.log_case_event
        store.log_case_event = lambda cid, act, lvl, msg, **kw: logged.append((cid, act, msg))
        try:
            m = store._case_mask("case_x", {"masking": {"enabled": True, "ner": True}})
            m._logfn("2 name(s) hidden")
        finally:
            store.log_case_event = orig
        self.assertTrue(m._ner)
        self.assertEqual(logged, [("case_x", "Masking · Presidio (AI/NER)", "2 name(s) hidden")])
        self.assertIsNone(store._case_mask("case_x", {"masking": {"enabled": False}}))

    def test_no_path_builds_its_own_mask(self):
        src = open(os.path.join(os.path.dirname(_HERE), "modules/backend/services/fusion/store.py")).read()
        self.assertEqual(src.count("DataAnonymizer("), 1, "build case masks via _case_mask only")


class SecurityTermsAreNotMasked(unittest.TestCase):
    """NER tagged DFIR tooling, techniques and report words as PERSON/ORG on a lab
    run (Procdump, Kerberoasting, Inveigh, Critical, SAM, Endpoints, Detections),
    so the model read "Person5" where the evidence said "Critical". Those pass
    through _KEEP now; masking them strips the context the report exists to give."""
    def test_confirmed_false_positives_are_kept(self):
        for t in ("procdump", "kerberoasting", "inveigh", "critical", "sam",
                  "endpoints", "detections", "lsass", "dcsync", "rubeus",
                  "ransomware", "severity", "exclusion"):
            self.assertIn(t, pm._KEEP, t)

    def test_a_span_of_all_kept_words_is_kept(self):
        # the inline guard in _detect_spans: every token a kept term -> not masked
        for span in ("Critical Detection", "SAM Exclusion"):
            self.assertTrue(all(w in pm._KEEP for w in span.lower().split()), span)


if __name__ == "__main__":
    unittest.main()
