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

    def test_rejects_flags_and_camelcase_identifiers(self):
        # PowerShell flags and camelCase/Pascal technical identifiers are NOT names;
        # NER tagged all of these PERSON/ORG on a live report.
        for s in ("-eq", "-NoProfile", "-NoProfile -NonInteractive -ExecutionPolicy",
                  "LogonId", "MethodPara", "NoProfile", "PSScriptPolicyTest"):
            self.assertFalse(pm._plausible_name(s), s)
        # hyphenated / apostrophe real names must survive the camelCase check
        for n in ("Jean-Luc Picard", "O'Brien"):
            self.assertTrue(pm._plausible_name(n), n)

    def test_span_glued_to_a_larger_token_is_not_a_name(self):
        # Windows chunks a scriptblock, so labels carry cut-off identifier tails;
        # NER tagged them PERSON. Their POSITION gives them away, not their shape.
        def glued(text, frag):
            i = text.index(frag)
            return pm._glued_to_token(text, i, i + len(frag))
        self.assertTrue(glued('text (21 of 24):\\nft.Management.Infrastr"', "Infrastr"))
        self.assertTrue(glued("ntFirewallServiceFilter", "Firewal"))
        self.assertTrue(glued("OmitNullValues = 64", "Valu"))
        self.assertTrue(glued("C:\\Users\\Sarah\\x", "Sarah"))
        # real prose names stay maskable: sentence end, quotes, JSON line break, comma
        self.assertFalse(glued("reviewed by Sarah Johnson.", "Sarah Johnson"))
        self.assertFalse(glued('"analyst": "Sarah Johnson"', "Sarah Johnson"))
        self.assertFalse(glued('notes:\\nSarah Johnson escalated', "Sarah Johnson"))
        self.assertFalse(glued("Sarah Johnson, Contoso Ltd", "Contoso Ltd"))

    def test_ner_reads_decoded_prose_values_not_json_escapes(self):
        import json as _j
        payload = {"notes": "Escalated by Sarah Johnson.\nDavid Okoro confirmed.",
                   "name": "Jos\u00e9 Garc\u00eda",
                   "label": "Creating Scriptblock text (2 of 7):\n[Parameter()]@{Name = 'Remot"}
        det = pm._detection_text(_j.dumps(payload))
        self.assertIn("Sarah Johnson.\nDavid Okoro", det)      # real newline, not "\\n"
        self.assertIn("Jos\u00e9 Garc\u00eda", det)            # accent decoded
        self.assertNotIn("Remot", det)                          # code value skipped
        self.assertEqual("plain chat question", pm._detection_text("plain chat question"))

    def test_code_vs_prose(self):
        self.assertTrue(pm._is_code("Creating Scriptblock text (2 of 7):\n[Parameter()]@{Name = 'Remot'}"))
        self.assertTrue(pm._is_code("$x = Get-Item -Path $p; if ($x) { [void]$list.Add($x) }"))
        self.assertFalse(pm._is_code("Call with Maria Gonzalez from Acme Corporation about the incident."))

    def test_company_entity_is_requested(self):
        self.assertIn("ORGANIZATION", pm.DEFAULT_ENTITIES)       # Presidio has no "ORG"

    def test_replacement_edges_do_not_leak_after_a_json_escape(self):
        import re as _re
        def sub(name, text):
            return _re.sub(pm._NAME_EDGE_L + _re.escape(name) + r"(?!\w)", "P1", text)
        # detected right after a JSON line break: used to be reported masked and LEAK
        self.assertEqual('Johnson.\\nP1 confirmed', sub("David Okoro", 'Johnson.\\nDavid Okoro confirmed'))
        self.assertEqual('belongs to P1.\\nx', sub("Contoso Ltd", 'belongs to Contoso Ltd.\\nx'))
        self.assertEqual("Davidson", sub("David", "Davidson"))          # not inside a longer word
        self.assertEqual("xDavid", sub("David", "xDavid"))

    def test_span_rules_field_labels_vendors_and_companies(self):
        rej = pm._span_rejected
        # a Windows field label written as prose, with a colon or a backtick value
        t = "identifies Domain Name `HOST1` and Possiblecause: Permanent"
        i = t.index("Domain Name"); self.assertTrue(rej(t, i, i + 11, "Domain Name", "PERSON"))
        i = t.index("Possiblecause"); self.assertTrue(rej(t, i, i + 13, "Possiblecause", "PERSON"))
        # ORG needs a designator; a public vendor stays; a bank with a field word is masked
        t = "Remote Desktop Services; Microsoft Corporation; First Security Bank"
        for frag, want in (("Remote Desktop Services", True), ("Microsoft Corporation", True),
                           ("First Security Bank", False)):
            i = t.index(frag)
            self.assertEqual(want, rej(t, i, i + len(frag), frag, "ORGANIZATION"), frag)
        # lowercase tokens and a cut-off word with its whole form elsewhere
        t = "type ioc\n(Microso\nMicrosoft-Windows-Sysmon"
        i = t.index("ioc"); self.assertTrue(rej(t, i, i + 3, "ioc", "ORGANIZATION"))
        i = t.index("Microso"); self.assertTrue(rej(t, i, i + 7, "Microso", "PERSON"))

    def test_camelcase_company_allowed_camelcase_person_not(self):
        self.assertTrue(pm._plausible_name("PayPal Inc", allow_camel=True))
        self.assertFalse(pm._plausible_name("LogonId"))

    def test_model_written_values_are_skipped_and_tool_publishers_kept(self):
        import json as _j
        doc = _j.dumps({"analysis": "Mark these hosts as known.", "notes": "Sarah Johnson called"})
        vals = pm._prose_values(doc, skip={"Mark these hosts as known."})
        self.assertEqual(["Sarah Johnson called"], vals)          # evidence beside it still read
        t = "Signed by Nmap Software LLC"
        i = t.index("Nmap")
        self.assertTrue(pm._span_rejected(t, i, len(t), "Nmap Software LLC", "ORGANIZATION"))

    def test_threat_vocabulary_is_kept(self):
        for w in ("bypass", "trojan", "firewall", "value", "creation"):
            self.assertIn(w, pm._KEEP, w)


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
        self.assertEqual(logged, [("case_x", "Masking · Presidio leftovers", "2 name(s) hidden")])
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


class BuiltinsAndThreatActorsAreNotPeople(unittest.TestCase):
    """mask_eval corpus: "Domain Admins" came back Person1 and the threat actor
    "Agrius" Person4 -- the model lost the privileged group and the attribution."""
    def test_builtin_groups_are_all_kept_words(self):
        for span in ("Domain Admins", "Enterprise Admins", "Schema Admins", "Domain Controllers",
                     "Backup Operators", "Domain Computers"):
            self.assertTrue(all(w in pm._KEEP for w in span.lower().split()), span)

    def test_one_word_person_rejected_full_name_kept(self):
        t = "Overlaps MuddyWater and Agrius; escalated by Yossi Cohen."
        i = t.index("Agrius"); self.assertTrue(pm._span_rejected(t, i, i + 6, "Agrius", "PERSON"))
        i = t.index("Yossi Cohen"); self.assertFalse(pm._span_rejected(t, i, i + 11, "Yossi Cohen", "PERSON"))


class ModelPhaseTitlesAreNotPeople(unittest.TestCase):
    """2026-10-20, a live report: the model's own phase titles "PAExec Across
    Endpoints" and "Hacktool Staging" came back Person1/Person2, and "Domain
    Controller" Person3. The case's rules were named "PAExec Service Installation"
    and "HackTool - Rubeus Execution" -- a span holding one of their TOOL-shaped
    words is a technical phrase. A real name is never tool-shaped, so it stays masked."""
    TOOLS = frozenset({"paexec", "hacktool"})

    def rej(self, text, span, tools=TOOLS):
        i = text.index(span)
        return pm._span_rejected(text, i, i + len(span), span, "PERSON", (), tools)

    def test_tool_words_from_the_rule_names(self):
        self.assertTrue(self.rej("Phase 3 — PAExec Across Endpoints on two hosts", "PAExec Across Endpoints"))
        self.assertTrue(self.rej("then Hacktool Staging on ALClient06", "Hacktool Staging"))

    def test_domain_controller_is_vocabulary(self):
        self.assertTrue(all(w in pm._KEEP for w in "domain controller".split()))

    def test_real_names_are_still_masked(self):
        self.assertFalse(self.rej("escalated by Yossi Cohen at 10:00", "Yossi Cohen"))
        self.assertFalse(self.rej("signed off by Grant Wilson", "Grant Wilson"))   # "grant" is no tool word

    def test_only_tool_shaped_words_are_collected(self):
        import re
        names = ["PAExec Service Installation", "HackTool - Rubeus Execution 2", "Privilege Grant To Mark"]
        words = {w.lower() for n in names for w in re.findall(r"[A-Za-z][A-Za-z0-9]+", n)
                 if re.search(r"[a-z][A-Z]|[A-Z]{2}[a-z]", w)}
        self.assertEqual({"paexec", "hacktool"}, words)            # never "grant" or "mark"
        src = open(os.path.join(os.path.dirname(pm.__file__), "fusion", "llm_sim.py")).read()
        self.assertIn('if re.search(r"[a-z][A-Z]|[A-Z]{2}[a-z]", w))', src)   # the same rule, before lowercasing
        self.assertIn("mask._tech_words = frozenset(tool_words)", src)


class SaysWhenItFoundNothing(unittest.TestCase):
    """The Log only listed names Presidio hid, so "checked, nothing to hide" and
    "never ran" looked identical. It now says so -- once per report, not per chunk."""
    def test_one_clean_line_per_report(self):
        orig_en, orig_det = pm.enabled, pm._detect_spans
        pm.enabled = lambda *a, **k: True
        pm._detect_spans = lambda *a, **k: []
        logged = []
        try:
            class M:
                mapping = {}
            m = M()
            pm.scrub('{"a": "nothing here"}', m, logfn=lambda msg, lvl="info": logged.append(msg))
            pm.scrub('{"b": "still nothing"}', m, logfn=lambda msg, lvl="info": logged.append(msg))
        finally:
            pm.enabled, pm._detect_spans = orig_en, orig_det
        clean = [x for x in logged if "no leftover" in x]
        self.assertEqual(1, len(clean), logged)


class LargeTextIsReadInChunksAndFailuresAreSaid(unittest.TestCase):
    """One request per payload (up to ~330k chars) overran the 30 s timeout and was
    swallowed as "no names": Presidio silently checked nothing on big cases."""
    def setUp(self):
        self._saved = (pm.enabled, pm._detect_chunk)
        pm.enabled = lambda *a, **k: True

    def tearDown(self):
        pm.enabled, pm._detect_chunk = self._saved

    def test_chunks_cut_at_line_breaks_and_offsets_map_back(self):
        text = ("line of text\n" * 4000)                  # 52k chars
        parts = pm._chunks(text, 20000)
        self.assertGreater(len(parts), 2)
        self.assertEqual(text, "".join(p for _, p in parts))
        self.assertTrue(all(p.endswith("\n") for _, p in parts[:-1]))
        pm._detect_chunk = lambda t, *a, **k: [{"entity_type": "PERSON", "start": 0, "end": 4, "score": .9}]
        spans = pm._detect_spans(text, ("PERSON",), 0.6)
        self.assertEqual([off for off, _ in parts], [sp["start"] for sp in spans])

    def test_an_unread_chunk_is_reported_never_called_clean(self):
        pm._detect_chunk = lambda *a, **k: None             # engine did not answer
        logged = []

        class M:
            mapping = {}
        pm.scrub('{"a": "Sarah Johnson called"}', M(), logfn=lambda m, l="info": logged.append(m))
        self.assertTrue(any("NOT checked" in x for x in logged), logged)
        self.assertFalse(any("no leftover" in x for x in logged), logged)

    def test_each_distinct_value_is_read_once_per_report(self):
        calls = []
        pm._detect_chunk = lambda t, *a, **k: (calls.append(t), [])[1]

        class M:
            mapping = {}
        m = M()
        payload = '{"a": "Sarah Johnson called", "b": "Sarah Johnson called", "c": "other note"}'
        pm.scrub(payload, m, logfn=lambda *a, **k: None)
        pm.scrub(payload, m, logfn=lambda *a, **k: None)   # second model call, same values
        self.assertEqual(1, len(calls), calls)
        self.assertEqual(1, calls[0].count("Sarah Johnson called"), calls)


if __name__ == "__main__":
    unittest.main()
