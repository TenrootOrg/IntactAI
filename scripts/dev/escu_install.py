#!/usr/bin/env python3
"""Build modules/backend/config/sigma-escu/ from the translated rules.

Only rules that FIRED on their own attack_data recording ship. A rule that also
fired on benign Windows activity ships LOW (context, never a detection on its
own) with the reason in x-intact. A later prove result for the same file wins
(a re-translated rule proved again).

  python3 scripts/dev/escu_install.py <rules dir> <benign.json> <prove.jsonl>...
"""
import json
import os
import shutil
import sys

import yaml

here = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(here, "../../modules/backend/config/sigma-escu")
NOTICE = """These rules are translated from Splunk Security Content (https://github.com/splunk/security_content),
Copyright Splunk Inc., licensed under the Apache License 2.0 (https://www.apache.org/licenses/LICENSE-2.0).
Translated to Sigma by scripts/dev/escu_to_sigma.py; each rule shipped here fired on the attack_data
recording its detection names (scripts/dev/escu_prove.py). Changes: query language (SPL -> Sigma), field
names (Splunk CIM -> raw log fields), severity (see x-intact in each rule).
"""


def main(rules_dir, benign_path, prove_paths):
    result = {}
    for p in prove_paths:
        for line in open(p):
            r = json.loads(line)
            result[r["file"]] = r["result"]
    benign = {}
    for bp in benign_path.split(","):                 # several benign runs: TTP rules, low rules
        text = open(bp).read()
        for f, n in json.loads(text[text.index("{\n"):])["hits"].items():
            benign[f] = benign.get(f, 0) + n
    shutil.rmtree(OUT, ignore_errors=True)
    os.makedirs(OUT)
    kept = demoted = 0
    for f in sorted(os.listdir(rules_dir)):
        if result.get(f) != "fires":
            continue
        with open(os.path.join(rules_dir, f)) as fh:
            doc = yaml.safe_load(fh)
        n = int(benign.get(f) or 0)
        if n:
            # Normal systems raise it: never a detection on its own, and not counted
            # toward a burst of suspicious activity either.
            doc["x-intact-burst"] = False
            if doc.get("level") != "low":
                doc["level"] = "low"
                demoted += 1
            doc["x-intact"] = (f"Fired {n} time(s) on benign Windows activity (Nextron benign workstation + DC, "
                               f"1.24 M events): context only, not counted toward a burst.")
        with open(os.path.join(OUT, f), "w") as fh:
            yaml.safe_dump(doc, fh, sort_keys=False, allow_unicode=True, width=120)
        kept += 1
    with open(os.path.join(OUT, "NOTICE"), "w") as fh:
        fh.write(NOTICE)
    print(f"{kept} rule(s) installed in {os.path.normpath(OUT)}, {demoted} demoted to low for benign hits")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2], sys.argv[3:])
