"""Data events come from the trail's own bucket: data only, window only, bounded.

LookupEvents never returns S3 object reads/writes/deletes or Lambda invokes, so a live
scan could not see a mass download or an S3 ransomware run (2026-10-26).
"""
import gzip
import io
import json
import os
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (_HERE, os.path.join(os.path.dirname(_HERE), "modules/backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
_optional_deps.stub("markupsafe", "werkzeug", "werkzeug.utils")

from services.aws import boto_client, logbucket_runner as lb  # noqa: E402

ACCT = "111122223333"
WINDOW = {"enabled": True, "mode": "between", "start_datetime": "2026-10-20T00:00:00Z", "end_datetime": "2026-10-25T23:59:59Z"}


def rec(name, t, data=True):
    return {"eventName": name, "eventTime": t, "eventSource": "s3.amazonaws.com",
            "eventCategory": "Data" if data else "Management", "managementEvent": not data,
            "userIdentity": {"type": "IAMUser", "userName": "alice"}}


class Fake:
    def __init__(self, selectors, objects):
        self.selectors, self.objects, self.got = selectors, objects, []

    # cloudtrail
    def describe_trails(self, **kw):
        return {"trailList": [{"Name": "main", "TrailARN": "arn:trail", "S3BucketName": "logs", "IsMultiRegionTrail": True,
                               "HomeRegion": "us-east-1"}]}

    def get_event_selectors(self, **kw):
        return self.selectors

    # sts
    def get_caller_identity(self):
        return {"Account": ACCT}

    # s3
    def get_bucket_location(self, **kw):
        return {"LocationConstraint": None}

    def list_objects_v2(self, Bucket, Prefix, **kw):
        keys = [k for k in self.objects if k.startswith(Prefix)]
        if kw.get("Delimiter"):
            subs = sorted({Prefix + k[len(Prefix):].split("/")[0] + "/" for k in keys})
            return {"CommonPrefixes": [{"Prefix": p} for p in subs]}
        return {"KeyCount": len(keys[:kw.get("MaxKeys", 1000)]), "Contents": [{"Key": k} for k in keys]}

    def get_paginator(self, _name):
        outer = self

        class P:
            def paginate(self, Bucket, Prefix):
                return [outer.list_objects_v2(Bucket, Prefix)]
        return P()

    def get_object(self, Bucket, Key):
        self.got.append(Key)
        return {"Body": io.BytesIO(gzip.compress(json.dumps({"Records": self.objects[Key]}).encode()))}


def run(fake, **kw):
    logs = []
    orig = boto_client.client
    boto_client.client = lambda *a, **k: fake
    try:
        out = lb.collect_trail_data_events({"access_key_id": "x"}, regions=["us-east-1"], time_filter=WINDOW,
                                           log_func=lambda m, l="info": logs.append(m), **kw)
    finally:
        boto_client.client = orig
    return out, logs


DATA_SEL = {"EventSelectors": [{"DataResources": [{"Type": "AWS::S3::Object", "Values": ["arn:aws:s3"]}]}]}


class DataEventsFromTheTrailBucket(unittest.TestCase):
    def objects(self, prefix=f"AWSLogs/{ACCT}/CloudTrail/us-east-1"):
        return {f"{prefix}/2026/10/25/a.json.gz": [rec("GetObject", "2026-10-25T10:00:00Z"),
                                                    rec("CreateUser", "2026-10-25T10:00:01Z", data=False)],
                f"{prefix}/2026/10/21/b.json.gz": [rec("DeleteObject", "2026-10-21T09:00:00Z")],
                f"{prefix}/2026/10/19/c.json.gz": [rec("GetObject", "2026-10-19T09:00:00Z")]}

    def test_only_data_events_inside_the_window(self):
        out, logs = run(Fake(DATA_SEL, self.objects()))
        self.assertEqual(sorted(r["eventName"] for r in out), ["DeleteObject", "GetObject"])
        self.assertTrue(all(r["EventSource"] == "AWS.CloudTrail" and r["_source"] == "cloudtrail_data" for r in out))

    def test_an_organization_trail_layout_is_found(self):
        out, _ = run(Fake(DATA_SEL, self.objects(prefix=f"AWSLogs/o-abc123/{ACCT}/CloudTrail/us-east-1")))
        self.assertEqual(len(out), 2)

    def test_advanced_selectors_count(self):
        adv = {"AdvancedEventSelectors": [{"FieldSelectors": [{"Field": "eventCategory", "Equals": ["Data"]}]}]}
        self.assertEqual(len(run(Fake(adv, self.objects()))[0]), 2)

    def test_no_data_trail_says_so_and_reads_nothing(self):
        fake = Fake({"EventSelectors": [{"ReadWriteType": "All", "DataResources": []}]}, self.objects())
        out, logs = run(fake)
        self.assertEqual(out, [])
        self.assertEqual(fake.got, [])
        self.assertTrue(any("no trail records data events" in m for m in logs))

    def test_the_cap_reads_newest_first_and_says_where_it_stopped(self):
        old = lb.MAX_FILES
        lb.MAX_FILES = 1
        try:
            fake = Fake(DATA_SEL, self.objects())
            out, logs = run(fake)
        finally:
            lb.MAX_FILES = old
        self.assertEqual(len(fake.got), 1)
        self.assertIn("/2026/10/25/", fake.got[0])
        self.assertTrue(any("stopped at" in m and "not read" in m for m in logs))

    def test_a_bad_file_costs_only_itself(self):
        objs = self.objects()
        fake = Fake(DATA_SEL, objs)
        real = fake.get_object
        fake.get_object = lambda Bucket, Key: (_ for _ in ()).throw(ValueError("corrupt")) if "/25/" in Key else real(Bucket, Key)
        out, logs = run(fake)
        self.assertEqual([r["eventName"] for r in out], ["DeleteObject"])


if __name__ == "__main__":
    unittest.main()
