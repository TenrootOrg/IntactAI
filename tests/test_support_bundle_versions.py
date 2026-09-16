"""A support bundle must state what the box is, without a round trip.

A bundle arrived on 2026-09-14 with a fusion crash in it. Answering it needed
the release the box was on -- the failure turned out to be a known bug, already
fixed in the next release -- and the bundle said so only as one line inside
versions.txt. The host OS was not in there at all: `uname` runs inside the
backend CONTAINER, so system_info.txt named the container's kernel and nothing
about the appliance. config.yaml, which holds the enabled modules, the domain
and the pinned versions the upgrade plans against, was not collected either.

So the bundle now carries versions.json -- release, module pins, containers with
image tag and health, and the host OS as the DOCKER DAEMON reports it -- plus a
redacted config.yaml, and the release is named in manifest.json itself.

These tests run the collectors against a fake appliance tree; the docker calls
are stubbed, because what is being pinned is the SHAPE of the output a support
engineer (or a script) reads, not this box's own docker.
"""

import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (os.path.dirname(os.path.abspath(__file__)),
           os.path.join(ROOT, "modules", "backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402

from services import support_bundle as sb  # noqa: E402

PS_JSON = (
    '{"Names":"intact_backend","Image":"intact-backend:intact-20260903",'
    '"State":"running","Status":"Up 2 hours (healthy)","HealthStatus":"healthy",'
    '"CreatedAt":"2026-09-14 12:00:00 +0000 UTC"}\n'
    '{"Names":"intact_velociraptor","Image":"velociraptor-server:0.77.2",'
    '"State":"running","Status":"Up 2 hours","HealthStatus":"",'
    '"CreatedAt":"2026-09-14 12:00:00 +0000 UTC"}\n'
    # a registry with a port: the colon in the HOST is not a tag
    '{"Names":"intact_odd","Image":"localhost:5000/thing","State":"exited",'
    '"Status":"Exited (0) 1 day ago","HealthStatus":"","CreatedAt":"x"}\n'
)
INFO_JSON = json.dumps({
    "OperatingSystem": "Ubuntu 24.04.3 LTS", "OSType": "linux", "OSVersion": "24.04",
    "KernelVersion": "6.8.0-86-generic", "Architecture": "x86_64", "NCPU": 6,
    "MemTotal": 16324251648, "ServerVersion": "29.6.2",
})


def fake_run(cmd, timeout=60):
    if "docker ps" in cmd:
        return {"stdout": PS_JSON, "stderr": "", "rc": 0}
    if "docker info" in cmd:
        return {"stdout": INFO_JSON, "stderr": "", "rc": 0}
    if "compose version" in cmd:
        return {"stdout": "5.4.0\n", "stderr": "", "rc": 0}
    return {"stdout": "", "stderr": "", "rc": 0}


def appliance(tmp, version="intact-20260903", config="domain: box.local\n"):
    """A fake /app/workdir: VERSION, module .envs and config.yaml."""
    with open(os.path.join(tmp, "VERSION"), "w") as fh:
        fh.write(version + "\n")
    for mod, body in (("backend", "BACKEND_VERSION=intact-20260903\nDB_PASSWORD=hunter2\n"),
                      ("velociraptor", "VELOCIRAPTOR_VERSION=0.77.2\n")):
        d = os.path.join(tmp, "modules", mod)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, ".env"), "w") as fh:
            fh.write(body)
    if config is not None:
        with open(os.path.join(tmp, "config.yaml"), "w") as fh:
            fh.write(config)
    return tmp


class VersionsJson(unittest.TestCase):

    def setUp(self):
        self._run, sb._run = sb._run, fake_run
        self.tmp = tempfile.mkdtemp()
        self.dest = os.path.join(self.tmp, "versions.json")
        appliance(self.tmp)
        self.env = sb._environment_json(self.tmp, self.dest, lambda *a, **k: None)

    def tearDown(self):
        sb._run = self._run

    def test_it_is_valid_json_on_disk(self):
        with open(self.dest) as fh:
            self.assertEqual(self.env["intact_version"], json.load(fh)["intact_version"])

    def test_it_names_the_release(self):
        self.assertEqual("intact-20260903", self.env["intact_version"])

    def test_it_carries_every_module_pin(self):
        self.assertEqual("intact-20260903", self.env["module_pins"]["backend"]["BACKEND_VERSION"])
        self.assertEqual("0.77.2", self.env["module_pins"]["velociraptor"]["VELOCIRAPTOR_VERSION"])

    def test_no_env_value_other_than_a_version_is_collected(self):
        self.assertNotIn("hunter2", json.dumps(self.env))

    def test_it_carries_each_container_with_its_tag_and_health(self):
        by = {c["name"]: c for c in self.env["containers"]}
        self.assertEqual("intact-20260903", by["intact_backend"]["tag"])
        self.assertEqual("healthy", by["intact_backend"]["health"])
        self.assertEqual("0.77.2", by["intact_velociraptor"]["tag"])
        self.assertIsNone(by["intact_velociraptor"]["health"])
        self.assertEqual("exited", by["intact_odd"]["state"])

    def test_a_registry_port_is_not_read_as_a_tag(self):
        by = {c["name"]: c for c in self.env["containers"]}
        self.assertIsNone(by["intact_odd"]["tag"])

    def test_it_carries_the_host_os_not_the_containers(self):
        self.assertEqual("Ubuntu 24.04.3 LTS", self.env["host"]["os"])
        self.assertEqual("6.8.0-86-generic", self.env["host"]["kernel"])
        self.assertEqual("29.6.2", self.env["host"]["docker"])
        self.assertEqual("5.4.0", self.env["host"]["docker_compose"])

    def test_a_box_with_no_VERSION_file_still_produces_the_file(self):
        tmp = tempfile.mkdtemp()
        env = sb._environment_json(tmp, os.path.join(tmp, "v.json"), lambda *a, **k: None)
        self.assertIsNone(env["intact_version"])
        self.assertTrue(os.path.isfile(os.path.join(tmp, "v.json")))


class VersionsTxtAndJsonAgree(unittest.TestCase):

    def test_one_parser_feeds_both(self):
        tmp = appliance(tempfile.mkdtemp())
        sb._version_manifest(tmp, os.path.join(tmp, "versions.txt"), lambda *a, **k: None)
        txt = open(os.path.join(tmp, "versions.txt")).read()
        self.assertIn("VERSION = intact-20260903", txt)
        for mod, key, val in sb._read_version_pins(tmp):
            self.assertIn(f"modules/{mod}/.env  {key} = {val}", txt)


class ConfigYaml(unittest.TestCase):

    def test_it_is_collected(self):
        tmp = appliance(tempfile.mkdtemp())
        out = tempfile.mkdtemp()
        res = sb._copy_config_yaml(tmp, out, lambda *a, **k: None)
        self.assertTrue(res["included"])
        self.assertIn("domain: box.local", open(os.path.join(out, "config.yaml")).read())

    def test_secrets_in_it_are_redacted_before_it_is_archived(self):
        tmp = appliance(tempfile.mkdtemp(),
                        config="domain: box.local\nadmin_password: hunter2\napi_key: sk-abcdefghijklmnopqrstuvwx\n")
        out = tempfile.mkdtemp()
        res = sb._copy_config_yaml(tmp, out, lambda *a, **k: None)
        body = open(os.path.join(out, "config.yaml")).read()
        self.assertNotIn("hunter2", body)
        self.assertNotIn("sk-abcdefghijklmnopqrstuvwx", body)
        self.assertIn("domain: box.local", body)
        self.assertGreater(res["redacted_lines"], 0)

    def test_a_box_without_one_does_not_fail_the_bundle(self):
        tmp = appliance(tempfile.mkdtemp(), config=None)
        res = sb._copy_config_yaml(tmp, tempfile.mkdtemp(), lambda *a, **k: None)
        self.assertFalse(res["included"])


class TheManifestNamesTheRelease(unittest.TestCase):
    """manifest.json is what a support engineer opens first."""

    def test_the_builder_fills_in_the_version_and_host(self):
        src = open(os.path.join(ROOT, "modules/backend/services/support_bundle.py")).read()
        self.assertIn("manifest['intact_version'] = env.get('intact_version')", src)
        self.assertIn("manifest['host'] = env.get('host') or {}", src)
        self.assertIn("manifest['config_yaml'] = _copy_config_yaml(", src)


if __name__ == "__main__":
    unittest.main(verbosity=2)
