"""scripts/migrate/transform_config.py — the risx-mssp -> intact config transform.

This file is the first test of it. It has shipped unguarded, and it is the piece
that decides whether a customer's entire deployed Velociraptor fleet reconnects:
a client is pinned to Client.ca_certificate, Client.nonce and Client.server_urls,
and Velociraptor's own docs say of the CA "Do not change this!". If the transform
drops or rewrites any of those, every client is stranded silently — the server
simply never hears from them again.

The configs here are synthetic and carry fake key material.
"""

import io
import os
import subprocess
import sys
import tempfile
import unittest

try:
    import yaml
except ImportError:                                   # pragma: no cover
    yaml = None

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TRANSFORM = os.path.join(ROOT, "scripts/migrate/transform_config.py")


def _legacy(**over):
    """A config shaped like risx-mssp's entrypoint produces one."""
    cfg = {
        "version": {"name": "velociraptor", "version": "0.74"},
        "Client": {
            "server_urls": ["https://10.9.8.7:8000/"],
            "ca_certificate": "-----BEGIN CERTIFICATE-----\nFAKECA\n-----END CERTIFICATE-----",
            "nonce": "AAAAAAAAAAA=",
            "use_self_signed_ssl": True,
        },
        "API": {"bind_address": "127.0.0.1", "bind_port": 8001},
        "GUI": {
            "bind_address": "127.0.0.1", "bind_port": 8889,
            "public_url": "https://10.9.8.7/velociraptor/app/index.html",
            "reverse_proxy": [{"route": "/velociraptor/kibana/",
                               "url": "http://kibana:5601/", "require_auth": True}],
            "gw_certificate": "GWCERT", "gw_private_key": "GWKEY",
        },
        "CA": {"private_key": "-----BEGIN RSA PRIVATE KEY-----\nFAKEKEY\n-----END RSA PRIVATE KEY-----"},
        "Frontend": {
            "hostname": "VelociraptorServer", "bind_address": "0.0.0.0", "bind_port": 8000,
            "certificate": "FECERT", "private_key": "FEKEY",
            "public_path": "public",
            "default_server_monitoring_artifacts": ["Custom.Elastic.Flows.Upload"],
        },
        "Datastore": {"location": ".", "filestore_directory": "."},
        "Logging": {"output_directory": ".", "separate_logs_per_component": True},
        "obfuscation_nonce": "OBFUSCATE",
    }
    for k, v in over.items():
        if v is None:
            cfg.pop(k, None)
        else:
            cfg[k] = v
    return cfg


@unittest.skipIf(yaml is None, "PyYAML not installed")
class TheTransform(unittest.TestCase):
    def _run(self, cfg, *extra, domain="10.9.8.7"):
        d = tempfile.mkdtemp(prefix="xform-")
        src, dst = os.path.join(d, "in.yaml"), os.path.join(d, "out.yaml")
        with io.open(src, "w", encoding="utf-8") as fh:
            yaml.safe_dump(cfg, fh)
        r = subprocess.run([sys.executable, TRANSFORM, src, dst, "--domain", domain,
                            *extra], capture_output=True, text=True, timeout=120)
        out = None
        if os.path.exists(dst) and os.path.getsize(dst):
            out = yaml.safe_load(io.open(dst, encoding="utf-8"))
        return r, out

    # --- the identity: this is the whole point --------------------------
    def test_every_field_a_client_is_pinned_to_survives_byte_for_byte(self):
        cfg = _legacy()
        r, out = self._run(cfg)
        self.assertEqual(r.returncode, 0, r.stderr)
        for sect, key in (("CA", "private_key"),
                          ("Client", "ca_certificate"),
                          ("Client", "nonce"),
                          ("Client", "server_urls"),
                          ("Frontend", "certificate"),
                          ("Frontend", "private_key"),
                          ("GUI", "gw_certificate"),
                          ("GUI", "gw_private_key")):
            self.assertEqual(out[sect][key], cfg[sect][key], f"{sect}.{key} was altered")

    def test_the_obfuscation_nonce_survives(self):
        """Datastore filenames are obfuscated with it — a new one makes any
        transplanted datastore unreadable."""
        r, out = self._run(_legacy())
        self.assertEqual(out["obfuscation_nonce"], "OBFUSCATE")

    def test_a_config_missing_the_nonce_is_refused_not_repaired(self):
        cfg = _legacy()
        del cfg["Client"]["nonce"]
        r, out = self._run(cfg)
        self.assertEqual(r.returncode, 2)
        self.assertIn("Client.nonce", r.stderr)
        self.assertIsNone(out, "refused input must not produce an output file")

    def test_a_config_missing_the_CA_is_refused(self):
        cfg = _legacy()
        del cfg["CA"]["private_key"]
        r, _ = self._run(cfg)
        self.assertEqual(r.returncode, 2)
        self.assertIn("trust chain", r.stderr)

    # --- the rewrite: intact's layout -----------------------------------
    def test_the_datastore_is_rebased_off_the_legacy_bind_dir(self):
        """Legacy kept config+datastore in one dir ('.'); intact mounts a
        separate volume at /var./. Left alone, the server writes its datastore
        into the config bind mount."""
        r, out = self._run(_legacy())
        self.assertEqual(out["Datastore"]["location"], "/var./")
        self.assertEqual(out["Datastore"]["filestore_directory"], "/var./")

    def test_public_path_is_removed_because_0_76_hard_fails_on_it(self):
        r, out = self._run(_legacy())
        self.assertNotIn("public_path", out["Frontend"])

    def test_the_legacy_elk_monitoring_artifact_is_removed(self):
        """Custom.Elastic.Flows.Upload streams to the retired risx ELK."""
        r, out = self._run(_legacy())
        self.assertNotIn("default_server_monitoring_artifacts", out["Frontend"])

    def test_the_kibana_reverse_proxy_is_removed(self):
        r, out = self._run(_legacy())
        self.assertNotIn("reverse_proxy", out["GUI"])

    def test_the_gui_is_rewired_for_intacts_nginx(self):
        r, out = self._run(_legacy(), domain="192.168.1.5")
        self.assertEqual(out["GUI"]["base_path"], "/velociraptor")
        self.assertTrue(out["GUI"]["use_plain_http"])
        self.assertEqual(out["GUI"]["public_url"],
                         "http://192.168.1.5/velociraptor/app/index.html")

    # --- the shape gate --------------------------------------------------
    def test_a_deviating_port_is_refused_because_compose_publishes_fixed_ones(self):
        cfg = _legacy()
        cfg["Frontend"]["bind_port"] = 9999
        r, out = self._run(cfg)
        self.assertEqual(r.returncode, 2)
        self.assertIsNone(out)

    def test_the_port_gate_can_be_overridden_deliberately(self):
        cfg = _legacy()
        cfg["Frontend"]["bind_port"] = 9999
        r, out = self._run(cfg, "--allow-shape-mismatch")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIsNotNone(out)

    # --- the warning that matters ----------------------------------------
    def test_it_warns_when_the_clients_url_is_not_this_box(self):
        """The one thing no config edit can fix."""
        r, _ = self._run(_legacy(), domain="192.168.1.5")   # clients dial 10.9.8.7
        self.assertIn("stranded", r.stdout + r.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
