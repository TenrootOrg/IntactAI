"""The startup prune must not delete images the platform itself needs.

app.py reclaims the images of modules the operator has switched off. The
hazard is that several image repos are SHARED: timesketch ships its own nginx,
so module_image_repos('timesketch') names the bare `nginx` repo -- the same
repo the platform's own reverse proxy lives in. With timesketch disabled,
`docker images nginx` matches intact_nginx's image.

The guard in front of that is an in-use check, and it is genuinely not enough.
It protects a RUNNING appliance; it cannot protect one that is still being
built. During an install the backend is step 7 of 8 and nginx is step 8, so
when the backend boots and runs this, intact_nginx does not exist, nothing
references the image, and it is deleted seconds before the installer starts it.

Measured on a clean install with timesketch disabled: "No such image:
nginx:1.31.3-alpine", one line after the installer logged that same image as
successfully loaded, and the install failed with Nginx unhealthy. Found by the
e2e's backend-only scenario, which is the only configuration that disables
timesketch.
"""

import ast
import os
import re
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKEND = os.path.join(ROOT, "modules/backend")
APP = os.path.join(BACKEND, "app.py")


def _image_table(name):
    """A dict-of-lists-of-tuples read out of image_map.py via the AST.

    Parsed, not imported: `services/__init__.py` pulls in the whole backend and
    tries to open the database, and this suite has to run on a dev box with no
    appliance around it.
    """
    src = open(os.path.join(BACKEND, "services/image_map.py"),
               encoding="utf-8").read()
    for node in ast.parse(src).body:
        if isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id == name for t in node.targets):
            return ast.literal_eval(node.value)
    return {}


class TestSharedReposAreRealHazards(unittest.TestCase):
    """Proves the overlap exists, so the guard below is not theoretical."""

    def test_a_disableable_module_claims_the_platform_nginx_repo(self):
        table = _image_table("TRANSITIVE_IMAGES")
        self.assertTrue(table, "could not parse TRANSITIVE_IMAGES")
        repos = {pattern.rsplit(":", 1)[0]
                 for _dep, pattern, _tar in table.get("timesketch", [])}
        self.assertIn(
            "nginx", repos,
            "if timesketch no longer claims the bare `nginx` repo this test "
            "has lost its subject -- check whether the prune guard is still "
            "needed before deleting it")

    def test_the_platform_nginx_shares_that_repo(self):
        """The appliance's own proxy really is `nginx:<tag>`, not a distinct
        repo that would never collide."""
        compose = os.path.join(ROOT, "modules/nginx/docker-compose.yaml")
        with open(compose, encoding="utf-8") as fh:
            body = fh.read()
        self.assertRegex(
            body, r"image:\s*nginx:\$\{NGINX_VERSION",
            "the platform proxy no longer lives under the shared `nginx` repo")


class TestThePruneProtectsThePlatform(unittest.TestCase):

    def setUp(self):
        with open(APP, encoding="utf-8") as fh:
            self.src = fh.read()

    def test_app_py_still_parses(self):
        ast.parse(self.src)

    def _prune_block(self):
        start = self.src.index("disabled-module image prune")
        head = self.src.rindex("try:", 0, start)
        return self.src[head:start]

    def test_the_platform_images_are_added_to_the_in_use_set(self):
        block = self._prune_block()
        self.assertIn("_inuse |=", block,
                      "nothing protects the platform's own images from a "
                      "disabled module's reclaim")
        for ref in ("nginx:%s", "intact-backend:%s", "tusproject/tusd:%s"):
            self.assertIn(ref, block,
                          f"{ref} is not protected; a disabled module sharing "
                          f"its repo can delete it mid-install")

    def test_the_protection_comes_from_config_not_a_hard_coded_tag(self):
        """A pinned literal would rot the moment versions.nginx moved, and the
        failure would be silent -- the prune would simply stop matching."""
        # Comments stripped: the block quotes the observed error message,
        # which legitimately contains a pinned tag.
        block = "\n".join(l for l in self._prune_block().splitlines()
                          if not l.lstrip().startswith("#"))
        self.assertRegex(
            block, r"_vers\s*=\s*\(cfg\.get\('versions'\) or \{\}\)",
            "the protected refs must be built from config.yaml's versions")
        self.assertNotRegex(
            block, r"nginx:1\.\d+\.\d+-alpine",
            "a hard-coded nginx tag stops matching the moment the pin moves")

    def test_nothing_is_pruned_without_an_in_use_check(self):
        block = self.src[self.src.index("_inuse = set("):
                         self.src.index("disabled-module image prune")]
        rmi = block.index('"docker", "rmi"')
        guard = block.index("_ref in _inuse")
        self.assertLess(guard, rmi,
                        "an image is removed before it is checked against the "
                        "in-use set")


if __name__ == "__main__":
    unittest.main(verbosity=2)
