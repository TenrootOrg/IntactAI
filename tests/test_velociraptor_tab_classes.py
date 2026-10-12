"""Every class the Settings → Velociraptor tab uses exists in the PREBUILT css/tailwind.css.

The dashboard ships a compiled Tailwind file, not the JIT: a class that is not
in it does nothing. On 2026-10-12 a summary built with gap-10 / h-1.5 /
items-end / items-baseline rendered with its labels run together and no bar,
and an audit found three older ones (z-20 on the pilot dropdown, so it could
sit under other elements; disabled:opacity-40, so disabled buttons did not
look disabled; w-64). Use a class that exists, or an inline style.
"""
import os
import re
import unittest

_HTML = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "modules/nginx/html")


class VelociraptorTabClasses(unittest.TestCase):
    def test_every_class_exists_in_the_prebuilt_css(self):
        page = open(os.path.join(_HTML, "partials/settings.html"), encoding="utf-8").read()
        panel = page[page.index("<!-- Velociraptor Tab"):page.index("<!-- Cloud Tab -->")]
        css = open(os.path.join(_HTML, "css/tailwind.css"), encoding="utf-8").read()
        classes = set()
        for m in re.finditer(r'(?<!:)class="([^"]*)"', panel):
            classes.update(m.group(1).split())
        for m in re.finditer(r':class="([^"]*)"', panel):           # classes inside Alpine expressions
            for quoted in re.findall(r"'([^']*)'", m.group(1)):
                classes.update(quoted.split())
        classes = {c for c in classes if re.match(r"^[a-z][a-z0-9:\-./]*$", c) and not c.endswith(":")}
        escaped = lambda c: "." + c.replace(":", "\\:").replace(".", "\\.").replace("/", "\\/")
        missing = sorted(c for c in classes if escaped(c) not in css)
        self.assertGreater(len(classes), 50)
        self.assertEqual(missing, [], "not in the prebuilt css/tailwind.css -- use one that is, or an inline style")


if __name__ == "__main__":
    unittest.main()
