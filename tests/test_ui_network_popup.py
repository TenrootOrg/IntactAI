"""Settings -> General -> Network card: the "Change IP / ports" popup.

Static checks only (no browser): the card must keep talking to the endpoints the
backend serves, offer a field for every public port change_ip.sh applies, and
warn before the agent port moves -- a silent agent_port change strands every
deployed Velociraptor agent.
"""

import os
import re
import unittest
from pathlib import Path

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HTML = os.path.join(ROOT, "modules", "nginx", "html")
SETTINGS = os.path.join(HTML, "partials", "settings.html")

PORT_KEYS = ("kibana", "portainer", "iris", "timesketch", "volweb", "velociraptor_agent")


def _read(path):
    return Path(path).read_text(encoding="utf-8")


def _card():
    s = _read(SETTINGS)
    start = s.index("<!-- Network (config.yaml")
    end = s.index("<!-- Online Upgrade", start)
    return s[start:end]


def _xdata(card):
    m = re.search(r'x-data="([^"]*)"', card)
    assert m, "Network card has no x-data"
    return m.group(1)


class NetworkPopup(unittest.TestCase):
    def test_card_sits_between_data_storage_and_online_upgrade(self):
        s = _read(SETTINGS)
        self.assertLess(s.index("<h4 class=\"text-white font-medium\">Data storage</h4>"),
                        s.index("<!-- Network (config.yaml"))
        self.assertIn("Change IP / ports", _card())

    def test_xdata_has_no_double_quote(self):
        # A double quote ends the attribute early and Alpine silently drops the card.
        xd = _xdata(_card())
        self.assertIn("async save()", xd, "x-data was cut short by a double quote")
        self.assertIn("problem()", xd)

    def test_endpoints(self):
        xd = _xdata(_card())
        self.assertIn("fetch('/api/system/network')", xd)
        self.assertRegex(xd, r"fetch\('/api/system/network', \{ method: 'POST'")

    def test_every_port_has_a_field(self):
        xd = _xdata(_card())
        for k in PORT_KEYS:
            self.assertIn("['%s', " % k, xd, "no popup field for %s" % k)
        card = _card()
        self.assertIn('x-model="form.ip"', card)
        self.assertIn('x-model="form.ports[f[0]]"', card)

    def test_agent_port_warning_and_extra_confirm(self):
        card = _card()
        self.assertIn('x-show="agentChanged()"', card)
        self.assertIn("bg-red-900", card)
        # Its own confirm, before the generic one.
        self.assertRegex(_xdata(card), r"if \(this\.agentChanged\(\) && !confirm\(")

    def test_client_validation(self):
        xd = _xdata(_card())
        for msg in ("65535", "belong to the dashboard", "cannot share port", "Nothing changed"):
            self.assertIn(msg, xd)

    def test_after_save_points_at_actions_and_new_url(self):
        card = _card()
        self.assertIn("Running - follow it in Settings -> Actions", card)
        self.assertIn("'https://' + ip + '/'", card)
        self.assertIn("open it in a moment", card)
        self.assertIn("$dispatch('show-system-actions')", card)

    def test_card_classes_exist_in_built_tailwind(self):
        # tailwind.css is prebuilt and committed; a class not in it renders as
        # nothing (the popup once had no dimmed backdrop because of bg-black/60).
        css = _read(os.path.join(HTML, "css", "tailwind.css"))
        classes = set()
        for attr in re.findall(r'\sclass="([^"]*)"', _card()):
            classes.update(attr.split())
        missing = [c for c in sorted(classes)
                   if "." + re.sub(r"([:/.\[\]])", r"\\\1", c) not in css]
        self.assertEqual(missing, [], "classes missing from tailwind.css: %s" % missing)

    def test_cache_busting_bumped(self):
        loader = _read(os.path.join(HTML, "js", "bootstrap", "partial-loader.js"))
        index = _read(os.path.join(HTML, "index.html"))
        self.assertGreaterEqual(int(re.search(r"partials/\$\{name\}\.html\?v=(\d+)", loader).group(1)), 296)
        self.assertGreaterEqual(int(re.search(r"partial-loader\.js\?v=(\d+)", index).group(1)), 280)


if __name__ == "__main__":
    unittest.main()
