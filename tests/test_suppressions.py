import unittest

from agentic_code_review.rules.base import ignored
from tests.helpers import ids

PY = {"app", "lang:python"}


class InlineSuppressionTests(unittest.TestCase):
    def test_bare_marker_silences_every_rule(self):
        self.assertTrue(ignored("x = 1  # acr:ignore", "ACR-APP-001"))
        self.assertTrue(ignored("x = 1  # acr:ignore - reviewed", "semgrep:python.x"))

    def test_scoped_marker_silences_only_listed_rules(self):
        line = "x = 1  # acr:ignore[ACR-APP-004, semgrep:*]"
        self.assertTrue(ignored(line, "ACR-APP-004"))
        self.assertTrue(ignored(line, "semgrep:python.lang.security.audit"))
        self.assertFalse(ignored(line, "ACR-APP-002"))
        self.assertTrue(ignored("# acr:ignore[acr-k8s-*]", "ACR-K8S-005"))  # ids are case-insensitive

    def test_unmarked_line_is_not_ignored(self):
        self.assertFalse(ignored("x = 1", "ACR-APP-001"))

    def test_scoped_marker_keeps_other_findings_on_the_line(self):
        src = "subprocess.run(yaml.load(fh), shell=True)  # acr:ignore[ACR-APP-004]\n"
        self.assertEqual(ids("a.py", src, PY), ["ACR-APP-002"])
        self.assertEqual(ids("a.py", src.replace("[ACR-APP-004]", ""), PY), [])
