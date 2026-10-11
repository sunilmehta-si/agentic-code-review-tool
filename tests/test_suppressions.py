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


class StructuralSuppressionTests(unittest.TestCase):
    MANIFEST = ("apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\nspec:\n  template:\n    spec:\n"
                "      securityContext:\n        runAsNonRoot: true\n      containers:\n"
                "        - name: web{marker}\n          image: web:1.2.3\n")

    def test_structural_rule_honours_marker_on_the_reported_line(self):
        k8s = {"kubernetes"}
        self.assertIn("ACR-K8S-007", ids("d.yaml", self.MANIFEST.format(marker=""), k8s))
        self.assertNotIn("ACR-K8S-007", ids("d.yaml", self.MANIFEST.format(marker="  # acr:ignore[ACR-K8S-007]"), k8s))


class ScannerSuppressionTests(unittest.TestCase):
    def test_scanner_findings_honour_inline_markers(self):
        from unittest import mock

        from agentic_code_review.engine import review
        from agentic_code_review.models import Finding, Severity
        from agentic_code_review.scanners.tools import Scanner
        from tests.helpers import git_repo

        def run(root, files):
            return [Finding("hadolint:DL3008", "pin apt", Severity.LOW, "Dockerfile", n, "hadolint", "other")
                    for n in (2, 3)]
        fake = Scanner("hadolint", "hadolint", frozenset({"*"}), run)
        root = git_repo({"README.md": "x\n"})
        (root / "Dockerfile").write_text("FROM a:1\nRUN apt-get install -y curl  # acr:ignore[hadolint:*]\n"
                                         "RUN apt-get install -y git\nUSER 1\n")
        with mock.patch("agentic_code_review.engine.available_scanners", return_value=[fake]), \
                mock.patch("agentic_code_review.scanners.tools.ALL_SCANNERS", [fake]):
            result = review(root)
        self.assertEqual([f.line for f in result.findings if f.tool == "hadolint"], [3])


class ScopedMarkerDoesNotHideOtherRules(unittest.TestCase):
    def test_marker_for_one_rule_leaves_line_rules_of_other_files_working(self):
        # Before suppression was centralised, any `acr:ignore` text made these rules skip the whole line.
        workflow = "permissions: {}\njobs:\n  a:\n    steps:\n      - uses: some/action@v1  # acr:ignore[ACR-GHA-004]\n"
        self.assertEqual(ids(".github/workflows/x.yml", workflow, {"github-actions"}), ["ACR-GHA-003"])
        dockerfile = "FROM base  # acr:ignore[ACR-DOCKER-002]\nUSER 1\n"
        self.assertEqual(ids("Dockerfile", dockerfile, {"dockerfile"}), ["ACR-DOCKER-001"])
