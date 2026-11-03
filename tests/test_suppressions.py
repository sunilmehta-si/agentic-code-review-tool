import unittest

from agentic_code_review.rules.base import BANDIT_RULES, GOSEC_RULES, REGISTRY, ignored
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


class ExpiringSuppressionTests(unittest.TestCase):
    def test_until_date(self):
        import datetime
        line = "x = 1  # acr:ignore[ACR-APP-004] until=2026-12-31"
        self.assertTrue(ignored(line, "ACR-APP-004", today=datetime.date(2026, 12, 31)))
        self.assertFalse(ignored(line, "ACR-APP-004", today=datetime.date(2027, 1, 1)))
        self.assertTrue(ignored("x  # acr:ignore until=2999-01-01", "ACR-APP-001"))

    def test_lapsed_marker_reports_the_finding_with_a_note(self):
        from agentic_code_review.rules import base
        found = base.run_rules("a.py", "cfg = yaml.load(fh)  # acr:ignore[ACR-APP-004] until=2020-01-01\n", PY)
        self.assertEqual([f.rule_id for f in found], ["ACR-APP-004"])
        self.assertIn("expired on 2020-01-01", found[0].detail)
        self.assertEqual(ids("a.py", "cfg = yaml.load(fh)  # acr:ignore[ACR-APP-004] until=2999-01-01\n", PY), [])


GO = {"app", "lang:go"}


class OtherToolsMarkersTests(unittest.TestCase):
    """gosec's and bandit's own markers are reviewed decisions about the same findings."""

    def test_nolint_gosec_covers_the_rules_gosec_also_checks(self):
        line = "hashBytes := sha1.Sum(serialObj) //nolint:gosec // We are not using this for security purposes"
        self.assertTrue(ignored(line, "ACR-APP-007"))
        self.assertTrue(ignored("tlsCfg := &tls.Config{InsecureSkipVerify: true} //nolint:gosec // local only", "ACR-APP-005"))
        self.assertTrue(ignored("x() //nolint:govet,gosec", "ACR-APP-002"))
        self.assertTrue(ignored("x() //nolint:gosec,G401", "ACR-APP-007"))

    def test_gosec_hash_nosec_comment_counts_too(self):
        self.assertTrue(ignored("h := md5.New() // #nosec G401", "ACR-APP-007"))
        self.assertTrue(ignored("os.MkdirAll(d, 0o777) // #nosec", "ACR-APP-025"))

    def test_a_bare_nolint_or_another_linter_is_not_a_security_decision(self):
        self.assertFalse(ignored("h := sha1.New() //nolint", "ACR-APP-007"))
        self.assertFalse(ignored("h := sha1.New() //nolint:govet", "ACR-APP-007"))
        self.assertFalse(ignored("h := sha1.New() //nolint:gosecurity", "ACR-APP-007"))      # a different linter name

    def test_a_marker_does_not_reach_rules_its_tool_does_not_check(self):
        self.assertFalse(ignored("w.Header().Set(\"Access-Control-Allow-Origin\", \"*\") //nolint:gosec", "ACR-APP-009"))
        self.assertFalse(ignored("x = 1  # nosec", "ACR-APP-009"))
        self.assertFalse(ignored("jwt.ParseUnverified(t, c) //nolint:gosec", "ACR-APP-008"))
        self.assertFalse(ignored("srv := &http.Server{} # nosec", "ACR-APP-024"))             # bandit has no check for it

    def test_bandit_nosec_covers_its_rules_with_or_without_a_test_id(self):
        self.assertTrue(ignored("subprocess.run(cmd, shell=True)  # nosec", "ACR-APP-002"))
        self.assertTrue(ignored("subprocess.run(cmd, shell=True)  # nosec B602", "ACR-APP-002"))
        self.assertTrue(ignored("requests.get(url)  # nosec B113", "ACR-APP-021"))
        self.assertTrue(ignored("assert user.is_admin  # nosec", "ACR-APP-026"))

    def test_findings_on_a_marked_line_are_not_reported_and_the_same_line_unmarked_is(self):
        self.assertEqual(ids("a/util.go", "package a\nfunc f() { h := sha1.New() //nolint:gosec // naming, not security\n }\n", GO), [])
        self.assertIn("ACR-APP-007", ids("a/util.go", "package a\nfunc f() { h := sha1.New() }\n", GO))
        self.assertEqual(ids("a.py", "import subprocess\nsubprocess.run(cmd, shell=True)  # nosec B602\n", PY), [])
        self.assertIn("ACR-APP-002", ids("a.py", "import subprocess\nsubprocess.run(cmd, shell=True)\n", PY))

    def test_every_rule_a_marker_covers_exists(self):
        known = {info.rule_id for info, _ in REGISTRY}
        self.assertEqual((GOSEC_RULES | BANDIT_RULES) - known, set())
