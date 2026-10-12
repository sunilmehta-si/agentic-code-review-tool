import io
import json
import unittest
from contextlib import redirect_stdout
from unittest import mock

from agentic_code_review import report
from agentic_code_review.cli import main
from agentic_code_review.engine import dedupe, review
from agentic_code_review.models import Finding, Severity
from agentic_code_review.scanners import tools
from tests.helpers import git_repo


class EngineTests(unittest.TestCase):
    def setUp(self):
        self.root = git_repo({"app.py": "import yaml\ncfg = yaml.load(fh)\n"})
        (self.root / "app.py").write_text("import yaml\ncfg = yaml.load(fh)\nsubprocess.run(c, shell=True)\n")

    def test_only_changed_lines_are_reported(self):
        result = review(self.root, use_scanners=False)
        self.assertEqual([(f.rule_id, f.line) for f in result.findings], [("ACR-APP-002", 3)])

    def test_full_mode_reports_old_issues_too(self):
        result = review(self.root, full=True, use_scanners=False)
        self.assertIn("ACR-APP-004", [f.rule_id for f in result.findings])

    def test_dedupe_merges_across_tools_only(self):
        a = Finding("ACR-SEC-001", "a", Severity.CRITICAL, "x", 3, "acr", "secrets")
        b = Finding("gitleaks:k", "b", Severity.HIGH, "x", 3, "gitleaks", "secrets")
        c = Finding("ACR-SEC-002", "c", Severity.HIGH, "x", 3, "acr", "secrets")
        merged = dedupe([b, a, c])
        self.assertEqual(sorted(f.rule_id for f in merged), ["ACR-SEC-001", "ACR-SEC-002"])
        self.assertIn("gitleaks", merged[0].detail)


class ParallelScannerTests(unittest.TestCase):
    def test_scanners_run_concurrently_and_merge_in_order(self):
        import time
        from agentic_code_review.scanners.tools import Scanner

        def slow(name, line):
            def run(root, files):
                time.sleep(0.3)
                return [Finding(f"{name}:x", name, Severity.LOW, "Dockerfile", line, name, "container")]
            return Scanner(name, name, frozenset({"*"}), run)

        root = git_repo({"README.md": "x\n"})
        (root / "Dockerfile").write_text("FROM a:1\nUSER 1\nRUN true\n")
        fakes = [slow("one", 1), slow("two", 2), slow("three", 3)]
        with mock.patch("agentic_code_review.engine.available_scanners", return_value=fakes), \
                mock.patch("agentic_code_review.scanners.tools.ALL_SCANNERS", fakes):
            start = time.monotonic()
            result = review(root)
            elapsed = time.monotonic() - start
        self.assertLess(elapsed, 0.8)  # three 0.3s scanners in parallel, not 0.9s in series
        self.assertEqual(result.scanners_run, ["one", "two", "three"])


class ReportTests(unittest.TestCase):
    def test_sarif_shape(self):
        root = git_repo({"README.md": "x\n"})
        (root / "Dockerfile").write_text("FROM python:latest\n")
        sarif = json.loads(report.to_sarif(review(root, use_scanners=False)))
        run = sarif["runs"][0]
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertTrue(run["results"])
        self.assertIn("security-severity", run["tool"]["driver"]["rules"][0]["properties"])
        self.assertEqual(run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], "Dockerfile")

    def test_summary_by_area(self):
        root = git_repo({"README.md": "x\n"})
        (root / "Dockerfile").write_text("FROM python:latest\nRUN curl -s https://x.sh | sh\n")
        (root / "app.py").write_text("subprocess.run(c, shell=True)\n")
        md = report.to_markdown(review(root, use_scanners=False))
        self.assertIn("**By area:** Containers 3 · App code 1", md)

    def test_false_positives_hidden_from_reports(self):
        root = git_repo({"README.md": "x\n"})
        (root / "Dockerfile").write_text("FROM python:latest\nUSER 1000\n")
        result = review(root, use_scanners=False)
        result.findings[0].ai_verdict = "false_positive"
        self.assertNotIn(result.findings[0].rule_id, report.to_markdown(result))


class CliTests(unittest.TestCase):
    def test_exit_code_gates_on_severity(self):
        root = git_repo({"README.md": "x\n"})
        (root / "Dockerfile").write_text("FROM python:3.12\nRUN curl -s https://x.sh | sh\nUSER 1000\n")
        with redirect_stdout(io.StringIO()):
            self.assertEqual(main(["review", "--root", str(root), "--no-scanners"]), 1)
            self.assertEqual(main(["review", "--root", str(root), "--no-scanners", "--fail-on", "critical"]), 0)

    def test_one_run_writes_every_format(self):
        root = git_repo({"README.md": "x\n"})
        (root / "Dockerfile").write_text("FROM python:latest\nUSER 1000\n")
        sarif, js, md = (root / "r.sarif"), (root / "r.json"), (root / "r.md")
        with redirect_stdout(io.StringIO()):
            main(["review", "--root", str(root), "--no-scanners", "--fail-on", "never",
                  "--sarif", str(sarif), "--json", str(js), "--markdown", str(md)])
        self.assertEqual(json.loads(sarif.read_text())["version"], "2.1.0")
        self.assertEqual(json.loads(js.read_text())["counts"]["medium"], 1)
        self.assertIn("Agentic code review", md.read_text())

    def test_explain_shows_fix_and_handles_typos(self):
        from contextlib import redirect_stderr
        buf = io.StringIO()
        with redirect_stdout(buf):
            self.assertEqual(main(["explain", "acr-ai-002"]), 0)
        self.assertIn("How to fix", buf.getvalue())
        self.assertIn("genai.owasp.org", buf.getvalue())
        err = io.StringIO()
        with redirect_stderr(err):
            self.assertEqual(main(["explain", "ACR-AI-999"]), 2)
        self.assertIn("ACR-AI-001", err.getvalue())

    def test_rules_command_lists_rules(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            self.assertEqual(main(["rules"]), 0)
        self.assertIn("ACR-AI-001", buf.getvalue())


class ScannerParsingTests(unittest.TestCase):
    def test_semgrep_and_hadolint_json_normalised(self):
        semgrep = json.dumps({"results": [{"check_id": "python.lang.security.eval", "path": "a.py",
                                            "start": {"line": 4}, "end": {"line": 4},
                                            "extra": {"message": "eval use", "severity": "ERROR"}}]})
        with mock.patch.object(tools, "_exec", return_value=semgrep):
            f = tools.run_semgrep(tools.Path("."), ["a.py"])[0]
        self.assertEqual((f.rule_id, f.line, f.severity), ("semgrep:eval", 4, Severity.HIGH))
        hado = json.dumps([{"code": "DL3007", "file": "Dockerfile", "line": 1, "level": "warning", "message": "latest"}])
        with mock.patch.object(tools, "_exec", return_value=hado):
            f = tools.run_hadolint(tools.Path("."), ["Dockerfile"])[0]
        self.assertEqual((f.rule_id, f.severity), ("hadolint:DL3007", Severity.MEDIUM))

    def test_missing_or_garbage_output_is_safe(self):
        with mock.patch.object(tools, "_exec", return_value="not json"):
            self.assertEqual(tools.run_checkov(tools.Path("."), ["m.tf"]), [])


class GitHubAnnotationTests(unittest.TestCase):
    def test_annotations_are_escaped_and_levelled(self):
        from agentic_code_review.engine import ReviewResult
        f = Finding("ACR-APP-002", "Shell, built from a string", Severity.HIGH, "src/a,b.py", 7, "acr", "app-security",
                    detail="line one\nline two: 100%", fix="Use a list.")
        low = Finding("ACR-APP-007", "Weak hash", Severity.LOW, "x.py", 2, "acr", "app-security")
        fp = Finding("ACR-APP-003", "eval", Severity.HIGH, "x.py", 3, "acr", "app-security", ai_verdict="false_positive")
        out = report.to_github(ReviewResult([f, low, fp], {}, {})).splitlines()
        self.assertEqual(len(out), 2)  # the dismissed false positive is not annotated
        self.assertTrue(out[0].startswith("::error file=src/a%2Cb.py,line=7,title=ACR-APP-002 Shell%2C built from a string::"))
        self.assertIn("line one%0Aline two: 100%25 Fix: Use a list.", out[0])
        self.assertTrue(out[1].startswith("::notice file=x.py,line=2,"))

    def test_cli_format_github(self):
        root = git_repo({"a.py": "x = 1\n"})
        (root / "a.py").write_text("x = 1\nos.system(cmd)\n")
        buf = io.StringIO()
        with redirect_stdout(buf):
            main(["review", "--root", str(root), "--no-scanners", "--format", "github", "--fail-on", "never"])
        self.assertIn("::error file=a.py,line=2,title=ACR-APP-002", buf.getvalue())


class RulesFormatTests(unittest.TestCase):
    def test_json_and_markdown_cover_every_rule(self):
        from agentic_code_review.rules import base
        buf = io.StringIO()
        with redirect_stdout(buf):
            main(["rules", "--format", "json"])
        data = json.loads(buf.getvalue())
        self.assertEqual(len(data), len(base.REGISTRY))
        self.assertTrue(all(r["fix"] and r["applies_to"] for r in data))
        buf = io.StringIO()
        with redirect_stdout(buf):
            main(["rules", "--format", "markdown"])
        rows = [r for r in buf.getvalue().splitlines() if r.startswith("| ") and "`ACR-" in r]
        self.assertEqual(len(rows), len(base.REGISTRY))
        self.assertTrue(rows[0].startswith("| Secrets |"))

    def test_readme_catalogue_is_up_to_date(self):
        from pathlib import Path
        buf = io.StringIO()
        with redirect_stdout(buf):
            main(["rules", "--format", "markdown"])
        readme = (Path(__file__).resolve().parents[1] / "README.md").read_text()
        self.assertIn(buf.getvalue().strip(), readme, "README rule table is stale: run `acr rules --format markdown`")


class SkippedFilesTests(unittest.TestCase):
    def test_binary_and_oversized_files_are_reported(self):
        from agentic_code_review import engine
        root = git_repo({"a.py": "x = 1\n"})
        (root / "model.bin").write_bytes(b"\x00\x01weights")
        (root / "big.py").write_text("x = 1\n" * 10)
        with mock.patch.object(engine, "MAX_BYTES", 30):
            result = review(root, use_scanners=False)
        self.assertEqual(result.skipped, ["big.py", "model.bin"])
        self.assertIn("2 binary or oversized file(s)", report.to_markdown(result))
        self.assertEqual(json.loads(report.to_json(result))["files_skipped"], ["big.py", "model.bin"])


class IncludeTests(unittest.TestCase):
    def test_include_limits_the_review(self):
        root = git_repo({"README.md": "x\n"})
        for rel in ("services/api/app.py", "services/web/app.py"):
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text("os.system(cmd)\n")
        result = review(root, use_scanners=False, includes=("services/api/*",))
        self.assertEqual([f.path for f in result.findings], ["services/api/app.py"])
        buf = io.StringIO()
        with redirect_stdout(buf):
            main(["review", "--root", str(root), "--no-scanners", "--include", "services/web/*", "--format", "json", "--fail-on", "never"])
        self.assertEqual({f["path"] for f in json.loads(buf.getvalue())["findings"]}, {"services/web/app.py"})


class ScannerFailureTests(unittest.TestCase):
    def test_exec_classifies_failures(self):
        import subprocess
        ok = subprocess.CompletedProcess([], 1, stdout="[]", stderr="")
        crash = subprocess.CompletedProcess([], 2, stdout="", stderr="config error\nbad rule file")
        with mock.patch.object(tools.subprocess, "run", return_value=ok):
            self.assertEqual(tools._exec(["x"], tools.Path(".")), "[]")  # exit 1 with findings is normal
        with mock.patch.object(tools.subprocess, "run", return_value=crash):
            with self.assertRaisesRegex(tools.ScannerError, "exited with 2: bad rule file"):
                tools._exec(["x"], tools.Path("."))
        with mock.patch.object(tools.subprocess, "run", side_effect=subprocess.TimeoutExpired("x", 1)):
            with self.assertRaisesRegex(tools.ScannerError, "timed out"):
                tools._exec(["x"], tools.Path("."))

    def test_failed_scanner_is_reported_not_silent(self):
        from agentic_code_review.scanners.tools import Scanner

        def boom(root, files):
            raise tools.ScannerError("timed out after 300s")
        fake = Scanner("semgrep", "semgrep", frozenset({"*"}), boom)
        root = git_repo({"README.md": "x\n"})
        (root / "a.py").write_text("x = 1\n")
        with mock.patch("agentic_code_review.engine.available_scanners", return_value=[fake]), \
                mock.patch("agentic_code_review.scanners.tools.ALL_SCANNERS", [fake]):
            result = review(root)
        self.assertEqual((result.scanners_run, result.scanners_failed), ([], {"semgrep": "timed out after 300s"}))
        self.assertIn("semgrep (timed out after 300s)", report.to_markdown(result))


class SarifInvocationTests(unittest.TestCase):
    def test_scanner_problems_become_notifications(self):
        from agentic_code_review.engine import ReviewResult
        r = ReviewResult([], {}, {}, scanners_missing=["trivy"], scanners_failed={"semgrep": "timed out after 300s"})
        inv = json.loads(report.to_sarif(r))["runs"][0]["invocations"][0]
        self.assertFalse(inv["executionSuccessful"])
        self.assertEqual([n["level"] for n in inv["toolExecutionNotifications"]], ["error", "note"])
        clean = json.loads(report.to_sarif(ReviewResult([], {}, {})))["runs"][0]["invocations"][0]
        self.assertEqual(clean, {"executionSuccessful": True, "toolExecutionNotifications": []})


class SarifRuleMetadataTests(unittest.TestCase):
    def test_builtin_rules_are_documented(self):
        from agentic_code_review.engine import ReviewResult
        acr = Finding("ACR-APP-002", "Shell command built from a string", Severity.HIGH, "a.py", 3, "acr", "app-security")
        ext = Finding("semgrep:x", "semgrep thing", Severity.LOW, "a.py", 4, "semgrep", "app-security")
        rules = {r["id"]: r for r in json.loads(report.to_sarif(ReviewResult([acr, ext], {}, {})))["runs"][0]["tool"]["driver"]["rules"]}
        self.assertIn("acr explain ACR-APP-002", rules["ACR-APP-002"]["help"]["text"])
        self.assertTrue(rules["ACR-APP-002"]["helpUri"].startswith("https://"))
        self.assertEqual(rules["ACR-APP-002"]["properties"]["precision"], "high")
        self.assertNotIn("precision", rules["semgrep:x"]["properties"])


class JsonGateTests(unittest.TestCase):
    def test_gate_section(self):
        root = git_repo({"a.py": "x = 1\n"})
        (root / "a.py").write_text("x = 1\nos.system(cmd)\nh = hashlib.md5(b)\n")

        def gate(level):
            buf = io.StringIO()
            with redirect_stdout(buf):
                main(["review", "--root", str(root), "--no-scanners", "--format", "json", "--fail-on", level])
            return json.loads(buf.getvalue())
        data = gate("high")
        self.assertEqual(data["schema_version"], 1)
        self.assertEqual(data["gate"], {"fail_on": "high", "blocking": 1, "passed": False})
        self.assertEqual(gate("low")["gate"]["blocking"], 2)
        self.assertEqual(gate("never")["gate"], {"fail_on": "never", "blocking": 0, "passed": True})
