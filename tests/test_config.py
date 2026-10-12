import unittest
from pathlib import Path

from agentic_code_review.config import ConfigError, load
from agentic_code_review.models import Severity
from tests.helpers import git_repo


class ConfigTests(unittest.TestCase):
    def test_no_file_means_defaults(self):
        cfg = load(git_repo({"a.py": "x\n"}))
        self.assertIsNone(cfg.fail_on)
        self.assertEqual(cfg.disable, [])

    def test_full_file(self):
        root = git_repo({".acr.yml": "fail_on: critical\nexclude: docs/*\ndisable: [ACR-AI-007, 'hadolint:*']\n"
                                     "severity:\n  ACR-K8S-009: medium\nscanners: [trivy]\nai: claude\n"})
        cfg = load(root)
        self.assertEqual((cfg.fail_on, cfg.exclude, cfg.ai, cfg.scanners), ("critical", ["docs/*"], "claude", ["trivy"]))
        self.assertEqual(cfg.disable, ["ACR-AI-007", "hadolint:*"])
        self.assertEqual(cfg.severity["ACR-K8S-009"], Severity.MEDIUM)

    def test_mistakes_are_reported_not_ignored(self):
        for body in ("fial_on: high\n", "fail_on: urgent\n", "severity:\n  X: severe\n", "ai: gpt\n", "- just\n- a list\n"):
            with self.assertRaises(ConfigError, msg=body):
                load(git_repo({".acr.yml": body}))


class ConfigAppliedTests(unittest.TestCase):
    def _run(self, root, *extra):
        import io
        from contextlib import redirect_stdout
        from agentic_code_review.cli import main
        with redirect_stdout(io.StringIO()) as buf:
            code = main(["review", "--root", str(root), "--no-scanners", "--format", "json", *extra])
        import json
        return code, json.loads(buf.getvalue())

    def test_disable_override_and_fail_on_from_file(self):
        root = git_repo({"README.md": "x\n", ".acr.yml": "fail_on: critical\ndisable: ['ACR-DOCKER-002']\n"
                                                        "severity:\n  ACR-DOCKER-003: critical\n"})
        (root / "Dockerfile").write_text("FROM python:latest\nRUN curl -s https://x.sh | sh\n")
        code, data = self._run(root)
        rules = {f["rule_id"]: f["severity"] for f in data["findings"]}
        self.assertNotIn("ACR-DOCKER-002", rules)
        self.assertEqual(rules["ACR-DOCKER-003"], "critical")
        self.assertEqual(code, 1)          # fail_on: critical from the file, and there is now a critical
        code, _ = self._run(root, "--fail-on", "never")
        self.assertEqual(code, 0)          # the flag wins over the file

    def test_bad_config_is_a_clean_error(self):
        root = git_repo({".acr.yml": "fial_on: high\n"})
        import io
        from contextlib import redirect_stderr
        from agentic_code_review.cli import main
        with redirect_stderr(io.StringIO()) as err:
            self.assertEqual(main(["review", "--root", str(root), "--no-scanners"]), 2)
        self.assertIn("Unknown setting", err.getvalue())


class InitCommandTests(unittest.TestCase):
    def test_init_writes_a_valid_starter_and_refuses_to_overwrite(self):
        import io
        import tempfile
        from contextlib import redirect_stderr, redirect_stdout

        from agentic_code_review.cli import main
        from agentic_code_review.config import load
        root = Path(tempfile.mkdtemp())
        with redirect_stdout(io.StringIO()):
            self.assertEqual(main(["init", "--root", str(root)]), 0)
        cfg = load(root)  # the template must pass the same validation as a hand-written file
        self.assertEqual((cfg.fail_on, cfg.exclude, cfg.source), ("high", ["docs/*"], ".acr.yml"))
        (root / ".acr.yml").write_text("fail_on: low\n")
        with redirect_stderr(io.StringIO()):
            self.assertEqual(main(["init", "--root", str(root)]), 1)
        self.assertEqual((root / ".acr.yml").read_text(), "fail_on: low\n")
        with redirect_stdout(io.StringIO()):
            self.assertEqual(main(["init", "--root", str(root), "--force"]), 0)
        self.assertEqual(load(root).fail_on, "high")


class SeverityGlobTests(unittest.TestCase):
    def test_exact_id_beats_glob_and_longer_glob_beats_shorter(self):
        from agentic_code_review.engine import _override
        o = {"ACR-K8S-*": Severity.LOW, "ACR-K8S-00*": Severity.MEDIUM, "ACR-K8S-001": Severity.INFO}
        self.assertEqual(_override("ACR-K8S-001", o), Severity.INFO)
        self.assertEqual(_override("ACR-K8S-005", o), Severity.MEDIUM)
        self.assertEqual(_override("ACR-K8S-010", o), Severity.LOW)
        self.assertIsNone(_override("ACR-TF-001", o))


class IncludeConfigTests(unittest.TestCase):
    def test_include_from_file_and_flag_precedence(self):
        import io
        import json
        from contextlib import redirect_stdout

        from agentic_code_review.cli import main
        root = git_repo({"README.md": "x\n"})
        for rel in ("api/a.py", "web/a.py"):
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text("os.system(cmd)\n")
        (root / ".acr.yml").write_text("include: ['api/*']\n")
        self.assertEqual(load(root).include, ["api/*"])

        def paths(*extra):
            buf = io.StringIO()
            with redirect_stdout(buf):
                main(["review", "--root", str(root), "--no-scanners", "--format", "json", "--fail-on", "never", *extra])
            return {f["path"] for f in json.loads(buf.getvalue())["findings"]}
        self.assertEqual(paths(), {"api/a.py"})
        self.assertEqual(paths("--include", "web/*"), {"web/a.py"})  # the flag wins over the file
