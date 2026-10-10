import unittest

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
