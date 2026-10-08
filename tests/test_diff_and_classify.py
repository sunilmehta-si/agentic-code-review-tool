import unittest

from agentic_code_review.classify import kinds
from agentic_code_review.diff import parse_unified_diff


class DiffTests(unittest.TestCase):
    def test_added_lines_are_tracked_per_hunk(self):
        diff = "+++ b/app.py\n@@ -1,0 +2,3 @@\n+a\n+b\n+c\n@@ -10 +20 @@\n+d\n+++ /dev/null\n"
        files = parse_unified_diff(diff)
        self.assertEqual(sorted(files["app.py"].added_lines), [2, 3, 4, 20])

    def test_pure_deletion_hunk_adds_no_lines(self):
        files = parse_unified_diff("+++ b/x.py\n@@ -5,2 +4,0 @@\n")
        self.assertEqual(files["x.py"].added_lines, set())


class ClassifyTests(unittest.TestCase):
    def test_file_kinds(self):
        self.assertIn("dockerfile", kinds("svc/Dockerfile", "FROM x"))
        self.assertIn("github-actions", kinds(".github/workflows/ci.yml", "on: push"))
        self.assertIn("kubernetes", kinds("k8s/d.yaml", "apiVersion: v1\nkind: Pod\n"))
        self.assertNotIn("kubernetes", kinds("config.yaml", "foo: bar"))
        self.assertIn("terraform", kinds("main.tf", ""))
        self.assertIn("mcp-config", kinds(".mcp.json", "{}"))
        self.assertIn("agent-skill", kinds("skills/x/SKILL.md", ""))

    def test_ai_code_detected_only_with_llm_imports(self):
        self.assertIn("ai-code", kinds("bot.py", "from anthropic import Anthropic"))
        self.assertNotIn("ai-code", kinds("util.py", "import os"))
