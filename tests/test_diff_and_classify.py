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


class AiImportDetectionTests(unittest.TestCase):
    def test_mentions_in_strings_are_not_imports(self):
        self.assertNotIn("ai-code", kinds("scan.py", 'RULES = [("anthropic-api-key", "sk-ant-")]\n'))

    def test_real_imports_in_python_and_js(self):
        self.assertIn("ai-code", kinds("a.py", "from openai import OpenAI\n"))
        self.assertIn("ai-code", kinds("a.py", "import langchain.agents\n"))
        self.assertIn("ai-code", kinds("a.ts", 'import Anthropic from "@anthropic-ai/sdk"\n'))
        self.assertIn("ai-code", kinds("a.js", 'const { OpenAI } = require("openai")\n'))

    def test_scoped_package_detected_regardless_of_binding_name(self):
        self.assertIn("ai-code", kinds("b.ts", 'import Client from "@anthropic-ai/sdk"\n'))
        self.assertIn("ai-code", kinds("c.ts", 'import { ChatOpenAI } from "@langchain/openai"\n'))


class StagedModeTests(unittest.TestCase):
    def test_only_staged_content_is_reviewed(self):
        import subprocess

        from agentic_code_review.engine import review
        from tests.helpers import git_repo
        root = git_repo({"app.py": "x = 1\n"})
        (root / "app.py").write_text("x = 1\nsubprocess.run(c, shell=True)\n")
        subprocess.run(["git", "-C", str(root), "add", "app.py"], check=True)
        # An unstaged edit on top: it is not part of the commit, so it must not be reviewed.
        (root / "app.py").write_text("x = 1\nsubprocess.run(c, shell=True)\nos.system(cmd)\n")
        (root / "new.py").write_text("os.system(cmd)\n")  # untracked, not staged
        result = review(root, staged=True, use_scanners=False)
        self.assertEqual([(f.path, f.line) for f in result.findings], [("app.py", 2)])

    def test_staged_conflicts_with_base(self):
        import io
        from contextlib import redirect_stderr

        from agentic_code_review.cli import main
        err = io.StringIO()
        with redirect_stderr(err):
            self.assertEqual(main(["review", "--staged", "--base", "origin/main"]), 2)
        self.assertIn("--staged", err.getvalue())


class ShellClassificationTests(unittest.TestCase):
    def test_scripts_by_extension_shebang_and_makefiles(self):
        from agentic_code_review.classify import kinds
        self.assertIn("shell", kinds("scripts/deploy.sh", "echo hi\n"))
        self.assertIn("shell", kinds("bin/release", "#!/usr/bin/env bash\nset -e\n"))
        self.assertIn("shell", kinds("bin/run", "#!/bin/sh\n"))
        self.assertIn("shell", kinds("Makefile", "all:\n\tgo build\n"))
        self.assertNotIn("shell", kinds("bin/tool", "#!/usr/bin/env python3\n"))
        self.assertNotIn("shell", kinds("notes.txt", "#!/bin/sh in a sentence\n"))


class AgentSettingsClassificationTests(unittest.TestCase):
    def test_coding_agent_plugins_and_marketplaces(self):
        for path in (".claude-plugin/marketplace.json", "plugins/x/.claude-plugin/plugin.json", ".grok-plugin/marketplace.json",
                     "external_plugins/acme/.grok-plugin/plugin.json", "plugins/acme/hooks/hooks.json"):
            self.assertIn("agent-plugin", kinds(path, "{}"), path)
        for path in ("package.json", "hooks.json", ".claude/settings.json", "docs/hooks/readme.json"):
            self.assertNotIn("agent-plugin", kinds(path, "{}"), path)

    def test_coding_agent_permission_files(self):
        from agentic_code_review.classify import kinds
        for path in (".claude/settings.json", ".claude/settings.local.json", "svc/.claude/settings.json", ".codex/config.toml"):
            self.assertIn("agent-settings", kinds(path, "{}"), path)
        self.assertNotIn("agent-settings", kinds("settings.json", "{}"))
        self.assertNotIn("agent-settings", kinds("docs/claude/settings.json", "{}"))


class QuotedPathTests(unittest.TestCase):
    def test_unquote(self):
        from agentic_code_review.diff import unquote
        self.assertEqual(unquote('"b/na\\303\\257ve.py"'), "b/naïve.py")
        self.assertEqual(unquote('"b/say \\"hi\\".py"'), 'b/say "hi".py')
        self.assertEqual(unquote("b/plain.py"), "b/plain.py")

    def test_files_with_unusual_names_are_reviewed(self):
        import subprocess

        from agentic_code_review.engine import review
        from tests.helpers import git_repo
        root = git_repo({"naïve.py": "x = 1\n", 'say "hi".py': "x = 1\n"})
        for name in ("naïve.py", 'say "hi".py'):
            (root / name).write_text("x = 1\nos.system(cmd)\n")
        self.assertEqual(sorted(f.path for f in review(root, use_scanners=False).findings), ["naïve.py", 'say "hi".py'])
        self.assertEqual(len(review(root, full=True, use_scanners=False).findings), 2)
        subprocess.run(["git", "-C", str(root), "add", "."], check=True)
        self.assertEqual(len(review(root, staged=True, use_scanners=False).findings), 2)


class NoMergeBaseTests(unittest.TestCase):
    def test_falls_back_to_a_direct_diff(self):
        import io
        import subprocess
        from contextlib import redirect_stderr

        from agentic_code_review.engine import review
        from tests.helpers import git_repo
        root = git_repo({"a.py": "x = 1\n"})
        run = lambda *a: subprocess.run(["git", "-C", str(root), *a], check=True, capture_output=True)  # noqa: E731
        run("branch", "-m", "main")
        run("checkout", "-q", "--orphan", "feature")  # unrelated history, like a shallow clone without the base
        (root / "a.py").write_text("x = 1\nos.system(cmd)\n")
        run("commit", "-qam", "feature")
        err = io.StringIO()
        with redirect_stderr(err):
            result = review(root, base="main", use_scanners=False)
        self.assertEqual([(f.path, f.line) for f in result.findings], [("a.py", 2)])
        self.assertIn("no merge base", err.getvalue())


class DiffFileTests(unittest.TestCase):
    def test_review_a_patch_from_file_and_stdin(self):
        import io
        import json
        import subprocess
        from contextlib import redirect_stdout
        from unittest import mock

        from agentic_code_review.cli import main
        from tests.helpers import git_repo
        root = git_repo({"a.py": "x = 1\n", "b.py": "y = 1\n"})
        (root / "a.py").write_text("x = 1\nos.system(cmd)\n")
        (root / "b.py").write_text("y = 1\nos.popen(cmd)\n")
        patch = subprocess.run(["git", "-C", str(root), "diff", "-U0", "--", "a.py"], capture_output=True, text=True).stdout
        (root / "change.patch").write_text(patch)

        def paths(*extra, stdin=None):
            buf = io.StringIO()
            with redirect_stdout(buf), mock.patch("sys.stdin", io.StringIO(stdin or "")):
                main(["review", "--root", str(root), "--no-scanners", "--format", "json", "--fail-on", "never", *extra])
            return [(f["path"], f["line"]) for f in json.loads(buf.getvalue())["findings"]]
        self.assertEqual(paths("--diff-file", str(root / "change.patch")), [("a.py", 2)])  # b.py is not in the patch
        self.assertEqual(paths("--diff-file", "-", stdin=patch), [("a.py", 2)])

    def test_diff_file_conflicts_with_other_modes(self):
        import io
        from contextlib import redirect_stderr

        from agentic_code_review.cli import main
        with redirect_stderr(io.StringIO()):
            self.assertEqual(main(["review", "--diff-file", "-", "--all"]), 2)


class ComposeClassificationTests(unittest.TestCase):
    def test_compose_file_names(self):
        from agentic_code_review.classify import kinds
        for name in ("docker-compose.yml", "compose.yaml", "deploy/docker-compose.prod.yml", "compose.override.yaml"):
            self.assertEqual(kinds(name, "services:\n  web:\n    image: x\n"), {"compose"}, name)
        self.assertNotIn("compose", kinds("k8s/composer.yaml", "apiVersion: v1\nkind: Pod\n"))


class AgentInstructionClassificationTests(unittest.TestCase):
    def test_instruction_files(self):
        from agentic_code_review.classify import kinds
        for path in ("AGENTS.md", "services/api/CLAUDE.md", ".cursorrules", ".cursor/rules/style.mdc", ".windsurfrules",
                     ".github/copilot-instructions.md", ".github/instructions/py.instructions.md", ".clinerules/deploy.md"):
            self.assertIn("agent-instructions", kinds(path, "Be concise.\n"), path)
        for path in ("README.md", "docs/agents.txt", "notes/claude.mdx"):
            self.assertNotIn("agent-instructions", kinds(path, "x\n"), path)


class ContextLineTests(unittest.TestCase):
    def test_only_plus_lines_count_in_diffs_with_context(self):
        from agentic_code_review.diff import parse_unified_diff
        d = ("--- a/x.py\n+++ b/x.py\n@@ -1,4 +1,5 @@\n a = 1\n+b = 2\n c = 3\n-d = 4\n+d = 5\n e = 6\n"
             "\\ No newline at end of file\n@@ -20,2 +21,3 @@\n y = 1\n+z = 2\n w = 3\n"
             "--- /dev/null\n+++ b/new.py\n@@ -0,0 +1,2 @@\n+one\n+two\n")
        files = parse_unified_diff(d)
        self.assertEqual(sorted(files["x.py"].added_lines), [2, 4, 22])
        self.assertEqual(sorted(files["new.py"].added_lines), [1, 2])

    def test_a_plus_plus_plus_line_inside_a_hunk_is_content(self):
        from agentic_code_review.diff import parse_unified_diff
        d = "--- a/n.md\n+++ b/n.md\n@@ -1,0 +1,1 @@\n+++ b/heading-looking-text\n"
        self.assertEqual(list(parse_unified_diff(d)), ["n.md"])  # not mistaken for a new file header
        self.assertEqual(sorted(parse_unified_diff(d)["n.md"].added_lines), [1])

    def test_piped_context_diff_reports_only_changed_lines(self):
        import subprocess

        from agentic_code_review.engine import review
        from tests.helpers import git_repo
        root = git_repo({"a.py": "os.system(a)\nx = 1\n"})
        (root / "a.py").write_text("os.system(a)\nx = 1\nos.popen(b)\n")
        patch = subprocess.run(["git", "-C", str(root), "diff"], capture_output=True, text=True).stdout  # default -U3
        self.assertEqual([f.line for f in review(root, use_scanners=False, diff_text=patch).findings], [3])

    def test_untracked_files_are_still_fully_reviewed(self):
        from agentic_code_review.engine import review
        from tests.helpers import git_repo
        root = git_repo({"a.py": "x = 1\n"})
        (root / "new.py").write_text("x = 1\nos.system(a)\n")
        self.assertEqual([(f.path, f.line) for f in review(root, use_scanners=False).findings], [("new.py", 2)])
