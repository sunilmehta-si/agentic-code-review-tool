import io
import json
import unittest
from contextlib import redirect_stdout

from agentic_code_review.cli import main
from tests.helpers import git_repo


def run(root, *args):
    with redirect_stdout(io.StringIO()) as buf:
        code = main([*args, "--root", str(root), "--no-scanners"] + (["--format", "json"] if args[0] == "review" else []))
    return code, buf.getvalue()


class BaselineTests(unittest.TestCase):
    def setUp(self):
        self.root = git_repo({"app.py": "import subprocess\nsubprocess.run(cmd, shell=True)\n"})

    def test_known_findings_suppressed_new_ones_still_fail(self):
        code, out = run(self.root, "baseline")
        self.assertEqual(code, 0)
        self.assertTrue((self.root / ".acr-baseline.json").exists())
        # Code above the known finding moves it to line 4; it stays suppressed.
        (self.root / "app.py").write_text("import os\nimport subprocess\n\nsubprocess.run(cmd, shell=True)\n")
        code, out = run(self.root, "review", "--all")
        self.assertEqual(json.loads(out)["findings"], [])
        self.assertEqual(code, 0)
        # A genuinely new finding is still reported.
        (self.root / "app.py").write_text("import subprocess\nsubprocess.run(cmd, shell=True)\nos.system(user_cmd)\n")
        code, out = run(self.root, "review", "--all")
        self.assertEqual([f["line"] for f in json.loads(out)["findings"]], [3])
        self.assertEqual(code, 1)

    def test_corrupt_baseline_is_ignored_safely(self):
        (self.root / ".acr-baseline.json").write_text("{not json")
        code, out = run(self.root, "review", "--all")
        self.assertEqual(len(json.loads(out)["findings"]), 1)
