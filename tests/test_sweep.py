import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import sweep  # noqa: E402


class SweepScriptTests(unittest.TestCase):
    """scripts/sweep.py reviews whole repositories so a rule is tuned on real code before it ships."""

    def test_writes_one_json_per_repository_and_prints_counts_samples_and_movement(self):
        with tempfile.TemporaryDirectory() as d:
            before, after = Path(d) / "before", Path(d) / "after"
            out = io.StringIO()
            with redirect_stdout(out):
                sweep.main([str(ROOT / "examples" / "insecure-app"), "--out", str(before), "--samples", "2"])
            report = json.loads((before / "insecure-app.json").read_text())
            self.assertIn("findings", report)
            rules = {f["rule_id"] for f in report["findings"]}
            self.assertIn("ACR-K8S-001", rules)                                  # the demo's privileged pod
            text = out.getvalue()
            self.assertIn("ACR-K8S-001 insecure-app:", text)
            self.assertIn("== ACR-K8S-001", text)
            self.assertRegex(text, r"insecure-app:k8s/[\w.-]+\.yaml:\d+: ")        # a sample line names file, line and text
            # a second sweep against the first reports how each count moved
            out = io.StringIO()
            with redirect_stdout(out):
                sweep.main([str(ROOT / "examples" / "insecure-app"), "--out", str(after), "--before", str(before),
                            "--rule", "ACR-K8S-001", "--samples", "1"])
            text = out.getvalue()
            self.assertIn("(before -> after)", text)
            self.assertRegex(text, r"ACR-K8S-001 insecure-app: (\d+) -> \1\b")
            self.assertNotIn("== ACR-SEC-001", text)                            # --rule narrows the samples


if __name__ == "__main__":
    unittest.main()
