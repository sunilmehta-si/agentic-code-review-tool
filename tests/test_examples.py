"""End-to-end: the deliberately insecure demo must trigger every rule family."""
import unittest
from pathlib import Path

from agentic_code_review.engine import review

DEMO = Path(__file__).resolve().parents[1] / "examples" / "insecure-app"


class DemoTests(unittest.TestCase):
    def test_every_category_is_caught(self):
        result = review(DEMO, full=True, use_scanners=False)
        categories = {f.category for f in result.findings}
        for cat in ("secrets", "app-security", "ai-security", "kubernetes", "container", "ci-cd", "iac", "dependency"):
            self.assertIn(cat, categories)
        rules = {f.rule_id for f in result.findings}
        for rid in ("ACR-AI-001", "ACR-AI-002", "ACR-AI-004", "ACR-AI-005", "ACR-MCP-001", "ACR-MCP-002",
                    "ACR-SKILL-001", "ACR-SKILL-002", "ACR-SKILL-003", "ACR-GHA-001", "ACR-K8S-008", "ACR-TF-001",
                    # 0.3.0 rules
                    "ACR-AI-010", "ACR-AI-011", "ACR-MCP-004", "ACR-GHA-008", "ACR-GHA-009", "ACR-DOCKER-008",
                    "ACR-K8S-012", "ACR-TF-008", "ACR-APP-010", "ACR-APP-011",
                    # 0.4.0 rules
                    "ACR-K8S-013", "ACR-K8S-014", "ACR-K8S-015", "ACR-K8S-016", "ACR-K8S-017", "ACR-GHA-010",
                    "ACR-GHA-011", "ACR-DOCKER-009", "ACR-TF-009", "ACR-TF-010", "ACR-TF-011", "ACR-TF-012",
                    "ACR-AI-012", "ACR-AI-013", "ACR-SKILL-004", "ACR-APP-012", "ACR-APP-013", "ACR-APP-014",
                    "ACR-APP-015",
                    # 0.5.0 rules
                    "ACR-COMPOSE-001", "ACR-COMPOSE-002", "ACR-COMPOSE-003", "ACR-COMPOSE-004", "ACR-GHA-012",
                    "ACR-GHA-013", "ACR-TF-013", "ACR-TF-014", "ACR-K8S-018", "ACR-K8S-019", "ACR-AI-014", "ACR-AI-015",
                    "ACR-APP-016", "ACR-APP-017", "ACR-APP-018", "ACR-DOCKER-010",
                    # 0.7.0 rules
                    "ACR-DEP-001", "ACR-DEP-002", "ACR-DEP-003", "ACR-APP-019", "ACR-APP-020", "ACR-APP-021"):
            self.assertIn(rid, rules)

    def test_clean_pod_only_trips_the_rule_it_demonstrates(self):
        result = review(DEMO, full=True, use_scanners=False)
        self.assertEqual({f.rule_id for f in result.findings if f.path == "k8s/sandbox.yaml"}, {"ACR-K8S-012"})

    def test_agent_instruction_file_is_checked(self):
        result = review(DEMO, full=True, use_scanners=False)
        self.assertIn("ACR-SKILL-003", {f.rule_id for f in result.findings if f.path == "AGENTS.md"})

    def test_runtime_socket_mount_is_critical_in_the_demo(self):
        result = review(DEMO, full=True, use_scanners=False)
        sock = [f for f in result.findings if f.rule_id == "ACR-K8S-003" and f.path == "k8s/trainer.yaml"]
        self.assertEqual([f.severity.label() for f in sock], ["critical"])


class CiTemplateTests(unittest.TestCase):
    def test_gitlab_template_uses_valid_acr_flags(self):
        import shlex

        import yaml

        from agentic_code_review.cli import _parser
        job = yaml.safe_load((DEMO.parents[1] / "templates" / "gitlab-ci.yml").read_text())["acr-review"]
        commands = [c for c in job["script"] if c.strip().startswith("acr ")]
        self.assertTrue(commands)
        import re
        env = {**job["variables"], "CI_MERGE_REQUEST_TARGET_BRANCH_NAME": "main"}
        for cmd in commands:
            expanded = re.sub(r"\$\{?(\w+)\}?", lambda m: str(env[m.group(1)]), cmd)  # as GitLab would
            args = _parser().parse_args(shlex.split(expanded)[1:])
            self.assertEqual((args.command, args.format), ("review", "gitlab"))
        self.assertEqual(job["artifacts"]["reports"]["codequality"], "gl-code-quality-report.json")
