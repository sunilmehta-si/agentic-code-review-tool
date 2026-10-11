"""End-to-end: the deliberately insecure demo must trigger every rule family."""
import unittest
from pathlib import Path

from agentic_code_review.engine import review

DEMO = Path(__file__).resolve().parents[1] / "examples" / "insecure-app"


class DemoTests(unittest.TestCase):
    def test_every_category_is_caught(self):
        result = review(DEMO, full=True, use_scanners=False)
        categories = {f.category for f in result.findings}
        for cat in ("secrets", "app-security", "ai-security", "kubernetes", "container", "ci-cd", "iac"):
            self.assertIn(cat, categories)
        rules = {f.rule_id for f in result.findings}
        for rid in ("ACR-AI-001", "ACR-AI-002", "ACR-AI-004", "ACR-AI-005", "ACR-MCP-001", "ACR-MCP-002",
                    "ACR-SKILL-001", "ACR-SKILL-002", "ACR-SKILL-003", "ACR-GHA-001", "ACR-K8S-008", "ACR-TF-001",
                    # 0.3.0 rules
                    "ACR-AI-010", "ACR-AI-011", "ACR-MCP-004", "ACR-GHA-008", "ACR-GHA-009", "ACR-DOCKER-008",
                    "ACR-K8S-012", "ACR-TF-008", "ACR-APP-010", "ACR-APP-011"):
            self.assertIn(rid, rules)

    def test_clean_pod_only_trips_the_rule_it_demonstrates(self):
        result = review(DEMO, full=True, use_scanners=False)
        self.assertEqual({f.rule_id for f in result.findings if f.path == "k8s/sandbox.yaml"}, {"ACR-K8S-012"})
