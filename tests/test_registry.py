"""Invariants every built-in rule must keep, so a new rule cannot ship half-registered."""
import re
import unittest

from agentic_code_review.models import CATEGORIES
from agentic_code_review.rules import base

KNOWN_KINDS = {"*", "app", "ai-code", "dockerfile", "github-actions", "terraform", "kubernetes", "helm-template", "shell",
               "mcp-config", "agent-skill", "agent-settings", "compose"}


class RegistryTests(unittest.TestCase):
    def test_ids_are_unique_and_well_formed(self):
        ids = [info.rule_id for info, _ in base.REGISTRY]
        self.assertEqual(len(ids), len(set(ids)), "duplicate rule id")
        for rid in ids:
            self.assertRegex(rid, r"^ACR-[A-Z0-9]+-\d{3}$")

    def test_every_rule_is_actionable_and_targets_known_kinds(self):
        for info, fn in base.REGISTRY:
            with self.subTest(rule=info.rule_id):
                self.assertTrue(info.fix.strip(), "rules must say how to fix the problem")
                self.assertIn(info.category, CATEGORIES)
                self.assertTrue(info.applies_to)
                for kind in info.applies_to:
                    self.assertTrue(kind in KNOWN_KINDS or re.fullmatch(r"lang:[a-z]+", kind), kind)
                self.assertIs(fn.info, info)
                for ref in info.references:
                    self.assertTrue(ref.startswith("https://"), ref)

    def test_titles_are_short_enough_for_a_pr_table(self):
        for info, _ in base.REGISTRY:
            self.assertLessEqual(len(info.title), 110, info.rule_id)
