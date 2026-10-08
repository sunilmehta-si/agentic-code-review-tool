import json
import os
import tempfile
import unittest
from unittest import mock

from agentic_code_review.engine import review
from agentic_code_review.github import GitHubError, build_review, post_review
from agentic_code_review.models import Severity
from tests.helpers import git_repo


class GitHubReviewTests(unittest.TestCase):
    def setUp(self):
        root = git_repo({"README.md": "x\n"})
        (root / "Dockerfile").write_text("FROM python:latest\nUSER 1000\n")
        self.result = review(root, use_scanners=False)
        fd, self.event = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w") as fh:
            json.dump({"pull_request": {"number": 7, "head": {"sha": "abc123"}}}, fh)
        self.env = mock.patch.dict(os.environ, {"GITHUB_EVENT_PATH": self.event, "GITHUB_REPOSITORY": "o/r",
                                                "GITHUB_TOKEN": "t"})
        self.env.start()

    def tearDown(self):
        self.env.stop()
        os.unlink(self.event)

    def test_inline_comments_target_changed_lines(self):
        payload = build_review(self.result, Severity.HIGH, "abc123")
        self.assertEqual(payload["commit_id"], "abc123")
        self.assertEqual({(c["path"], c["line"], c["side"]) for c in payload["comments"]}, {("Dockerfile", 1, "RIGHT")})

    def test_posts_to_the_pull_request(self):
        sent = []
        url = post_review(self.result, Severity.HIGH, request=lambda m, u, t, b: sent.append((m, u, b)) or {"html_url": "https://x/7"})
        self.assertEqual(url, "https://x/7")
        self.assertTrue(sent[0][1].endswith("/repos/o/r/pulls/7/reviews"))

    def test_falls_back_to_summary_when_github_rejects_positions(self):
        attempts = []

        def request(method, url, token, body):
            attempts.append(len(body["comments"]))
            if body["comments"]:
                raise GitHubError("GitHub API 422: pull_request_review_thread.line must be part of the diff")
            return {"html_url": "u"}

        post_review(self.result, Severity.HIGH, request=request)
        self.assertEqual(attempts, [len(self.result.findings), 0])
