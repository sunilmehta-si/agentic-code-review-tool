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
        url = post_review(self.result, Severity.HIGH,
                          request=lambda m, u, t, b: sent.append((m, u, b)) or ([] if m == "GET" else {"html_url": "https://x/7"}))
        self.assertEqual(url, "https://x/7")
        self.assertTrue(sent[0][1].endswith("/repos/o/r/pulls/7/comments?per_page=100&page=1"))
        self.assertTrue(sent[1][1].endswith("/repos/o/r/pulls/7/reviews"))

    def test_falls_back_to_summary_when_github_rejects_positions(self):
        attempts = []

        def request(method, url, token, body):
            if method == "GET":
                return []
            attempts.append(len(body["comments"]))
            if body["comments"]:
                raise GitHubError("GitHub API 422: pull_request_review_thread.line must be part of the diff")
            return {"html_url": "u"}

        post_review(self.result, Severity.HIGH, request=request)
        self.assertEqual(attempts, [len(self.result.findings), 0])


class RepeatCommentTests(unittest.TestCase):
    def test_findings_commented_earlier_are_not_repeated(self):
        root = git_repo({"README.md": "x\n"})
        (root / "Dockerfile").write_text("FROM python:latest\nRUN curl -k https://x -o y\nUSER 1000\n")
        result = review(root, use_scanners=False)
        first = build_review(result, Severity.HIGH, "abc")
        self.assertEqual(len(first["comments"]), 2)
        self.assertIn("<!-- acr:", first["comments"][0]["body"])
        earlier = [{"body": first["comments"][0]["body"]}]

        def request(method, url, token, body):
            return earlier if method == "GET" else {"html_url": "u", "sent": body}
        with mock.patch.dict(os.environ, {"GITHUB_REPOSITORY": "o/r", "GITHUB_TOKEN": "t", "GITHUB_EVENT_PATH": ""}):
            sent = []
            post_review(result, Severity.HIGH, pr=7, request=lambda m, u, t, b: sent.append(b) or request(m, u, t, b))
        posted = sent[-1]
        self.assertEqual(len(posted["comments"]), 1)
        self.assertIn("already commented on in an earlier run", posted["body"])

    def test_listing_failure_does_not_block_the_review(self):
        from agentic_code_review.github import _posted_markers

        def failing(method, url, token, body):
            raise GitHubError("GitHub API 403: forbidden")
        self.assertEqual(_posted_markers("o/r", 7, "t", failing), set())
