"""Post the review to a GitHub pull request: one summary plus inline comments on the changed lines.

Runs inside GitHub Actions using GITHUB_TOKEN (needs `pull-requests: write`). Comments can only be
placed on lines in the PR diff; findings are already limited to changed lines, and if GitHub still
rejects a position the review falls back to the summary alone instead of failing.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

from .engine import ReviewResult
from .models import Severity
from .report import comment_body, to_markdown

API = os.environ.get("GITHUB_API_URL", "https://api.github.com")
MAX_INLINE = 50


class GitHubError(RuntimeError):
    pass


def pr_context(repo: str | None = None, pr: int | None = None) -> tuple[str, int, str | None]:
    """Repository, PR number and head SHA from arguments or the Actions event payload."""
    event: dict = {}
    path = os.environ.get("GITHUB_EVENT_PATH")
    if path and os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            event = json.load(fh)
    pull = event.get("pull_request") or {}
    repo = repo or os.environ.get("GITHUB_REPOSITORY")
    number = pr or pull.get("number")
    if not repo or not number:
        raise GitHubError("Not a pull request context: pass --pr and set GITHUB_REPOSITORY, or run on a pull_request event.")
    return repo, int(number), (pull.get("head") or {}).get("sha")


def _request(method: str, url: str, token: str, body: dict | None = None) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={
        "Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            raw = resp.read().decode()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        raise GitHubError(f"GitHub API {exc.code}: {exc.read().decode(errors='replace')[:300]}") from exc


def build_review(result: ReviewResult, threshold: Severity, commit_id: str | None) -> dict:
    shown = [f for f in result.findings if f.ai_verdict != "false_positive"]
    comments = [{"path": f.path, "line": f.line, "side": "RIGHT", "body": comment_body(f)} for f in shown[:MAX_INLINE]]
    body = to_markdown(result, threshold)
    if len(shown) > MAX_INLINE:
        body += f"\n\n_{len(shown) - MAX_INLINE} more finding(s) are in the summary table but not commented inline._"
    review = {"body": body, "event": "COMMENT", "comments": comments}
    if commit_id:
        review["commit_id"] = commit_id
    return review


def post_review(result: ReviewResult, threshold: Severity, repo: str | None = None, pr: int | None = None,
                token: str | None = None, request=_request) -> str:
    token = token or os.environ.get("GITHUB_TOKEN")
    if not token:
        raise GitHubError("GITHUB_TOKEN is not set.")
    repo, number, sha = pr_context(repo, pr)
    url = f"{API}/repos/{repo}/pulls/{number}/reviews"
    review = build_review(result, threshold, sha)
    try:
        resp = request("POST", url, token, review)
    except GitHubError as exc:
        if "422" not in str(exc) or not review["comments"]:
            raise
        # A comment landed outside the diff GitHub knows about: keep the summary rather than lose the review.
        review["comments"] = []
        review["body"] += "\n\n_Inline comments could not be placed on this diff; see the table above._"
        resp = request("POST", url, token, review)
    return str(resp.get("html_url", ""))
