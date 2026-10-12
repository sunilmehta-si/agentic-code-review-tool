"""Post the review to a GitHub pull request: one summary plus inline comments on the changed lines.

Runs inside GitHub Actions using GITHUB_TOKEN (needs `pull-requests: write`). Comments can only be
placed on lines in the PR diff; findings are already limited to changed lines, and if GitHub still
rejects a position the review falls back to the summary alone instead of failing.
"""
from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request

from .engine import ReviewResult
from .models import Severity
from .report import comment_body, to_markdown

API = os.environ.get("GITHUB_API_URL", "https://api.github.com")
MAX_INLINE = 50
MARKER = "<!-- acr:{} -->"            # hidden in each inline comment; identifies the finding across pushes
MARKER_RE = re.compile(r"<!-- acr:([0-9a-f]{8,64}) -->")
MAX_PAGES = 10
ATTEMPTS = 4
MAX_BODY = 60_000      # GitHub rejects review and comment bodies over 65,536 characters
_sleep = time.sleep  # replaced in tests


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


def _retry_after(exc: urllib.error.HTTPError, text: str, attempt: int) -> float | None:
    """Seconds to wait before retrying, or None if the error is not transient."""
    rate_limited = exc.code == 429 or (exc.code == 403 and "rate limit" in text.lower())
    if exc.code not in (502, 503, 504) and not rate_limited:
        return None
    header = (exc.headers or {}).get("Retry-After") if exc.headers is not None else None
    if header and str(header).isdigit():
        return min(float(header), 60.0)
    return float(2 ** attempt)


def _request(method: str, url: str, token: str, body: dict | None = None) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    for attempt in range(ATTEMPTS):
        req = urllib.request.Request(url, data=data, method=method, headers={
            "Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28", "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                raw = resp.read().decode()
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as exc:
            text = exc.read().decode(errors="replace")
            wait = _retry_after(exc, text, attempt)
            if wait is None or attempt == ATTEMPTS - 1:
                raise GitHubError(f"GitHub API {exc.code}: {text[:300]}") from exc
        except urllib.error.URLError as exc:
            if attempt == ATTEMPTS - 1:
                raise GitHubError(f"Could not reach the GitHub API: {exc.reason}") from exc
            wait = float(2 ** attempt)
        _sleep(wait)
    raise GitHubError("GitHub API request failed after retries.")


def _posted_markers(repo: str, number: int, token: str, request) -> set[str]:
    """Fingerprints of findings this tool already commented on in earlier runs (best effort)."""
    seen: set[str] = set()
    try:
        for page in range(1, MAX_PAGES + 1):
            batch = request("GET", f"{API}/repos/{repo}/pulls/{number}/comments?per_page=100&page={page}", token, None)
            if not isinstance(batch, list):
                break
            seen.update(m for c in batch for m in MARKER_RE.findall(str((c or {}).get("body", ""))))
            if len(batch) < 100:
                break
    except GitHubError:
        return set()  # listing is an optimisation; never block the review on it
    return seen


def build_review(result: ReviewResult, threshold: Severity, commit_id: str | None, already: set[str] = frozenset()) -> dict:
    shown = [f for f in result.findings if f.ai_verdict != "false_positive"]
    fresh = [f for f in shown if not f.fingerprint or f.fingerprint not in already]
    comments = [{"path": f.path, "line": f.line, "side": "RIGHT",
                 "body": comment_body(f) + (f"\n\n{MARKER.format(f.fingerprint)}" if f.fingerprint else "")}
                for f in fresh[:MAX_INLINE]]
    body = to_markdown(result, threshold)
    if len(shown) > len(fresh):
        body += f"\n\n_{len(shown) - len(fresh)} finding(s) were already commented on in an earlier run and are not repeated._"
    shown = fresh
    if len(shown) > MAX_INLINE:
        body += f"\n\n_{len(shown) - MAX_INLINE} more finding(s) are in the summary table but not commented inline._"
    if len(body) > MAX_BODY:
        cut = body.rfind("\n", 0, MAX_BODY)
        body = body[:cut if cut > 0 else MAX_BODY] + "\n\n_The summary was too long for GitHub and was cut here; the full report is in the job summary and SARIF._"
    for c in comments:
        c["body"] = c["body"][:MAX_BODY]
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
    review = build_review(result, threshold, sha, _posted_markers(repo, number, token, request))
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
