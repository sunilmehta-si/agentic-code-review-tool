"""GitHub Actions rules: the CI/CD supply chain is part of the attack surface."""
from __future__ import annotations

import re

from ..models import Severity
from .base import line_matches, make, rule

GHA = ["github-actions"]
HARDENING = "https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions"
UNTRUSTED = re.compile(r"\$\{\{\s*(github\.event\.(issue|pull_request|comment|review|review_comment|discussion|head_commit|commits|pages)"
                       r"[^}]*\.(title|body|message|name|label|ref|email|head_ref)|github\.head_ref)[^}]*\}\}")
FIRST_PARTY = ("actions/", "github/")


def _run_block_lines(lines: list[str]) -> set[int]:
    """Line numbers that belong to a `run:` script (inline or block scalar)."""
    out, indent = set(), None
    for i, line in enumerate(lines, start=1):
        m = re.match(r"^(\s*)(-\s*)?run\s*:\s*(.*)$", line)
        if m:
            out.add(i)
            indent = len(m.group(1)) + (2 if m.group(2) else 0) if m.group(3).strip() in ("|", ">", "|-", ">-", "") else None
            continue
        if indent is not None:
            if line.strip() == "" or len(line) - len(line.lstrip()) > indent:
                out.add(i)
            else:
                indent = None
    return out


@rule("ACR-GHA-001", "pull_request_target checks out untrusted PR code", Severity.CRITICAL, "ci-cd", GHA,
      fix="Use pull_request for builds. If pull_request_target is required, never check out or run the PR's head.",
      references=[HARDENING])
def prt_checkout(path, text, lines):
    if not re.search(r"^\s*pull_request_target\s*:|on\s*:\s*\[?[^\n]*pull_request_target", text, re.M):
        return
    pat = re.compile(r"ref\s*:\s*\$\{\{\s*github\.(event\.pull_request\.head\.(sha|ref)|head_ref)")
    yield from line_matches(prt_checkout.info, path, lines, pat)


@rule("ACR-GHA-002", "Untrusted event data interpolated into a shell script", Severity.HIGH, "ci-cd", GHA,
      fix="Pass the value through an env: variable and quote it in the script, e.g. env: TITLE: ${{ github.event.issue.title }} "
          "then run: echo \"$TITLE\".",
      references=[HARDENING])
def script_injection(path, text, lines):
    run_lines = _run_block_lines(lines)
    for i, line in enumerate(lines, start=1):
        if i in run_lines and UNTRUSTED.search(line):
            yield make(script_injection.info, path, i)


@rule("ACR-GHA-003", "Third-party action not pinned to a commit SHA", Severity.MEDIUM, "ci-cd", GHA,
      fix="Pin to the full 40-character commit SHA and keep the version in a comment: uses: org/action@<sha> # v1.2.3. "
          "Tags can be moved to malicious code.",
      references=[HARDENING])
def unpinned_action(path, text, lines):
    info = unpinned_action.info
    for i, line in enumerate(lines, start=1):
        m = re.search(r"uses\s*:\s*['\"]?([^'\"\s#]+)@([^'\"\s#]+)", line)
        if not m:
            continue
        action, ref = m.group(1), m.group(2)
        if action.startswith(FIRST_PARTY) or action.startswith("./") or re.fullmatch(r"[0-9a-f]{40}", ref):
            continue
        yield make(info, path, i, f"'{action}@{ref}' follows a mutable ref.")


@rule("ACR-GHA-004", "Workflow token has broad or default permissions", Severity.MEDIUM, "ci-cd", GHA,
      fix="Declare least privilege at the top: permissions: { contents: read } and widen per job only where needed.",
      references=[HARDENING])
def permissions(path, text, lines):
    info = permissions.info
    write_all = list(line_matches(info, path, lines, re.compile(r"^\s*permissions\s*:\s*write-all\b")))
    yield from write_all
    if not write_all and not re.search(r"^\s*permissions\s*:", text, re.M):
        yield make(info, path, 1, "No permissions block, so the token gets the repository default (often read/write).",
                   severity=Severity.LOW)


@rule("ACR-GHA-005", "Secret printed to the workflow log", Severity.HIGH, "ci-cd", GHA,
      fix="Never echo secrets. Pass them via env: to the single step that needs them.", references=[HARDENING])
def secret_echo(path, text, lines):
    yield from line_matches(secret_echo.info, path, lines,
                            re.compile(r"\b(echo|printf|cat)\b[^\n]*\$\{\{\s*secrets\.(?!GITHUB_TOKEN\b)"))


@rule("ACR-GHA-006", "Deprecated workflow command", Severity.LOW, "ci-cd", GHA,
      fix="Write to $GITHUB_OUTPUT / $GITHUB_STATE instead of ::set-output / ::save-state.")
def deprecated_cmd(path, text, lines):
    yield from line_matches(deprecated_cmd.info, path, lines, re.compile(r"::(set-output|save-state|add-path|set-env)\b"))


@rule("ACR-GHA-007", "Cloud OIDC token granted to every job in the workflow", Severity.MEDIUM, "ci-cd", GHA,
      fix="Keep top-level permissions read-only and add `id-token: write` only to the deploy job that exchanges it for cloud credentials.",
      references=["https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/about-security-hardening-with-openid-connect"])
def workflow_oidc(path, text, lines):
    info = workflow_oidc.info
    in_top = False
    for i, line in enumerate(lines, start=1):
        if re.match(r"^permissions\s*:", line):
            in_top = True
            if re.search(r"write-all", line):
                return  # covered by ACR-GHA-004
            continue
        if in_top:
            if line.strip() and not line.startswith((" ", "\t")):
                in_top = False
            elif re.match(r"^\s+id-token\s*:\s*write\b", line):
                yield make(info, path, i)
