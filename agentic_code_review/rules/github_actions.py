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


@rule("ACR-GHA-001", "Privileged workflow checks out untrusted PR code", Severity.CRITICAL, "ci-cd", GHA,
      fix="Use pull_request for builds. pull_request_target, issue_comment and workflow_run run with secrets and a write "
          "token: never check out or run the PR's head there, or split the job and pass only data between them.",
      references=[HARDENING, "https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/"])
def prt_checkout(path, text, lines):
    if not re.search(r"^\s*(pull_request_target|issue_comment|workflow_run)\s*:|^on\s*:[^\n]*\b(pull_request_target|issue_comment|workflow_run)\b",
                     text, re.M):
        return
    pat = re.compile(r"ref\s*:\s*['\"]?(\$\{\{\s*github\.(event\.pull_request\.head\.(sha|ref)|head_ref|event\.workflow_run\.head_(sha|branch))"
                     r"|refs/pull/\$\{\{)")
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


@rule("ACR-GHA-008", "Every repository secret handed to an external reusable workflow", Severity.MEDIUM, "ci-cd", GHA,
      fix="Pass only the secrets that workflow needs (secrets: { NPM_TOKEN: ${{ secrets.NPM_TOKEN }} }) and pin it to a commit SHA.",
      references=["https://docs.github.com/en/actions/sharing-automations/reusing-workflows#passing-secrets-to-nested-workflows"])
def secrets_inherit(path, text, lines):
    info = secrets_inherit.info
    for i, line in enumerate(lines, start=1):
        m = re.match(r"^(\s*)secrets\s*:\s*inherit\b", line)
        if not m:
            continue
        indent = len(m.group(1))
        # The job's `uses:` is a sibling key: same indentation, above this line, within the same job.
        for j in range(i - 2, -1, -1):
            prev = lines[j]
            if not prev.strip() or prev.lstrip().startswith("#"):
                continue
            lead = len(prev) - len(prev.lstrip())
            if lead < indent:
                break
            u = re.match(r"^\s*uses\s*:\s*['\"]?([^'\"\s#]+)", prev)
            if lead == indent and u:
                if not u.group(1).startswith("./"):
                    yield make(info, path, i, f"'{u.group(1)}' receives every secret in this repository.")
                break


@rule("ACR-GHA-009", "Self-hosted runner used by a pull-request workflow", Severity.MEDIUM, "ci-cd", GHA,
      fix="Run pull-request jobs on GitHub-hosted or ephemeral, isolated runners. On a persistent self-hosted runner, a PR "
          "(from a fork, in public repositories) can run code on your machine and leave something behind for the next job.",
      references=["https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners/about-self-hosted-runners#self-hosted-runner-security"])
def self_hosted_pr(path, text, lines):
    if not re.search(r"^\s*pull_request(_target)?\s*:|^on\s*:[^\n]*\bpull_request", text, re.M):
        return
    info = self_hosted_pr.info
    in_runs_on = False
    for i, line in enumerate(lines, start=1):
        m = re.match(r"^(\s*)runs-on\s*:\s*(.*)$", line)
        if m:
            in_runs_on = m.group(2).strip() in ("", "|", ">")
            if "self-hosted" in m.group(2):
                yield make(info, path, i)
            continue
        if in_runs_on:
            if re.match(r"^\s*-\s*['\"]?self-hosted\b", line):
                yield make(info, path, i)
            elif not re.match(r"^\s*-", line):
                in_runs_on = False


@rule("ACR-GHA-010", "Insecure workflow commands re-enabled (ACTIONS_ALLOW_UNSECURE_COMMANDS)", Severity.HIGH, "ci-cd", GHA,
      fix="Remove the variable and write to $GITHUB_ENV / $GITHUB_PATH. With it on, any log line that prints untrusted "
          "text can set environment variables such as LD_PRELOAD for later steps.",
      references=["https://github.blog/changelog/2020-10-01-github-actions-deprecating-set-env-and-add-path-commands/"])
def unsecure_commands(path, text, lines):
    pat = re.compile(r"ACTIONS_ALLOW_UNSECURE_COMMANDS\s*[:=]\s*['\"]?(true|1)\b", re.I)
    yield from line_matches(unsecure_commands.info, path, lines, pat)
