"""`acr` command line: review a change, list rules, print the version."""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from . import __version__, report
from .engine import review
from .models import Severity
from .rules import base as rules_base

FAIL_LEVELS = {"critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM, "low": Severity.LOW}


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="acr", description="Agentic, scanner-grounded code review for the whole pull request.")
    p.add_argument("--version", action="version", version=f"agentic-code-review-tool {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    r = sub.add_parser("review", help="Review changed code (default: working tree vs HEAD).")
    r.add_argument("--root", default=".", help="Repository root (default: current directory).")
    r.add_argument("--base", help="Base ref, e.g. origin/main. Reviews base...head (merge-base) like a PR.")
    r.add_argument("--head", help="Head ref (default: HEAD).")
    r.add_argument("--all", dest="full", action="store_true", help="Review every tracked file, not just the change.")
    r.add_argument("--format", choices=("markdown", "json", "sarif"), default="markdown")
    r.add_argument("--output", "-o", help="Write the report to a file instead of stdout.")
    r.add_argument("--sarif", metavar="PATH", help="Also write SARIF to PATH (same run, no re-scan).")
    r.add_argument("--json", dest="json_out", metavar="PATH", help="Also write JSON to PATH (same run, no re-scan).")
    r.add_argument("--markdown", dest="md_out", metavar="PATH", help="Also write Markdown to PATH (same run, no re-scan).")
    r.add_argument("--fail-on", choices=(*FAIL_LEVELS, "never"), default="high",
                   help="Exit 1 if a finding at or above this severity remains (default: high).")
    r.add_argument("--no-scanners", action="store_true", help="Built-in rules only; skip external scanners.")
    r.add_argument("--scanners", help="Comma-separated subset, e.g. semgrep,trivy.")
    r.add_argument("--exclude", action="append", default=[], help="Glob to skip (repeatable).")
    r.add_argument("--ai", choices=("claude", "openai"), default=os.environ.get("ACR_AI") or None,
                   help="Have an LLM agent verify findings and explain fixes (claude needs the [claude] extra).")
    r.add_argument("--model", help="Model override (default: claude-opus-5-5 for claude; ACR_MODEL for openai).")
    r.add_argument("--max-steps", type=int, default=12, help="Maximum agent tool-use steps (default: 12).")
    r.add_argument("--github-review", action="store_true",
                   help="Post a summary and inline comments to the current pull request (needs GITHUB_TOKEN).")
    r.add_argument("--pr", type=int, help="Pull request number (default: from the GitHub Actions event).")

    sub.add_parser("rules", help="List built-in rules.")
    return p


def _cmd_rules() -> int:
    for info, _ in sorted(rules_base.REGISTRY, key=lambda x: x[0].rule_id):
        print(f"{info.rule_id:<16} {info.severity.label():<9} {info.category:<13} {info.title}")
    print(f"\n{len(rules_base.REGISTRY)} built-in rules")
    return 0


def _cmd_review(args: argparse.Namespace) -> int:
    only = {s.strip() for s in args.scanners.split(",")} if args.scanners else None
    result = review(Path(args.root), base=args.base, head=args.head, full=args.full,
                    use_scanners=not args.no_scanners, only_scanners=only, excludes=tuple(args.exclude))
    if args.ai:
        from .agent.review import AgentError
        from .agent.run import apply_ai, make_reviewer
        try:
            reviewer = make_reviewer(args.ai, model=args.model, max_steps=args.max_steps)
        except AgentError as exc:
            result.ai_error = str(exc)
        else:
            apply_ai(result, Path(args.root).resolve(), reviewer, base=args.base, head=args.head, full=args.full)
        if result.ai_error:
            print(f"acr: AI review skipped: {result.ai_error}", file=sys.stderr)
    threshold = FAIL_LEVELS.get(args.fail_on)
    rendered = {"markdown": lambda: report.to_markdown(result, threshold or Severity.CRITICAL),
                "json": lambda: report.to_json(result), "sarif": lambda: report.to_sarif(result)}[args.format]()
    if args.output:
        Path(args.output).write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)
    # Extra formats come from the same result, so scanners and the AI agent run only once.
    for path, render in ((args.sarif, lambda: report.to_sarif(result)), (args.json_out, lambda: report.to_json(result)),
                         (args.md_out, lambda: report.to_markdown(result, threshold or Severity.CRITICAL))):
        if path:
            Path(path).write_text(render() + "\n", encoding="utf-8")
    if args.github_review:
        from .github import GitHubError, post_review
        try:
            url = post_review(result, threshold or Severity.CRITICAL, pr=args.pr)
            print(f"acr: review posted {url}".rstrip(), file=sys.stderr)
        except GitHubError as exc:
            print(f"acr: could not post the PR review: {exc}", file=sys.stderr)
    if threshold is not None and result.blocking(threshold):
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "rules":
        return _cmd_rules()
    try:
        return _cmd_review(args)
    except Exception as exc:  # surface a clean error in CI logs
        print(f"acr: error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
