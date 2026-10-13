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
# Order and names of the areas in the README's rule catalogue.
RULE_AREAS = {"secrets": "Secrets", "app-security": "Application code", "ai-security": "AI / LLM / agent code",
              "kubernetes": "Kubernetes", "container": "Dockerfile", "ci-cd": "GitHub Actions", "iac": "Terraform"}


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="acr", description="Agentic, scanner-grounded code review for the whole pull request.")
    p.add_argument("--version", action="version", version=f"agentic-code-review-tool {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    r = sub.add_parser("review", help="Review changed code (default: working tree vs HEAD).")
    r.add_argument("--root", default=".", help="Repository root (default: current directory).")
    r.add_argument("--base", help="Base ref, e.g. origin/main. Reviews base...head (merge-base) like a PR.")
    r.add_argument("--head", help="Head ref (default: HEAD).")
    r.add_argument("--all", dest="full", action="store_true", help="Review every tracked file, not just the change.")
    r.add_argument("--diff-file", metavar="PATH",
                   help="Review the changed lines of a unified diff file ('-' for stdin) against the files in --root.")
    r.add_argument("--staged", action="store_true", help="Review only staged changes, as they will be committed (for git hooks).")
    r.add_argument("--format", choices=("markdown", "json", "sarif", "github", "gitlab", "junit"), default="markdown",
                   help="github prints workflow-command annotations; gitlab writes a GitLab Code Quality report.")
    r.add_argument("--output", "-o", help="Write the report to a file instead of stdout.")
    r.add_argument("--sarif", metavar="PATH", help="Also write SARIF to PATH (same run, no re-scan).")
    r.add_argument("--json", dest="json_out", metavar="PATH", help="Also write JSON to PATH (same run, no re-scan).")
    r.add_argument("--markdown", dest="md_out", metavar="PATH", help="Also write Markdown to PATH (same run, no re-scan).")
    r.add_argument("--fail-on", choices=(*FAIL_LEVELS, "never"), default=None,
                   help="Exit 1 if a finding at or above this severity remains (default: .acr.yml, else high).")
    r.add_argument("--min-severity", choices=("critical", "high", "medium", "low", "info"), default=None,
                   help="Leave out findings below this severity (default: .acr.yml, else show everything).")
    r.add_argument("--no-scanners", action="store_true", help="Built-in rules only; skip external scanners.")
    r.add_argument("--timings", action="store_true", help="Print how long the rules and each scanner took (stderr).")
    r.add_argument("--scanners", help="Comma-separated subset, e.g. semgrep,trivy.")
    r.add_argument("--exclude", action="append", default=[], help="Glob to skip (repeatable).")
    r.add_argument("--include", action="append", default=[], help="Only review paths matching this glob (repeatable).")
    r.add_argument("--ai", choices=("claude", "openai"), default=os.environ.get("ACR_AI") or None,
                   # falls back to `ai:` in .acr.yml
                   help="Have an LLM agent verify findings and explain fixes (claude needs the [claude] extra).")
    r.add_argument("--model", help="Model override (default: claude-opus-5-5 for claude; ACR_MODEL for openai).")
    r.add_argument("--max-steps", type=int, default=12, help="Maximum agent tool-use steps (default: 12).")
    r.add_argument("--ai-dry-run", action="store_true",
                   help="Print the redacted request the AI reviewer would receive, then exit without calling a model.")
    r.add_argument("--ai-max-findings", type=int, default=50,
                   help="Send at most this many findings (most severe first) to the AI reviewer (default: 50).")
    r.add_argument("--github-review", action="store_true",
                   help="Post a summary and inline comments to the current pull request (needs GITHUB_TOKEN).")
    r.add_argument("--pr", type=int, help="Pull request number (default: from the GitHub Actions event).")
    r.add_argument("--baseline", help="Baseline file to suppress known findings (default: .acr.yml, else .acr-baseline.json if present).")

    b = sub.add_parser("baseline", help="Accept every current finding so only new ones fail future reviews.")
    b.add_argument("--root", default=".", help="Repository root (default: current directory).")
    b.add_argument("--output", default=None, help="Baseline file (default: .acr.yml 'baseline', else .acr-baseline.json).")
    b.add_argument("--no-scanners", action="store_true", help="Built-in rules only.")

    i = sub.add_parser("init", help="Write a starter .acr.yml in the repository root.")
    i.add_argument("--root", default=".", help="Repository root (default: current directory).")
    i.add_argument("--force", action="store_true", help="Overwrite an existing config file.")

    rl = sub.add_parser("rules", help="List built-in rules and the repository's custom rules.")
    rl.add_argument("--root", default=".", help="Repository whose .acr.yml custom rules to include (default: current directory).")
    rl.add_argument("--format", choices=("text", "markdown", "json"), default="text",
                    help="markdown prints the README catalogue table; json suits other tools.")
    c = sub.add_parser("classify", help="Show how files are classified and which built-in rules apply to them.")
    c.add_argument("paths", nargs="+", help="Files to classify.")
    e = sub.add_parser("explain", help="Explain a built-in rule: why it matters and how to fix it.")
    e.add_argument("rule_id", help="Rule id, e.g. ACR-AI-002 (case-insensitive).")
    e.add_argument("--root", default=".", help="Repository whose .acr.yml custom rules to search (default: current directory).")
    return p


def _custom(root: str) -> list:
    """The repository's custom rules; a broken config is reported by `acr review`, not here."""
    from .config import ConfigError, load
    try:
        return load(Path(root)).custom_rules
    except ConfigError as exc:
        print(f"acr: ignoring custom rules: {exc}", file=sys.stderr)
        return []


def _cmd_rules(fmt: str = "text", root: str = ".") -> int:
    custom = {c.rule_id: c for c in _custom(root)}
    infos = sorted([info for info, _ in rules_base.REGISTRY] +
                   [rules_base.RuleInfo(c.rule_id, c.title, c.severity, c.category, frozenset(c.files or ("*",)), c.fix,
                                        c.references) for c in custom.values()], key=lambda i: i.rule_id)
    if fmt == "json":
        import json
        print(json.dumps([{"id": i.rule_id, "title": i.title, "severity": i.severity.label(), "category": i.category,
                           "applies_to": sorted(i.applies_to), "fix": i.fix, "references": list(i.references),
                           "custom": i.rule_id in custom} for i in infos], indent=2))
        return 0
    if fmt == "markdown":
        order = list(RULE_AREAS)
        print("| Area | Rule | Severity | What it catches |\n|---|---|---|---|")
        for i in sorted(infos, key=lambda i: (order.index(i.category) if i.category in order else len(order), i.rule_id)):
            title = i.title.replace("|", "\\|")
            print(f"| {RULE_AREAS.get(i.category, i.category)} | `{i.rule_id}` | {i.severity.label()} | {title} |")
        return 0
    for info in infos:
        print(f"{info.rule_id:<16} {info.severity.label():<9} {info.category:<13} {info.title}"
              + ("  (custom)" if info.rule_id in custom else ""))
    print(f"\n{len(rules_base.REGISTRY)} built-in rules" + (f", {len(custom)} custom" if custom else ""))
    return 0


def _cmd_explain(rule_id: str, root: str = ".") -> int:
    wanted = rule_id.strip().upper()
    for c in _custom(root):
        if c.rule_id == wanted:
            print(f"{c.rule_id}  ·  {c.severity.label()}  ·  {c.category}  (custom rule from .acr.yml)")
            print(f"\n{c.title}\n\nPattern: {c.pattern.pattern}\nFiles: {', '.join(c.files) or 'every file'}")
            if c.fix:
                print(f"\nHow to fix:\n  {c.fix}")
            if c.references:
                print("\nReferences:\n" + "\n".join(f"  {r}" for r in c.references))
            return 0
    for info, fn in rules_base.REGISTRY:
        if info.rule_id == wanted:
            doc = " ".join((fn.__module__.rsplit(".", 1)[-1] + " rules").split())
            print(f"{info.rule_id}  ·  {info.severity.label()}  ·  {info.category}  ({doc})")
            print(f"\n{info.title}\n")
            print(f"Applies to: {', '.join(sorted(info.applies_to))}")
            if info.fix:
                print(f"\nHow to fix:\n  {info.fix}")
            if info.references:
                print("\nReferences:\n" + "\n".join(f"  {r}" for r in info.references))
            print("\nSuppress one reviewed line with an inline `acr:ignore` comment, or disable the rule in .acr.yml.")
            return 0
    close = [i.rule_id for i, _ in rules_base.REGISTRY if wanted.split("-")[:2] == i.rule_id.split("-")[:2]]
    hint = f" Did you mean: {', '.join(sorted(close)[:6])}?" if close else " Run `acr rules` for the list."
    print(f"acr: unknown rule '{rule_id}'.{hint}", file=sys.stderr)
    return 2


def _cmd_init(args: argparse.Namespace) -> int:
    from .config import FILENAMES, STARTER
    root = Path(args.root)
    existing = next((root / n for n in FILENAMES if (root / n).is_file()), None)
    if existing and not args.force:
        print(f"acr: {existing.name} already exists; use --force to overwrite it.", file=sys.stderr)
        return 1
    target = existing or root / FILENAMES[0]
    target.write_text(STARTER, encoding="utf-8")
    print(f"acr: wrote {target.name}. Edit it, then commit it with the repository.")
    return 0


def _cmd_classify(paths: list[str]) -> int:
    from .classify import kinds as classify
    status = 0
    for p in paths:
        try:
            text = Path(p).read_text(errors="replace")
        except OSError as exc:
            print(f"{p}: cannot read ({exc.strerror})", file=sys.stderr)
            status = 2
            continue
        k = classify(Path(os.path.relpath(p)).as_posix(), text)  # paths are classified relative to the repo root
        applies = sorted(i.rule_id for i, _ in rules_base.REGISTRY if i.applies_to & k or "*" in i.applies_to)
        print(f"{p}\n  kinds: {', '.join(sorted(k)) or '(none: only any-file rules apply)'}\n  rules: {len(applies)} ({', '.join(applies)})")
    return status


def _cmd_review(args: argparse.Namespace) -> int:
    from .config import ConfigError, load
    try:
        cfg = load(Path(args.root))
    except ConfigError as exc:
        print(f"acr: config error: {exc}", file=sys.stderr)
        return 2
    if args.staged and (args.full or args.base):
        print("acr: --staged cannot be combined with --all or --base.", file=sys.stderr)
        return 2
    diff_text = None
    if args.diff_file:
        if args.staged or args.full or args.base:
            print("acr: --diff-file cannot be combined with --staged, --all or --base.", file=sys.stderr)
            return 2
        diff_text = sys.stdin.read() if args.diff_file == "-" else Path(args.diff_file).read_text(encoding="utf-8", errors="replace")
    args.fail_on = args.fail_on or cfg.fail_on or "high"
    args.ai = args.ai or cfg.ai
    only = {s.strip() for s in args.scanners.split(",")} if args.scanners else (set(cfg.scanners) if cfg.scanners else None)
    result = review(Path(args.root), base=args.base, head=args.head, full=args.full,
                    use_scanners=not args.no_scanners, only_scanners=only, excludes=tuple(args.exclude) + tuple(cfg.exclude),
                    disable=tuple(cfg.disable), severity_overrides=cfg.severity, staged=args.staged,
                    includes=tuple(args.include) or tuple(cfg.include), custom_rules=tuple(cfg.custom_rules),
                    diff_text=diff_text)
    from . import baseline as baseline_mod
    baseline_mod.apply(Path(args.root).resolve(), result,
                       baseline_mod.load(Path(args.root).resolve(), args.baseline or cfg.baseline or baseline_mod.DEFAULT_PATH))
    if args.timings:
        for name, secs in sorted(result.timings.items(), key=lambda kv: -kv[1]):
            print(f"acr: {name:<24} {secs * 1000:8.0f} ms", file=sys.stderr)
    floor = args.min_severity or cfg.min_severity
    if floor:  # applied before the AI step so it never spends tokens on findings nobody will see
        level = Severity.parse(floor)
        kept = [f for f in result.findings if f.severity >= level]
        result.below_floor, result.findings = len(result.findings) - len(kept), kept
    if args.ai_dry_run:
        from .agent.review import SYSTEM_PROMPT
        from .agent.run import build_request
        message = build_request(result, Path(args.root).resolve(), base=args.base, head=args.head, full=args.full,
                                staged=args.staged, diff_text=diff_text, max_findings=args.ai_max_findings)
        print(f"--- system prompt ---\n{SYSTEM_PROMPT}\n\n--- first user message ---\n{message}")
        return 0
    if args.ai:
        from .agent.review import AgentError
        from .agent.run import apply_ai, make_reviewer
        try:
            reviewer = make_reviewer(args.ai, model=args.model, max_steps=args.max_steps)
        except AgentError as exc:
            result.ai_error = str(exc)
        else:
            apply_ai(result, Path(args.root).resolve(), reviewer, base=args.base, head=args.head, full=args.full,
                     staged=args.staged, diff_text=diff_text, max_findings=args.ai_max_findings)
        if result.ai_error:
            print(f"acr: AI review skipped: {result.ai_error}", file=sys.stderr)
    threshold = FAIL_LEVELS.get(args.fail_on)
    rendered = {"markdown": lambda: report.to_markdown(result, threshold or Severity.CRITICAL),
                "json": lambda: report.to_json(result, threshold), "sarif": lambda: report.to_sarif(result),
                "github": lambda: report.to_github(result), "gitlab": lambda: report.to_gitlab(result),
                "junit": lambda: report.to_junit(result, threshold)}[args.format]()
    if args.output:
        Path(args.output).write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)
    # Extra formats come from the same result, so scanners and the AI agent run only once.
    for path, render in ((args.sarif, lambda: report.to_sarif(result)), (args.json_out, lambda: report.to_json(result, threshold)),
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


def _cmd_baseline(args: argparse.Namespace) -> int:
    from . import baseline as baseline_mod
    from .config import ConfigError, load
    root = Path(args.root).resolve()
    try:
        cfg = load(root)
    except ConfigError as exc:
        print(f"acr: config error: {exc}", file=sys.stderr)
        return 2
    result = review(root, full=True, use_scanners=not args.no_scanners, excludes=tuple(cfg.exclude),
                    disable=tuple(cfg.disable), severity_overrides=cfg.severity, includes=tuple(cfg.include),
                    custom_rules=tuple(cfg.custom_rules))
    path = args.output or cfg.baseline or baseline_mod.DEFAULT_PATH
    n = baseline_mod.write(root, result, path)
    print(f"acr: wrote {n} known finding(s) to {path}. Commit it; future reviews fail only on new findings.")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "rules":
        return _cmd_rules(args.format, args.root)
    if args.command == "baseline":
        return _cmd_baseline(args)
    if args.command == "init":
        return _cmd_init(args)
    if args.command == "classify":
        return _cmd_classify(args.paths)
    if args.command == "explain":
        return _cmd_explain(args.rule_id, args.root)
    try:
        return _cmd_review(args)
    except Exception as exc:  # surface a clean error in CI logs
        print(f"acr: error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
