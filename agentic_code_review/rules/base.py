"""Tiny rule framework: a rule is a function that turns one file into findings.

Rules are deliberately dependency-light and line-precise. They run with no external
tools installed, so the review is useful on a laptop, in CI, and before any LLM is called.
"""
from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from typing import Callable, Iterable

from ..models import Finding, Severity

IGNORE_MARKER = "acr:ignore"
IGNORE_SCOPED = re.compile(r"acr:ignore\[([^\]]*)\]")


def ignored(text: str, rule_id: str) -> bool:
    """True if a line carries an inline suppression that covers `rule_id`.

    A bare `acr:ignore` silences every rule on the line; `acr:ignore[ACR-AI-005, semgrep:*]`
    silences only the listed rule ids or globs, so other problems on the same line still show.
    """
    if IGNORE_MARKER not in text:
        return False
    scoped = IGNORE_SCOPED.findall(text)
    if not scoped:
        return True
    wanted = [p.strip().upper() for group in scoped for p in group.split(",") if p.strip()]
    return any(fnmatch.fnmatchcase(rule_id.upper(), pat) for pat in wanted)


@dataclass(frozen=True)
class RuleInfo:
    rule_id: str
    title: str
    severity: Severity
    category: str
    applies_to: frozenset[str]          # file kinds from classify.kinds()
    fix: str = ""
    references: tuple[str, ...] = ()


CheckFn = Callable[[str, str, list[str]], Iterable[Finding]]
REGISTRY: list[tuple[RuleInfo, CheckFn]] = []


def rule(rule_id: str, title: str, severity: Severity, category: str, applies_to: Iterable[str],
         fix: str = "", references: Iterable[str] = ()):
    """Register a check. The check receives (path, text, lines) and yields findings."""
    info = RuleInfo(rule_id, title, severity, category, frozenset(applies_to), fix, tuple(references))

    def deco(fn: CheckFn) -> CheckFn:
        fn.info = info  # type: ignore[attr-defined]
        REGISTRY.append((info, fn))
        return fn
    return deco


def make(info: RuleInfo, path: str, line: int, detail: str = "", severity: Severity | None = None) -> Finding:
    return Finding(rule_id=info.rule_id, title=info.title, severity=severity or info.severity, path=path, line=line,
                   tool="acr", category=info.category, detail=detail, fix=info.fix, references=list(info.references))


def line_matches(info: RuleInfo, path: str, lines: list[str], pattern: re.Pattern[str],
                 detail: str = "", skip_comments: bool = True) -> Iterable[Finding]:
    """Yield one finding per line matching `pattern`, honouring the inline ignore marker."""
    for i, text in enumerate(lines, start=1):
        if ignored(text, info.rule_id):
            continue
        stripped = text.lstrip()
        if skip_comments and stripped.startswith(("#", "//")):
            continue
        if pattern.search(text):
            yield make(info, path, i, detail)


def find_line(lines: list[str], needle: str | re.Pattern[str], start: int = 1) -> int:
    """First 1-based line at or after `start` containing `needle` (string or regex); 1 if absent."""
    for i in range(max(start, 1), len(lines) + 1):
        text = lines[i - 1]
        if (needle.search(text) if isinstance(needle, re.Pattern) else needle in text):
            return i
    return 1


def run_rules(path: str, text: str, kinds: set[str]) -> list[Finding]:
    lines = text.splitlines()
    out: list[Finding] = []
    for info, fn in REGISTRY:
        if info.applies_to & kinds or "*" in info.applies_to:
            try:
                out.extend(fn(path, text, lines))
            except Exception as exc:  # a broken rule must never break the whole review
                out.append(Finding(rule_id="ACR-INTERNAL", title=f"Rule {info.rule_id} failed: {exc.__class__.__name__}",
                                   severity=Severity.INFO, path=path, line=1, tool="acr", category="other"))
    return out
