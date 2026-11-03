"""Tiny rule framework: a rule is a function that turns one file into findings.

Rules are deliberately dependency-light and line-precise. They run with no external
tools installed, so the review is useful on a laptop, in CI, and before any LLM is called.
"""
from __future__ import annotations

import datetime
import fnmatch
import re
from dataclasses import dataclass
from typing import Callable, Iterable

from ..models import Finding, Severity

IGNORE_MARKER = "acr:ignore"
IGNORE_SCOPED = re.compile(r"acr:ignore\[([^\]]*)\]")
IGNORE_UNTIL = re.compile(r"acr:ignore(?:\[[^\]]*\])?\s+until=(\d{4}-\d{2}-\d{2})\b")


def _covers(text: str, rule_id: str) -> bool:
    if IGNORE_MARKER not in text:
        return False
    scoped = IGNORE_SCOPED.findall(text)
    if not scoped:
        return True
    wanted = [p.strip().upper() for group in scoped for p in group.split(",") if p.strip()]
    return any(fnmatch.fnmatchcase(rule_id.upper(), pat) for pat in wanted)


def expired_on(text: str, rule_id: str, today: datetime.date | None = None) -> str | None:
    """The `until=` date of a marker covering `rule_id` if that date has passed, else None."""
    m = IGNORE_UNTIL.search(text)
    if not m or not _covers(text, rule_id):
        return None
    try:
        until = datetime.date.fromisoformat(m.group(1))
    except ValueError:
        return None
    return m.group(1) if (today or datetime.date.today()) > until else None


# The other tools' markers. A line that carries gosec's `//nolint:gosec` or `// #nosec`, or bandit's `# nosec`, records a
# reviewed decision about the same kind of finding, usually with the reason beside it (KubeRay: "We are not using this
# for security purposes"). Reporting it again only teaches people to stop trusting the report. Each marker covers the
# rules whose checks that tool also makes, and no others: a bare `//nolint` silences linters, not security rules.
GOSEC_MARKER = re.compile(r"//\s*(?:nolint\s*:[\w,\s-]*\bgosec\b|#nosec\b)")
BANDIT_MARKER = re.compile(r"#\s*nosec\b")
GOSEC_RULES = frozenset(f"ACR-APP-{n:03d}" for n in (1, 2, 5, 7, 10, 13, 14, 22, 23, 24, 25))
BANDIT_RULES = frozenset(f"ACR-APP-{n:03d}" for n in (1, 2, 3, 4, 5, 6, 7, 10, 11, 13, 21, 22, 23, 26))


def _acknowledged(text: str, rule_id: str) -> bool:
    return bool((rule_id in GOSEC_RULES and GOSEC_MARKER.search(text)) or (rule_id in BANDIT_RULES and BANDIT_MARKER.search(text)))


def ignored(text: str, rule_id: str, today: datetime.date | None = None) -> bool:
    """True if a line carries an inline suppression that covers `rule_id`.

    A bare `acr:ignore` silences every rule on the line; `acr:ignore[ACR-AI-005, semgrep:*]`
    silences only the listed rule ids or globs, so other problems on the same line still show.
    Adding `until=YYYY-MM-DD` makes the suppression lapse after that date. gosec's and bandit's own markers
    count for the rules they cover too (see GOSEC_RULES and BANDIT_RULES).
    """
    return (_covers(text, rule_id) and expired_on(text, rule_id, today) is None) or _acknowledged(text, rule_id)


def suppressed(lines: list[str], f: Finding) -> bool:
    """Apply the marker on the finding's line; a lapsed marker lets the finding through with a note."""
    if not 1 <= f.line <= len(lines):
        return False
    text = lines[f.line - 1]
    if ignored(text, f.rule_id):
        return True
    lapsed = expired_on(text, f.rule_id)
    if lapsed:
        f.detail = (f.detail + f" The acr:ignore on this line expired on {lapsed}.").strip()
    return False


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


# Lines a kind of file says no rule should read: kind -> function from the file's lines to those line numbers. A rule
# that applies to the kind never reports on them. Kubernetes uses it to leave out CustomResourceDefinition documents.
LINE_FILTERS: dict[str, Callable[[list[str]], set[int]]] = {}


def run_rules(path: str, text: str, kinds: set[str]) -> list[Finding]:
    lines = text.splitlines()
    out: list[Finding] = []
    skipped: dict[str, set[int]] = {}
    for info, fn in REGISTRY:
        if info.applies_to & kinds or "*" in info.applies_to:
            try:
                # Suppression is checked at the reported line, so structural rules (which point at a
                # container, block or server entry) honour `acr:ignore` exactly like line rules do.
                found = [f for f in fn(path, text, lines) if not suppressed(lines, f)]
                for kind in info.applies_to & kinds & LINE_FILTERS.keys():
                    if kind not in skipped:
                        skipped[kind] = LINE_FILTERS[kind](lines)
                    found = [f for f in found if f.line not in skipped[kind]]
                out.extend(found)
            except Exception as exc:  # a broken rule must never break the whole review
                out.append(Finding(rule_id="ACR-INTERNAL", title=f"Rule {info.rule_id} failed: {exc.__class__.__name__}",
                                   severity=Severity.INFO, path=path, line=1, tool="acr", category="other"))
    return out


TEST_DIRS = {"test", "tests", "e2e", "testdata", "testutil", "testing"}
FIXTURE_DIRS = {"testdata", "fixtures"}


def is_test(path: str) -> bool:
    """A test module or anything under a test directory: code whose inputs nobody outside controls."""
    *dirs, name = path.split("/")
    return (name.endswith("_test.go") or name.startswith("test_") or name.endswith("_test.py")
            or name == "conftest.py" or bool(TEST_DIRS & set(dirs)))


def is_fixture(path: str) -> bool:
    """A file under testdata/ or fixtures/: an input the project's tests read, never something it deploys."""
    return bool(FIXTURE_DIRS & set(path.split("/")[:-1]))
