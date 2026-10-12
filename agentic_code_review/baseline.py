"""Baseline: accept today's findings so only new problems fail pull requests.

A fingerprint is the rule, the file and the normalised text of the flagged line (not its number),
so a known finding stays suppressed when code above it moves, and reappears if the line changes.
"""
from __future__ import annotations

import json
from pathlib import Path

from .engine import ReviewResult
from .models import Finding
from .models import fingerprint as _fingerprint

DEFAULT_PATH = ".acr-baseline.json"


def _line(root: Path, path: str, line: int) -> str:
    try:
        lines = (root / path).read_text(errors="replace").splitlines()
    except OSError:
        return ""
    return lines[line - 1] if 0 < line <= len(lines) else ""


def fingerprint(root: Path, f: Finding) -> str:
    return f.fingerprint or _fingerprint(f.rule_id, f.path, _line(root, f.path, f.line))


def write(root: Path, result: ReviewResult, path: str = DEFAULT_PATH) -> int:
    entries = sorted({(fingerprint(root, f), f.rule_id, f.path) for f in result.findings})
    doc = {"version": 1, "note": "Findings accepted as existing debt. Regenerate with `acr baseline`.",
           "findings": [{"fingerprint": fp, "rule": rule, "path": p} for fp, rule, p in entries]}
    (root / path).write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    return len(entries)


def load(root: Path, path: str = DEFAULT_PATH) -> set[str]:
    p = root / path
    if not p.is_file():
        return set()
    try:
        return {e["fingerprint"] for e in json.loads(p.read_text()).get("findings", [])}
    except (ValueError, KeyError, TypeError, AttributeError):
        return set()


def apply(root: Path, result: ReviewResult, known: set[str]) -> int:
    """Remove baselined findings from the result; return how many were suppressed."""
    if not known:
        return 0
    keep = [f for f in result.findings if fingerprint(root, f) not in known]
    removed = len(result.findings) - len(keep)
    result.findings = keep
    result.baselined = removed
    return removed
