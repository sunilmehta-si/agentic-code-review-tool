"""Work out exactly which files and lines a change touches.

Reviewing only added/modified lines is what lets a team adopt the tool on a legacy
codebase without drowning every PR in old findings.
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

from .models import ChangedFile

HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def _git(root: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True, text=True).stdout


def parse_unified_diff(text: str) -> dict[str, ChangedFile]:
    """Parse `git diff -U0` output into added line numbers per file."""
    files: dict[str, ChangedFile] = {}
    current: ChangedFile | None = None
    for raw in text.splitlines():
        if raw.startswith("+++ "):
            target = raw[4:].strip()
            if target == "/dev/null":
                current = None
                continue
            path = target[2:] if target.startswith("b/") else target
            current = files.setdefault(path, ChangedFile(path))
            continue
        if raw.startswith("--- "):
            continue
        m = HUNK.match(raw)
        if m and current is not None:
            start, count = int(m.group(1)), int(m.group(2) or "1")
            current.added_lines.update(range(start, start + count))
    return files


def changed_files(root: Path, base: str | None, head: str | None) -> dict[str, ChangedFile]:
    """Changed files between two refs (merge-base semantics), or the working tree vs HEAD."""
    if base:
        rng = f"{base}...{head or 'HEAD'}"
        text = _git(root, "diff", "-U0", "--no-color", "--diff-filter=ACMR", rng)
    else:
        text = _git(root, "diff", "-U0", "--no-color", "--diff-filter=ACMR", "HEAD")
        # Untracked files count as fully added in workspace mode.
        for path in _git(root, "ls-files", "--others", "--exclude-standard").splitlines():
            p = root / path
            if p.is_file():
                text += f"\n+++ b/{path}\n@@ -0,0 +1,{max(1, _line_count(p))} @@\n"
    return parse_unified_diff(text)


def all_files(root: Path) -> dict[str, ChangedFile]:
    """Full-repository mode: every tracked file, every line counts as changed."""
    out: dict[str, ChangedFile] = {}
    for path in _git(root, "ls-files").splitlines():
        p = root / path
        if p.is_file():
            out[path] = ChangedFile(path, set(range(1, _line_count(p) + 1)))
    return out


def _line_count(p: Path) -> int:
    try:
        with p.open("rb") as fh:
            return sum(1 for _ in fh) or 1
    except OSError:
        return 1
