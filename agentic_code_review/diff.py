"""Work out exactly which files and lines a change touches.

Reviewing only added/modified lines is what lets a team adopt the tool on a legacy
codebase without drowning every PR in old findings.
"""
from __future__ import annotations

import codecs
import re
import subprocess
import sys
from pathlib import Path

from .models import ChangedFile

HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def _git(root: Path, *args: str) -> str:
    # quotepath=off prints non-ASCII names as-is; names with quotes, backslashes or control characters stay C-quoted.
    return subprocess.run(["git", "-C", str(root), "-c", "core.quotepath=off", *args], check=True, capture_output=True,
                          text=True, encoding="utf-8", errors="surrogateescape").stdout


def unquote(name: str) -> str:
    """Undo git's C-style quoting ("a\\tb.py", "na\\303\\257ve.py") so paths match the files on disk."""
    if len(name) >= 2 and name[0] == name[-1] == '"':
        raw = codecs.escape_decode(name[1:-1].encode("utf-8", "surrogateescape"))[0]
        return raw.decode("utf-8", errors="replace")
    return name


def parse_unified_diff(text: str) -> dict[str, ChangedFile]:
    """Parse a unified diff into added line numbers per file.

    Only '+' lines count, so diffs with context lines (plain `git diff`, patches from other tools)
    give the same result as `git diff -U0`.
    """
    files: dict[str, ChangedFile] = {}
    current: ChangedFile | None = None
    new_line, remaining = 0, 0          # position in the new file and lines left in the current hunk
    for raw in text.splitlines():
        if remaining <= 0 and raw.startswith("+++ "):
            target = unquote(raw[4:].strip())
            if target == "/dev/null":
                current = None
                continue
            path = target[2:] if target.startswith("b/") else target
            current = files.setdefault(path, ChangedFile(path))
            continue
        m = HUNK.match(raw)
        if m:
            new_line, remaining = int(m.group(1)), int(m.group(2) or "1")
            continue
        if current is None or remaining <= 0:
            continue
        if raw.startswith("+"):
            current.added_lines.add(new_line)
        elif raw.startswith("-") or raw.startswith("\\"):
            continue                    # removed line or "\ No newline at end of file": not in the new file
        new_line += 1
        remaining -= 1
    return files


def _range_diff(root: Path, base: str, head: str | None, context: str) -> str:
    """base...head (what the PR adds since it branched). Shallow CI clones often lack the merge base; then fall back
    to base..head, which can also show changes made on the base branch, and say so."""
    try:
        return _git(root, "diff", context, "--no-color", "--diff-filter=ACMR", f"{base}...{head or 'HEAD'}")
    except subprocess.CalledProcessError as exc:
        if "merge base" not in (exc.stderr or ""):
            raise
    print(f"acr: no merge base between {base} and {head or 'HEAD'} (shallow clone?); comparing the two commits directly. "
          "Fetch more history (fetch-depth: 0) for an exact PR diff.", file=sys.stderr)
    return _git(root, "diff", context, "--no-color", "--diff-filter=ACMR", base, head or "HEAD")


def changed_files(root: Path, base: str | None, head: str | None, staged: bool = False) -> dict[str, ChangedFile]:
    """Changed files between two refs (merge-base semantics), the staged index, or the working tree vs HEAD."""
    if staged:
        return parse_unified_diff(_git(root, "diff", "--cached", "-U0", "--no-color", "--diff-filter=ACMR"))
    if base:
        return parse_unified_diff(_range_diff(root, base, head, "-U0"))
    files = parse_unified_diff(_git(root, "diff", "-U0", "--no-color", "--diff-filter=ACMR", "HEAD"))
    # Untracked files count as fully added in workspace mode.
    for path in map(unquote, _git(root, "ls-files", "--others", "--exclude-standard").splitlines()):
        p = root / path
        if p.is_file():
            files[path] = ChangedFile(path, set(range(1, _line_count(p) + 1)))
    return files


def staged_text(root: Path, path: str, max_bytes: int) -> str | None:
    """A file's content as it will be committed (the index), which can differ from the working tree."""
    proc = subprocess.run(["git", "-C", str(root), "show", f":{path}"], capture_output=True)
    data = proc.stdout
    if proc.returncode != 0 or len(data) > max_bytes or b"\x00" in data[:4096]:
        return None
    return data.decode("utf-8", errors="replace")


def all_files(root: Path) -> dict[str, ChangedFile]:
    """Full-repository mode: every tracked file, every line counts as changed."""
    out: dict[str, ChangedFile] = {}
    for path in map(unquote, _git(root, "ls-files").splitlines()):
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


def unified_text(root: Path, base: str | None, head: str | None, staged: bool = False) -> str:
    """The human-readable diff (3 lines of context) that the AI reviewer reads."""
    if staged:
        return _git(root, "diff", "--cached", "-U3", "--no-color", "--diff-filter=ACMR")
    if base:
        return _range_diff(root, base, head, "-U3")
    text = _git(root, "diff", "-U3", "--no-color", "--diff-filter=ACMR", "HEAD")
    for path in map(unquote, _git(root, "ls-files", "--others", "--exclude-standard").splitlines()):
        p = root / path
        try:
            body = p.read_text(errors="replace")
        except OSError:
            continue
        text += f"\n--- /dev/null\n+++ b/{path}\n" + "".join(f"+{line}\n" for line in body.splitlines())
    return text
