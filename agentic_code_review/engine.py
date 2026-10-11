"""The deterministic review pipeline: changed lines -> rules + scanners -> one de-duplicated list.

The AI layer (added separately) takes this list as its starting point. Keeping the
deterministic part first means every finding is reproducible and placed on an exact line.
"""
from __future__ import annotations

import fnmatch
import os
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

from . import diff
from .classify import kinds as classify
from .models import ChangedFile, Finding, Severity
from .rules import base as rules_base
from .scanners import available_scanners

DEFAULT_EXCLUDES = ("node_modules/*", "vendor/*", "dist/*", "build/*", ".venv/*", "venv/*", "*.min.js", "*.lock",
                    "package-lock.json", "*.png", "*.jpg", "*.gif", "*.pdf", "*.zip", "*.svg")
MAX_BYTES = 1_000_000


@dataclass
class ReviewResult:
    findings: list[Finding]
    files: dict[str, ChangedFile]
    file_kinds: dict[str, set[str]]
    scanners_run: list[str] = field(default_factory=list)
    scanners_missing: list[str] = field(default_factory=list)
    ai_provider: str = ""
    ai_summary: str = ""
    ai_error: str = ""
    ai_usage: dict = field(default_factory=dict)
    baselined: int = 0

    def counts(self) -> dict[str, int]:
        out = {s.label(): 0 for s in sorted(Severity, reverse=True)}
        for f in self.findings:
            out[f.severity.label()] += 1
        return out

    def blocking(self, threshold: Severity) -> list[Finding]:
        return [f for f in self.findings if f.severity >= threshold and f.ai_verdict != "false_positive"]


def _excluded(path: str, extra: tuple[str, ...]) -> bool:
    return any(fnmatch.fnmatch(path, pat) or fnmatch.fnmatch(path, f"*/{pat}") for pat in DEFAULT_EXCLUDES + extra)


def _read(root: Path, path: str) -> str | None:
    p = root / path
    try:
        if not p.is_file() or p.stat().st_size > MAX_BYTES:
            return None
        data = p.read_bytes()
    except OSError:
        return None
    if b"\x00" in data[:4096]:
        return None  # binary
    return data.decode("utf-8", errors="replace")


def _suppressed(file_lines: dict[str, list[str]], f: Finding) -> bool:
    lines = file_lines.get(f.path) or []
    return 1 <= f.line <= len(lines) and rules_base.ignored(lines[f.line - 1], f.rule_id)


def dedupe(findings: list[Finding]) -> list[Finding]:
    """Merge the same issue reported by *different* tools on the same line; keep the most severe and credit the others.

    Two different rules from the same tool are different issues and are both kept.
    """
    out: list[Finding] = []
    seen_exact: set[tuple] = set()
    for f in sorted(findings, key=lambda f: -f.severity):
        exact = (f.tool, f.rule_id, f.path, f.line)
        if exact in seen_exact:
            continue
        seen_exact.add(exact)
        twin = next((g for g in out if g.path == f.path and g.line == f.line and g.category == f.category and g.tool != f.tool), None)
        if twin is not None:
            if f.tool not in twin.detail:
                twin.detail = (twin.detail + f" Also reported by {f.tool} ({f.rule_id}).").strip()
            continue
        out.append(f)
    return sorted(out, key=lambda f: (-f.severity, f.path, f.line, f.rule_id))


def review(root: Path, base: str | None = None, head: str | None = None, full: bool = False,
           use_scanners: bool = True, only_scanners: set[str] | None = None, excludes: tuple[str, ...] = (),
           disable: tuple[str, ...] = (), severity_overrides: dict[str, Severity] | None = None,
           staged: bool = False) -> ReviewResult:
    root = root.resolve()
    files = diff.all_files(root) if full else diff.changed_files(root, base, head, staged=staged)
    files = {p: cf for p, cf in files.items() if not _excluded(p, excludes)}

    findings: list[Finding] = []
    file_kinds: dict[str, set[str]] = {}
    file_lines: dict[str, list[str]] = {}
    for path in sorted(files):
        # In staged mode rules read what will be committed, not unstaged edits in the working tree.
        text = diff.staged_text(root, path, MAX_BYTES) if staged else _read(root, path)
        if text is None:
            continue
        k = classify(path, text)
        file_kinds[path] = k
        file_lines[path] = text.splitlines()
        findings.extend(rules_base.run_rules(path, text, k))

    ran, missing = [], []
    if use_scanners:
        wanted = only_scanners
        from .scanners.tools import ALL_SCANNERS
        installed = {s.name for s in available_scanners(wanted)}
        missing = [s.name for s in ALL_SCANNERS if (wanted is None or s.name in wanted) and s.name not in installed]
        all_kinds = set().union(*file_kinds.values()) if file_kinds else set()
        jobs = []
        for scanner in available_scanners(wanted):
            targets = [p for p, k in file_kinds.items() if "*" in scanner.kinds or scanner.kinds & k]
            if targets and ("*" in scanner.kinds or scanner.kinds & all_kinds):
                jobs.append((scanner, targets))
        # Scanners are separate processes, so threads run them concurrently; results keep a stable order.
        workers = max(1, min(len(jobs), int(os.environ.get("ACR_SCANNER_WORKERS", "4"))))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [(scanner, pool.submit(scanner.run, root, targets)) for scanner, targets in jobs]
            for scanner, fut in futures:
                # Built-in rules already honour `acr:ignore`; scanner findings get the same treatment here.
                findings.extend(f for f in fut.result() if not _suppressed(file_lines, f))
                ran.append(scanner.name)

    # Repository policy: drop disabled rules (ids or globs) and apply per-rule severity overrides.
    if disable:
        findings = [f for f in findings if not any(fnmatch.fnmatch(f.rule_id, pat) for pat in disable)]
    for f in findings:
        if severity_overrides and f.rule_id in severity_overrides:
            f.severity = severity_overrides[f.rule_id]

    # Keep only findings on lines this change touches (every line counts in full mode).
    kept = [f for f in findings if f.path in files and files[f.path].touches(f.line, f.end_line)]
    return ReviewResult(findings=dedupe(kept), files=files, file_kinds=file_kinds, scanners_run=ran, scanners_missing=missing)
