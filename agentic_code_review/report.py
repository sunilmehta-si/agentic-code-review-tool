"""Render a ReviewResult as Markdown (PR comment / terminal), JSON, or SARIF 2.1.0 (GitHub code scanning)."""
from __future__ import annotations

import json

from . import __version__
from .engine import ReviewResult
from .models import Finding, Severity

ICON = {Severity.CRITICAL: "🔴", Severity.HIGH: "🟠", Severity.MEDIUM: "🟡", Severity.LOW: "🔵", Severity.INFO: "⚪"}
SARIF_LEVEL = {Severity.CRITICAL: "error", Severity.HIGH: "error", Severity.MEDIUM: "warning", Severity.LOW: "note", Severity.INFO: "note"}
# GitHub maps this numeric property onto its critical/high/medium/low security severities.
SECURITY_SEVERITY = {Severity.CRITICAL: "9.5", Severity.HIGH: "8.0", Severity.MEDIUM: "5.5", Severity.LOW: "3.0", Severity.INFO: "0.0"}
TOOL_URI = "https://github.com/sunilmehta-si/agentic-code-review-tool"


def _visible(result: ReviewResult) -> list[Finding]:
    return [f for f in result.findings if f.ai_verdict != "false_positive"]


def comment_body(f: Finding) -> str:
    """Body used for inline PR comments and the Markdown table."""
    parts = [f"{ICON[f.severity]} **{f.title}** · `{f.rule_id}` · {f.severity.label()}"]
    if f.ai_explanation:
        parts.append(f.ai_explanation)
    elif f.detail:
        parts.append(f.detail)
    fix = f.ai_fix or f.fix
    if fix:
        parts.append(f"**Fix:** {fix}")
    if f.ai_verdict == "uncertain":
        parts.append("_The AI reviewer could not confirm this from the surrounding code; please double-check._")
    return "\n\n".join(parts)


def to_markdown(result: ReviewResult, threshold: Severity = Severity.HIGH) -> str:
    shown = _visible(result)
    counts = {s: sum(1 for f in shown if f.severity == s) for s in sorted(Severity, reverse=True)}
    blocking = [f for f in shown if f.severity >= threshold]
    status = "❌ **Changes requested**" if blocking else "✅ **No blocking issues**"
    lines = [f"## Agentic code review · {status}", "",
             " · ".join(f"{ICON[s]} {counts[s]} {s.label()}" for s in counts if s != Severity.INFO), "",
             f"Reviewed **{len(result.file_kinds)}** changed file(s). Scanners run: "
             f"{', '.join(result.scanners_run) or 'built-in rules only'}."]
    dropped = len(result.findings) - len(shown)
    if dropped:
        lines.append(f"The AI reviewer dismissed **{dropped}** finding(s) as false positives.")
    if result.scanners_missing:
        lines.append(f"<sub>Not installed (skipped): {', '.join(result.scanners_missing)}</sub>")
    if shown:
        lines += ["", "| | Severity | Location | Issue | Rule |", "|---|---|---|---|---|"]
        for f in shown:
            title = f.title.replace("|", "\\|")
            lines.append(f"| {ICON[f.severity]} | {f.severity.label()} | `{f.path}:{f.line}` | {title} | `{f.rule_id}` |")
        if blocking:
            lines += ["", "<details><summary>How to fix the blocking issues</summary>", ""]
            for f in blocking:
                lines += [f"#### `{f.path}:{f.line}`", comment_body(f), ""]
            lines.append("</details>")
    lines += ["", f"<sub>agentic-code-review-tool v{__version__} · only changed lines are reviewed</sub>"]
    return "\n".join(lines)


def to_json(result: ReviewResult) -> str:
    return json.dumps({"version": __version__, "counts": result.counts(), "scanners_run": result.scanners_run,
                       "scanners_missing": result.scanners_missing, "files_reviewed": sorted(result.file_kinds),
                       "findings": [f.to_dict() for f in result.findings]}, indent=2)


def to_sarif(result: ReviewResult) -> str:
    rules: dict[str, dict] = {}
    results = []
    for f in _visible(result):
        if f.rule_id not in rules:
            rules[f.rule_id] = {
                "id": f.rule_id, "name": f.rule_id.replace(":", "_").replace("-", "_"),
                "shortDescription": {"text": f.title[:200]},
                "help": {"text": f.fix or f.title, "markdown": f.fix or f.title},
                "properties": {"tags": ["security", f.category], "security-severity": SECURITY_SEVERITY[f.severity]},
            }
            if f.references:
                rules[f.rule_id]["helpUri"] = f.references[0]
        region = {"startLine": max(1, f.line)}
        if f.end_line and f.end_line >= f.line:
            region["endLine"] = f.end_line
        results.append({
            "ruleId": f.rule_id, "level": SARIF_LEVEL[f.severity],
            "message": {"text": " ".join(x for x in (f.title, f.ai_explanation or f.detail) if x)[:1000]},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.path}, "region": region}}],
            "properties": {"tool": f.tool, "category": f.category, **({"aiVerdict": f.ai_verdict} if f.ai_verdict else {})},
        })
    sarif = {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
             "runs": [{"tool": {"driver": {"name": "agentic-code-review-tool", "version": __version__,
                                           "informationUri": TOOL_URI, "rules": list(rules.values())}},
                       "results": results}]}
    return json.dumps(sarif, indent=2)
