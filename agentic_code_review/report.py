"""Render a ReviewResult as Markdown (PR comment / terminal), JSON, SARIF 2.1.0 (GitHub code scanning),
or GitHub Actions workflow-command annotations."""
from __future__ import annotations

import json

from . import __version__
from .engine import ReviewResult
from .models import Finding, Severity

AREA = {"secrets": "Secrets", "app-security": "App code", "ai-security": "AI/agent", "kubernetes": "Kubernetes",
        "container": "Containers", "ci-cd": "CI/CD", "iac": "Terraform/IaC", "dependency": "Dependencies", "other": "Other"}
ICON = {Severity.CRITICAL: "🔴", Severity.HIGH: "🟠", Severity.MEDIUM: "🟡", Severity.LOW: "🔵", Severity.INFO: "⚪"}
SARIF_LEVEL = {Severity.CRITICAL: "error", Severity.HIGH: "error", Severity.MEDIUM: "warning", Severity.LOW: "note", Severity.INFO: "note"}
# GitHub maps this numeric property onto its critical/high/medium/low security severities.
SECURITY_SEVERITY = {Severity.CRITICAL: "9.5", Severity.HIGH: "8.0", Severity.MEDIUM: "5.5", Severity.LOW: "3.0", Severity.INFO: "0.0"}
TOOL_URI = "https://github.com/sunilmehta-si/agentic-code-review-tool"
ANNOTATION_LEVEL = {Severity.CRITICAL: "error", Severity.HIGH: "error", Severity.MEDIUM: "warning", Severity.LOW: "notice",
                    Severity.INFO: "notice"}


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


def _by_area(findings: list[Finding]) -> list[str]:
    """One line showing where the problems are, most affected area first."""
    if not findings:
        return []
    areas: dict[str, int] = {}
    for f in findings:
        name = AREA.get(f.category, f.category)
        areas[name] = areas.get(name, 0) + 1
    ordered = sorted(areas.items(), key=lambda kv: (-kv[1], kv[0]))
    return ["**By area:** " + " · ".join(f"{name} {n}" for name, n in ordered), ""]


def to_markdown(result: ReviewResult, threshold: Severity = Severity.HIGH) -> str:
    shown = _visible(result)
    counts = {s: sum(1 for f in shown if f.severity == s) for s in sorted(Severity, reverse=True)}
    blocking = [f for f in shown if f.severity >= threshold]
    status = "❌ **Changes requested**" if blocking else "✅ **No blocking issues**"
    lines = [f"## Agentic code review · {status}", "",
             " · ".join(f"{ICON[s]} {counts[s]} {s.label()}" for s in counts if s != Severity.INFO), "",
             *_by_area(shown),
             f"Reviewed **{len(result.file_kinds)}** changed file(s). Scanners run: "
             f"{', '.join(result.scanners_run) or 'built-in rules only'}."]
    if result.ai_summary:
        lines += ["", f"**AI reviewer:** {result.ai_summary}"]
    if result.ai_error:
        lines += ["", f"⚠️ AI review skipped: {result.ai_error} The findings below come from rules and scanners only."]
    dropped = len(result.findings) - len(shown)
    if dropped:
        lines.append(f"The AI reviewer dismissed **{dropped}** finding(s) as false positives.")
    if result.baselined:
        lines.append(f"{result.baselined} known finding(s) suppressed by the baseline.")
    if result.scanners_missing:
        lines.append(f"<sub>Not installed (skipped): {', '.join(result.scanners_missing)}</sub>")
    if result.scanners_failed:
        lines.append("⚠️ Scanner(s) failed, so their checks did not run: "
                     + "; ".join(f"{name} ({why})" for name, why in sorted(result.scanners_failed.items())))
    if result.skipped:
        lines.append(f"<sub>{len(result.skipped)} binary or oversized file(s) were not reviewed.</sub>")
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
                       "scanners_missing": result.scanners_missing,
                       "scanners_failed": result.scanners_failed, "files_reviewed": sorted(result.file_kinds), "files_skipped": result.skipped,
                       "ai": {"provider": result.ai_provider, "summary": result.ai_summary, "error": result.ai_error,
                              "usage": result.ai_usage},
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
            # Lets code scanning follow the same alert across commits even when line numbers shift.
            **({"partialFingerprints": {"acrFingerprint/v1": f.fingerprint}} if f.fingerprint else {}),
            "properties": {"tool": f.tool, "category": f.category, **({"aiVerdict": f.ai_verdict} if f.ai_verdict else {})},
        })
    sarif = {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
             "runs": [{"tool": {"driver": {"name": "agentic-code-review-tool", "version": __version__,
                                           "informationUri": TOOL_URI, "rules": list(rules.values())}},
                       "results": results}]}
    return json.dumps(sarif, indent=2)


def _escape(value: str, prop: bool = False) -> str:
    """Workflow-command escaping: newlines and % always; ':' and ',' too inside properties."""
    out = value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    return out.replace(":", "%3A").replace(",", "%2C") if prop else out


def to_github(result: ReviewResult) -> str:
    """One `::error`/`::warning`/`::notice` line per finding. GitHub shows them on the PR's changed files,
    and they need no token, so they also work for pull requests from forks."""
    lines = []
    for f in _visible(result):
        props = f"file={_escape(f.path, True)},line={max(1, f.line)}"
        if f.end_line and f.end_line > f.line:
            props += f",endLine={f.end_line}"
        props += f",title={_escape(f'{f.rule_id} {f.title}', True)}"
        message = " ".join(x for x in (f.ai_explanation or f.detail, f"Fix: {f.ai_fix or f.fix}" if (f.ai_fix or f.fix) else "") if x)
        lines.append(f"::{ANNOTATION_LEVEL[f.severity]} {props}::{_escape(message or f.title)}")
    return "\n".join(lines)
