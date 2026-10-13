"""Render a ReviewResult as Markdown (PR comment / terminal), JSON, SARIF 2.1.0 (GitHub code scanning),
or GitHub Actions workflow-command annotations."""
from __future__ import annotations

import json
import os
from urllib.parse import quote

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
TABLE_ROWS = 25
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


def _blob_base() -> str | None:
    """https://github.com/<repo>/blob/<sha> inside GitHub Actions (the PR head when known), else None."""
    server, repo = os.environ.get("GITHUB_SERVER_URL"), os.environ.get("GITHUB_REPOSITORY")
    sha = os.environ.get("GITHUB_SHA")
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    if event_path and os.path.exists(event_path):
        try:
            with open(event_path, encoding="utf-8") as fh:
                sha = ((json.load(fh).get("pull_request") or {}).get("head") or {}).get("sha") or sha
        except (OSError, ValueError):
            pass
    return f"{server}/{repo}/blob/{sha}" if server and repo and sha else None


def _location(f: Finding, base: str | None) -> str:
    text = f"`{f.path}:{f.line}`"
    return f"[{text}]({base}/{quote(f.path)}#L{f.line})" if base else text


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
    if result.ai_unverified:
        lines.append(f"{result.ai_unverified} lower-severity finding(s) were not sent to the AI reviewer (--ai-max-findings).")
    dropped = len(result.findings) - len(shown)
    if dropped:
        lines.append(f"The AI reviewer dismissed **{dropped}** finding(s) as false positives.")
    if result.below_floor:
        lines.append(f"{result.below_floor} finding(s) below the minimum severity are not shown.")
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
        base = _blob_base()
        header = ["| | Severity | Location | Issue | Rule |", "|---|---|---|---|---|"]
        rows = []
        for f in shown:
            title = f.title.replace("|", "\\|")
            rows.append(f"| {ICON[f.severity]} | {f.severity.label()} | {_location(f, base)} | {title} | `{f.rule_id}` |")
        # Findings are sorted most severe first, so the visible rows are the ones that matter.
        lines += ["", *header, *rows[:TABLE_ROWS]]
        if len(rows) > TABLE_ROWS:
            lines += ["", f"<details><summary>{len(rows) - TABLE_ROWS} more finding(s)</summary>", "", *header,
                      *rows[TABLE_ROWS:], "", "</details>"]
        if blocking:
            lines += ["", "<details><summary>How to fix the blocking issues</summary>", ""]
            for f in blocking:
                lines += [f"#### `{f.path}:{f.line}`", comment_body(f), ""]
            lines.append("</details>")
    lines += ["", f"<sub>agentic-code-review-tool v{__version__} · only changed lines are reviewed</sub>"]
    return "\n".join(lines)


JSON_SCHEMA_VERSION = 1


def to_json(result: ReviewResult, threshold: Severity | None = None) -> str:
    """threshold None means the gate is off (--fail-on never)."""
    blocking = len(result.blocking(threshold)) if threshold is not None else 0
    gate = {"fail_on": threshold.label() if threshold is not None else "never", "blocking": blocking, "passed": blocking == 0}
    return json.dumps({"schema_version": JSON_SCHEMA_VERSION, "version": __version__, "gate": gate, "counts": result.counts(), "scanners_run": result.scanners_run,
                       "scanners_missing": result.scanners_missing,
                       "scanners_failed": result.scanners_failed, "files_reviewed": sorted(result.file_kinds), "files_skipped": result.skipped,
                       "timings_ms": {k: round(v * 1000) for k, v in result.timings.items()},
                       "ai": {"provider": result.ai_provider, "summary": result.ai_summary, "error": result.ai_error,
                              "usage": result.ai_usage},
                       "findings": [f.to_dict() for f in result.findings]}, indent=2)


def _builtin(rule_id: str):
    from .rules import base
    return next((info for info, _ in base.REGISTRY if info.rule_id == rule_id), None)


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
            info = _builtin(f.rule_id)
            if info is not None:  # built-in rules carry their own documentation into the code scanning UI
                refs = "".join(f"\n- {r}" for r in info.references)
                rules[f.rule_id].update({
                    "fullDescription": {"text": info.title},
                    "help": {"text": f"{info.fix}\n\nRun `acr explain {info.rule_id}` for details.",
                             "markdown": f"**How to fix:** {info.fix}" + (f"\n\n**References:**{refs}" if refs else "")},
                    "helpUri": info.references[0] if info.references else f"{TOOL_URI}#built-in-rules",
                })
                rules[f.rule_id]["properties"].update({"precision": "high", "tags": ["security", info.category, "acr"]})
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
    notes = [{"level": "error", "message": {"text": f"Scanner {name} failed: {why}"}}
             for name, why in sorted(result.scanners_failed.items())]
    notes += [{"level": "note", "message": {"text": f"Scanner {name} is not installed and was skipped."}}
              for name in result.scanners_missing]
    if result.ai_error:
        notes.append({"level": "warning", "message": {"text": f"AI review skipped: {result.ai_error}"}})
    invocation = {"executionSuccessful": not result.scanners_failed, "toolExecutionNotifications": notes}
    sarif = {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
             "runs": [{"tool": {"driver": {"name": "agentic-code-review-tool", "version": __version__,
                                           "informationUri": TOOL_URI, "rules": list(rules.values())}},
                       "invocations": [invocation], "results": results}]}
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


# GitLab orders severities blocker > critical > major > minor > info.
GITLAB_SEVERITY = {Severity.CRITICAL: "blocker", Severity.HIGH: "critical", Severity.MEDIUM: "major", Severity.LOW: "minor",
                   Severity.INFO: "info"}


def to_gitlab(result: ReviewResult) -> str:
    """GitLab Code Quality report (artifacts:reports:codequality); GitLab shows it on merge request diffs."""
    import hashlib
    issues = []
    for f in _visible(result):
        fp = f.fingerprint or hashlib.sha256(f"{f.rule_id}|{f.path}|{f.line}".encode()).hexdigest()[:24]
        issues.append({"description": f"{f.title} ({f.rule_id})", "check_name": f.rule_id, "fingerprint": fp,
                       "severity": GITLAB_SEVERITY[f.severity], "categories": ["Security"],
                       "content": {"body": comment_body(f)},
                       "location": {"path": f.path, "lines": {"begin": max(1, f.line)}}})
    return json.dumps(issues, indent=2)


def to_junit(result: ReviewResult, threshold: Severity | None = Severity.HIGH) -> str:
    """JUnit XML for CI systems that display test reports (Jenkins, Azure DevOps, CircleCI, GitLab).

    Each finding is a test case; only findings at or above the gate threshold are failures, so the
    test report and the exit code always agree. threshold None means the gate is off.
    """
    import xml.etree.ElementTree as ET
    shown = _visible(result)
    failing = [f for f in shown if threshold is not None and f.severity >= threshold]
    suite = ET.Element("testsuite", name="agentic-code-review", tests=str(max(1, len(shown))), failures=str(len(failing)),
                       errors=str(len(result.scanners_failed)), skipped="0")
    if not shown:
        ET.SubElement(suite, "testcase", classname="acr", name="No findings on the changed lines")
    for f in shown:
        case = ET.SubElement(suite, "testcase", classname=f.path, name=f"{f.rule_id} line {f.line}: {f.title}")
        text = comment_body(f)
        if f in failing:
            ET.SubElement(case, "failure", message=f.title, type=f.severity.label()).text = text
        else:
            ET.SubElement(case, "system-out").text = f"[{f.severity.label()}, below the gate] {text}"
    for name, why in sorted(result.scanners_failed.items()):
        case = ET.SubElement(suite, "testcase", classname="scanners", name=name)
        ET.SubElement(case, "error", message=why, type="ScannerError")
    root = ET.Element("testsuites", name="acr")
    root.append(suite)
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(root, encoding="unicode")
