"""Run the AI layer over a deterministic ReviewResult and merge its verdicts back in."""
from __future__ import annotations

from pathlib import Path

from .. import diff as diff_mod
from ..engine import ReviewResult
from ..models import Finding, Severity
from .review import AgentError, build_user_message
from .tools import RepoTools

PROVIDERS = ("claude", "openai")


def make_reviewer(provider: str, model: str | None = None, max_steps: int = 12):
    if provider == "claude":
        from .claude import ClaudeReviewer
        return ClaudeReviewer(model=model, max_steps=max_steps)
    if provider == "openai":
        from .openai_compat import OpenAICompatReviewer
        return OpenAICompatReviewer(model=model, max_steps=max_steps)
    raise AgentError(f"Unknown AI provider '{provider}'. Choose one of: {', '.join(PROVIDERS)}.")


def apply_ai(result: ReviewResult, root: Path, reviewer, base: str | None = None, head: str | None = None,
             full: bool = False, staged: bool = False) -> ReviewResult:
    """Ask the agent to verify every finding; on any failure keep the deterministic result and record why."""
    result.ai_provider = type(reviewer).__name__
    payload = [{"id": i, "rule": f.rule_id, "title": f.title, "severity": f.severity.label(), "path": f.path,
                "line": f.line, "detail": f.detail} for i, f in enumerate(result.findings)]
    try:
        diff_text = "(full-repository audit: no diff; use the tools to inspect files)" if full else \
            diff_mod.unified_text(root, base, head, staged=staged)
        data = reviewer.review(build_user_message(payload, diff_text), RepoTools(root, result.file_kinds))
    except AgentError as exc:
        result.ai_error = str(exc)
        return result

    for v in data.get("verdicts", []):
        try:
            f = result.findings[int(v.get("id"))]
        except (TypeError, ValueError, IndexError):
            continue
        if v.get("verdict") in ("confirmed", "false_positive", "uncertain"):
            f.ai_verdict = v["verdict"]
        f.ai_explanation = str(v.get("explanation") or "")[:1500]
        f.ai_fix = str(v.get("fix") or "")[:3000]

    for n in data.get("new_findings", [])[:5]:
        path, line = str(n.get("path", "")), int(n.get("line") or 0)
        changed = result.files.get(path)
        if not changed or not changed.touches(line):
            continue  # the agent may only add findings on lines this PR changes
        result.findings.append(Finding(rule_id="ACR-AGENT", title=str(n.get("title", "Issue found by the AI reviewer"))[:200],
                                       severity=Severity.parse(n.get("severity"), Severity.MEDIUM), path=path, line=line,
                                       tool="agent", category=str(n.get("category") or "other"), ai_verdict="confirmed",
                                       ai_explanation=str(n.get("explanation") or "")[:1500], ai_fix=str(n.get("fix") or "")[:3000]))
    result.findings.sort(key=lambda f: (-f.severity, f.path, f.line, f.rule_id))
    result.ai_summary = str(data.get("summary") or "")[:2000]
    result.ai_usage = dict(getattr(reviewer, "usage", {}) or {})
    return result
