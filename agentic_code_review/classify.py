"""Decide what kind of file each changed path is, so the right rules run on it."""
from __future__ import annotations

import fnmatch
from pathlib import Path

APP_EXT = {".py": "python", ".js": "javascript", ".jsx": "javascript", ".ts": "typescript", ".tsx": "typescript",
           ".go": "go", ".java": "java", ".rb": "ruby", ".php": "php", ".cs": "csharp", ".rs": "rust", ".kt": "kotlin"}

AI_IMPORT_HINTS = ("openai", "anthropic", "langchain", "llama_index", "llamaindex", "transformers", "vllm", "litellm",
                   "ollama", "mcp", "@modelcontextprotocol", "crewai", "autogen", "semantic_kernel", "google.genai",
                   "@ai-sdk", "ai/", "langgraph", "smolagents", "pydantic_ai")


def kinds(path: str, text: str) -> set[str]:
    """Return every kind that applies; a file can be both app code and AI code."""
    p = Path(path)
    name, lower = p.name, path.lower()
    out: set[str] = set()
    if name == "Dockerfile" or name.startswith("Dockerfile.") or name.endswith(".dockerfile") or name == "Containerfile":
        out.add("dockerfile")
    if lower.startswith(".github/workflows/") and p.suffix in (".yml", ".yaml"):
        out.add("github-actions")
    if p.suffix == ".tf":
        out.add("terraform")
    if p.suffix in (".yml", ".yaml") and "github-actions" not in out:
        if "/templates/" in lower and _in_helm_chart(path):
            out.add("helm-template")
        elif "apiVersion:" in text and "kind:" in text:
            out.add("kubernetes")
    if name in ("mcp.json", ".mcp.json", "claude_desktop_config.json") or fnmatch.fnmatch(lower, "*mcp*.json"):
        out.add("mcp-config")
    if lower.endswith("skill.md") or "/skills/" in lower and p.suffix == ".md":
        out.add("agent-skill")
    lang = APP_EXT.get(p.suffix)
    if lang:
        out.add("app")
        out.add(f"lang:{lang}")
        if any(h in text for h in AI_IMPORT_HINTS):
            out.add("ai-code")
    return out


def _in_helm_chart(path: str) -> bool:
    parts = Path(path).parts
    return "templates" in parts
