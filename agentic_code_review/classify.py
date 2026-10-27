"""Decide what kind of file each changed path is, so the right rules run on it."""
from __future__ import annotations

import fnmatch
import re
from pathlib import Path

APP_EXT = {".py": "python", ".js": "javascript", ".jsx": "javascript", ".ts": "typescript", ".tsx": "typescript",
           ".go": "go", ".java": "java", ".rb": "ruby", ".php": "php", ".cs": "csharp", ".rs": "rust", ".kt": "kotlin"}

AI_IMPORT_HINTS = ("openai", "anthropic", "langchain", "llama_index", "llamaindex", "transformers", "vllm", "litellm",
                   "ollama", "mcp", "@modelcontextprotocol", "crewai", "autogen", "semantic_kernel", "google.genai",
                   "@ai-sdk", "ai/", "langgraph", "smolagents", "pydantic_ai", "claude_agent_sdk", "@anthropic-ai/", "@google/genai", "@langchain/")


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
    if COMPOSE.fullmatch(name.lower()):
        out.add("compose")
    if p.suffix in (".yml", ".yaml") and "github-actions" not in out and "compose" not in out:
        if "/templates/" in lower and _in_helm_chart(path):
            out.add("helm-template")
        elif "apiVersion:" in text and "kind:" in text:
            out.add("kubernetes")
    if _is_shell(p, text):
        out.add("shell")
    if _is_lockfile(p):
        out.add("lockfile")
    if name in ("mcp.json", ".mcp.json", "claude_desktop_config.json") or fnmatch.fnmatch(lower, "*mcp*.json"):
        out.add("mcp-config")
    if _is_agent_settings(lower):
        out.add("agent-settings")
    if _is_agent_plugin(lower):
        out.add("agent-plugin")
    if _is_agent_instructions(lower):
        out.add("agent-instructions")
    if lower.endswith("skill.md") or "/skills/" in lower and p.suffix == ".md":
        out.add("agent-skill")
    lang = APP_EXT.get(p.suffix)
    if lang:
        out.add("app")
        out.add(f"lang:{lang}")
        if _imports_ai(text):
            out.add("ai-code")
    return out


_MODULE_REFS = (
    re.compile(r"^\s*from\s+([\w.]+)\s+import\b", re.M),             # python: from x import y
    re.compile(r"^\s*import\s+([\w.]+(?:\s*,\s*[\w.]+)*)\s*$", re.M),  # python: import x, y
    re.compile(r"""\bfrom\s+['"]([^'"]+)['"]"""),                   # js/ts: import ... from "x"
    re.compile(r"""\brequire\(\s*['"]([^'"]+)['"]"""),              # js: require("x")
    re.compile(r"""^\s*import\s+['"]([^'"]+)['"]""", re.M),          # js: import "x"
)


def _module_refs(text: str) -> set[str]:
    refs: set[str] = set()
    for pat in _MODULE_REFS:
        for m in pat.finditer(text):
            refs.update(part.strip().lower() for part in m.group(1).split(","))
    return refs


def _matches_hint(module: str, hint: str) -> bool:
    if hint.endswith("/"):
        return module.startswith(hint) or module.startswith("@" + hint)
    return module == hint or module.startswith(hint + ".") or module.startswith(hint + "/")


def _imports_ai(text: str) -> bool:
    """True only when an LLM/agent library is actually imported (a mention in a string or comment is not enough)."""
    return any(_matches_hint(m, h) for m in _module_refs(text) for h in AI_IMPORT_HINTS)


COMPOSE = re.compile(r"(docker-)?compose(\.[\w.-]+)?\.ya?ml")  # compose.yaml, docker-compose.prod.yml, ...
# Files that pin exact dependency versions: what a CVE or a compromised release is checked against.
LOCKFILES = {"uv.lock", "poetry.lock", "pipfile.lock", "pdm.lock", "package-lock.json", "npm-shrinkwrap.json"}
PIP_PINS = re.compile(r"(requirements|constraints)([-_.][\w.-]+)?\.(txt|in)")


def _is_lockfile(p: Path) -> bool:
    name = p.name.lower()
    return name in LOCKFILES or bool(PIP_PINS.fullmatch(name)) or (p.parent.name == "requirements" and p.suffix == ".txt")
SHEBANG = re.compile(r"^#!\s*(/usr/bin/env\s+)?(/bin/|/usr/bin/|/usr/local/bin/)?(ba|z|da|k)?sh\b")


def _is_shell(p: Path, text: str) -> bool:
    """Shell scripts by extension or shebang, plus Makefiles, whose recipes are shell commands."""
    if p.suffix in (".sh", ".bash", ".zsh") or p.name in ("Makefile", "GNUmakefile") or p.suffix == ".mk":
        return True
    return not p.suffix and bool(SHEBANG.match(text[:100]))


# Coding-agent permission files that are commonly committed so a whole team shares them.
AGENT_SETTINGS = ("*.claude/settings.json", "*.claude/settings.local.json", "*.codex/config.toml")


def _is_agent_settings(lower: str) -> bool:
    return any(fnmatch.fnmatch("/" + lower, "*/" + pat.lstrip("*")) for pat in AGENT_SETTINGS)


# Coding-agent plugins and the marketplaces that index them (Claude Code, Grok Build). A marketplace entry names
# where a plugin's code is fetched from; a plugin's hooks run on the developer's machine.
AGENT_PLUGIN = (".claude-plugin/marketplace.json", ".grok-plugin/marketplace.json", ".claude-plugin/plugin.json",
                ".grok-plugin/plugin.json", "hooks/hooks.json")


def _is_agent_plugin(lower: str) -> bool:
    return any(fnmatch.fnmatch("/" + lower, "*/" + pat) for pat in AGENT_PLUGIN)


# Instruction files coding agents load automatically; text in them steers the agent like a system prompt.
AGENT_INSTRUCTIONS = (".cursorrules", ".windsurfrules", ".clinerules", "agents.md", "claude.md", "claude.local.md", "gemini.md",
                      ".github/copilot-instructions.md")


def _is_agent_instructions(lower: str) -> bool:
    name = lower.rsplit("/", 1)[-1]
    return (name in AGENT_INSTRUCTIONS or lower.endswith(".github/copilot-instructions.md")
            or fnmatch.fnmatch(lower, "*.cursor/rules/*.mdc") or fnmatch.fnmatch(lower, "*.github/instructions/*.instructions.md")
            or fnmatch.fnmatch(lower, "*.clinerules/*.md"))


def _in_helm_chart(path: str) -> bool:
    parts = Path(path).parts
    return "templates" in parts
