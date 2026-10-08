"""Rules for MCP server configs and agent skill files: the new AI supply chain.

Malicious or careless skills and MCP servers run with the developer's own permissions,
so they get the same scrutiny as a third-party dependency.
"""
from __future__ import annotations

import json
import re

from ..models import Severity
from .base import IGNORE_MARKER, find_line, line_matches, make, rule

MCP = ["mcp-config"]
SKILL = ["agent-skill"]
MCP_SEC = "https://modelcontextprotocol.io/specification/draft/basic/security_best_practices"
CRED_NAME = re.compile(r"(?i)(token|secret|password|passwd|api[_-]?key|access[_-]?key|private[_-]?key)")
PLACEHOLDER = re.compile(r"(?i)^\$\{|^\$[A-Z_]|<[^>]+>|example|changeme|your[_-]|x{4,}|^env:")


def _servers(text: str) -> dict:
    try:
        data = json.loads(text)
    except ValueError:
        return {}
    if not isinstance(data, dict):
        return {}
    servers = data.get("mcpServers") or data.get("servers") or (data.get("mcp") or {}).get("servers") or {}
    return servers if isinstance(servers, dict) else {}


@rule("ACR-MCP-001", "MCP server installed from an unpinned package", Severity.HIGH, "ai-security", MCP,
      fix="Pin the exact version (npx pkg@1.2.3, uvx pkg==1.2.3) or a container digest, so a hijacked release can't run on every launch.",
      references=[MCP_SEC])
def mcp_unpinned(path, text, lines):
    info = mcp_unpinned.info
    for name, cfg in _servers(text).items():
        if not isinstance(cfg, dict):
            continue
        cmd = str(cfg.get("command", ""))
        args = [str(a) for a in (cfg.get("args") or [])]
        pkgs = [a for a in args if not a.startswith("-")]
        if cmd.endswith(("npx", "bunx", "pnpx")) and pkgs and not re.search(r".@\d", pkgs[0]):
            yield make(info, path, find_line(lines, f'"{name}"'), f"Server '{name}' runs '{pkgs[0]}' at whatever version is latest.")
        if cmd.endswith(("uvx", "pipx")) and pkgs and "==" not in " ".join(args):
            yield make(info, path, find_line(lines, f'"{name}"'), f"Server '{name}' runs '{pkgs[0]}' unpinned.")
        if cmd == "docker" and any(re.match(r"^[\w./-]+(:latest)?$", a) and "/" in a for a in pkgs) and not any("@sha256:" in a for a in args):
            yield make(info, path, find_line(lines, f'"{name}"'), f"Server '{name}' runs a container image without a digest.")


@rule("ACR-MCP-002", "Credential stored in plain text in an MCP config", Severity.CRITICAL, "secrets", MCP,
      fix="Reference the secret from the environment (\"${GITHUB_TOKEN}\") or the OS keychain; never commit it in the config.")
def mcp_secret(path, text, lines):
    info = mcp_secret.info
    for name, cfg in _servers(text).items():
        if not isinstance(cfg, dict):
            continue
        for key, value in ((cfg.get("env") or {}) | (cfg.get("headers") or {})).items():
            v = str(value)
            if CRED_NAME.search(key) and len(v) >= 8 and not PLACEHOLDER.search(v):
                yield make(info, path, find_line(lines, f'"{key}"'), f"'{key}' for server '{name}' is a literal value (not shown).")


@rule("ACR-MCP-003", "MCP server over plain HTTP or with broad host access", Severity.HIGH, "ai-security", MCP,
      fix="Use HTTPS for remote servers, and scope filesystem/docker servers to a project directory, never / or $HOME.",
      references=[MCP_SEC])
def mcp_exposure(path, text, lines):
    info = mcp_exposure.info
    for name, cfg in _servers(text).items():
        if not isinstance(cfg, dict):
            continue
        url = str(cfg.get("url", ""))
        if url.startswith("http://") and not re.match(r"http://(localhost|127\.0\.0\.1|\[::1\])", url):
            yield make(info, path, find_line(lines, url), f"Server '{name}' talks to {url} without TLS.")
        args = [str(a) for a in (cfg.get("args") or [])]
        broad = [a for a in args if a in ("/", "~", "$HOME", "${HOME}", "/Users", "/home", "C:\\") or a.startswith("/:/")]
        if broad or "--privileged" in args:
            yield make(info, path, find_line(lines, f'"{name}"'),
                       f"Server '{name}' is given {'privileged docker' if '--privileged' in args else broad[0]} access.")


@rule("ACR-SKILL-001", "Agent skill tells the agent to run a remote script", Severity.HIGH, "ai-security", SKILL,
      fix="Skills should never pipe downloads into a shell. Vendor the script, pin it, and review it like code.")
def skill_remote_exec(path, text, lines):
    yield from line_matches(skill_remote_exec.info, path, lines,
                            re.compile(r"\b(curl|wget|iwr|Invoke-WebRequest)\b[^\n|]*\|\s*(ba|z)?sh\b|\biex\s*\(", re.I),
                            skip_comments=False)


@rule("ACR-SKILL-002", "Agent skill reads credentials or sends data out", Severity.CRITICAL, "ai-security", SKILL,
      fix="Remove the instruction. A skill has no reason to read SSH keys, cloud credentials or .env files, or to post them anywhere.")
def skill_exfil(path, text, lines):
    pat = re.compile(r"~/\.(ssh|aws|kube|docker|config/gcloud|gnupg)|\bid_(rsa|ed25519)\b|\.aws/credentials|\.env\b[^\n]*(send|post|upload|curl)"
                     r"|(curl|wget|fetch)\b[^\n]*(-d|--data|--upload-file|POST)[^\n]*(\$\(|`|env|secret|token|key)", re.I)
    yield from line_matches(skill_exfil.info, path, lines, pat, skip_comments=False)


@rule("ACR-SKILL-003", "Agent skill contains hidden or override instructions", Severity.HIGH, "ai-security", SKILL,
      fix="Remove hidden text and override phrases; skill instructions should be plain, visible and reviewable.")
def skill_hidden(path, text, lines):
    info = skill_hidden.info
    hidden = re.compile(r"[\u200b-\u200f\u2060\u202a-\u202e\ufeff]")
    override = re.compile(r"(?i)ignore (all |any )?(previous|prior|above) instructions|do not (tell|inform) the user|"
                          r"disable (safety|guardrails|security)|without asking (the user|for (permission|approval))")
    blob = re.compile(r"[A-Za-z0-9+/]{120,}={0,2}")
    for i, line in enumerate(lines, start=1):
        if IGNORE_MARKER in line:
            continue
        if hidden.search(line):
            yield make(info, path, i, "Invisible Unicode characters can hide instructions from human reviewers.")
        elif override.search(line):
            yield make(info, path, i, "Override phrasing is a classic prompt-injection pattern.")
        elif blob.search(line):
            yield make(info, path, i, "Long encoded blob: decode and review what it contains.", severity=Severity.MEDIUM)
