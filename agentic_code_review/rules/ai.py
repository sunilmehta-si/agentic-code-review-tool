"""Rules for code that builds on LLMs and agents, mapped to the OWASP Top 10 for LLM Applications (2025).

Ordinary SAST does not understand prompts, model loading or agent tools; these rules do.
They only run on files that import an LLM/agent library (see classify.AI_IMPORT_HINTS).
"""
from __future__ import annotations

import re

from ..models import Severity
from .base import line_matches, make, rule

AI = ["ai-code"]
OWASP_LLM = "https://genai.owasp.org/llm-top-10/"


@rule("ACR-AI-001", "User input concatenated into a system prompt (LLM01 Prompt Injection)", Severity.HIGH, "ai-security", AI,
      fix="Keep the system prompt static. Put untrusted input in the user turn, clearly delimited, and treat it as data.",
      references=[OWASP_LLM])
def prompt_injection(path, text, lines):
    pat = re.compile(
        r"""(["']role["']\s*:\s*["']system["']\s*,\s*["']content["']\s*:\s*f["'][^"']*\{"""
        r"""|\bsystem(_prompt|_message)?\s*=\s*f["'][^"']*\{"""
        r"""|SystemMessage\(\s*(content\s*=\s*)?f["'][^"']*\{"""
        r"""|\bsystem\s*:\s*`[^`]*\$\{)""")
    yield from line_matches(prompt_injection.info, path, lines, pat)


@rule("ACR-AI-002", "LLM output used as code, shell, SQL or HTML (LLM05 Improper Output Handling)", Severity.CRITICAL,
      "ai-security", AI,
      fix="Treat model output as untrusted input: validate against a schema or allow-list, never pass it to eval, a shell, SQL or raw HTML.",
      references=[OWASP_LLM])
def output_handling(path, text, lines):
    llm_var = r"(\b(completion|response|resp|output|llm_\w+|answer|generated\w*|reply)\b|choices\[|message\.content|\.content\b)"
    pat = re.compile(rf"(?<![\w.])(eval|exec)\([^)]*{llm_var}|(os\.system|subprocess\.\w+|\.execute|innerHTML\s*=|dangerouslySetInnerHTML)[^\n]*{llm_var}")
    yield from line_matches(output_handling.info, path, lines, pat)


@rule("ACR-AI-003", "Agent given dangerous tools without guardrails (LLM06 Excessive Agency)", Severity.HIGH, "ai-security", AI,
      fix="Give agents the narrowest tools possible, run them in a sandbox, and require human approval for writes, shell and network.",
      references=[OWASP_LLM])
def excessive_agency(path, text, lines):
    pat = re.compile(r"allow_dangerous_(code|requests|deserialization)\s*=\s*True|\b(ShellTool|PythonREPLTool|BashProcess|PythonAstREPLTool|TerminalTool)\(|dangerouslyAllowCommands|auto_approve\s*=\s*True|human_in_the_loop\s*=\s*False")
    yield from line_matches(excessive_agency.info, path, lines, pat)
    # load_tools(["terminal", "python_repl", ...]) hands the agent a shell or an interpreter by name.
    by_name = re.compile(r"""load_tools\([^)]*["'](terminal|python_repl|shell|bash|requests_all|requests_post)["']""")
    yield from line_matches(excessive_agency.info, path, lines, by_name)


@rule("ACR-AI-004", "Untrusted model code or weights loaded (LLM03 Supply Chain)", Severity.HIGH, "ai-security", AI,
      fix="Avoid trust_remote_code; load weights with torch.load(..., weights_only=True) or safetensors; pin a model revision.",
      references=[OWASP_LLM, "https://huggingface.co/docs/safetensors"])
def model_supply_chain(path, text, lines):
    info = model_supply_chain.info
    remote = re.compile(r"trust_remote_code\s*=\s*True")
    torch_load = re.compile(r"\btorch\.load\((?![^)]*weights_only\s*=\s*True)")
    yield from line_matches(info, path, lines, remote)
    yield from line_matches(info, path, lines, torch_load)
    unpinned = re.compile(r"\.from_pretrained\((?![^)]*revision\s*=)")
    for i, line in enumerate(lines, start=1):
        if unpinned.search(line) and ")" in line:
            yield make(info, path, i, "Model is not pinned to a revision, so a changed upstream repo changes your code.",
                       severity=Severity.LOW)


@rule("ACR-AI-005", "LLM call without an output-token limit (LLM10 Unbounded Consumption)", Severity.MEDIUM, "ai-security", AI,
      fix="Set max_tokens (or max_output_tokens), a request timeout, and a step limit on agent loops.",
      references=[OWASP_LLM])
def unbounded(path, text, lines):
    info = unbounded.info
    call = re.compile(r"\.(chat\.completions|completions|messages|responses)\.(create|stream)\(|\bgenerate_content\(")
    limit = re.compile(r"max_(output_|completion_)?tokens|max_new_tokens|maxTokens|maxOutputTokens")
    for i, line in enumerate(lines, start=1):
        if not call.search(line):
            continue
        # Look at the call's argument list (until parentheses balance, max 40 lines).
        depth, window = 0, []
        for j in range(i - 1, min(len(lines), i + 39)):
            window.append(lines[j])
            depth += lines[j].count("(") - lines[j].count(")")
            if depth <= 0 and j >= i - 1:
                break
        args = "\n".join(window)
        # A call that forwards **kwargs may carry the limit inside them; don't guess.
        if not limit.search(args) and "**" not in args:
            yield make(info, path, i)


@rule("ACR-AI-006", "Provider API key exposed to the browser (LLM02 Sensitive Information Disclosure)", Severity.CRITICAL,
      "ai-security", ["lang:javascript", "lang:typescript"],
      fix="Call the model from your server. Never ship provider keys in client bundles or NEXT_PUBLIC_/VITE_ variables.",
      references=[OWASP_LLM])
def key_in_browser(path, text, lines):
    pat = re.compile(r"dangerouslyAllowBrowser\s*:\s*true|\b(NEXT_PUBLIC|VITE|REACT_APP)_(OPENAI|ANTHROPIC|GEMINI|GROQ|MISTRAL)\w*KEY")
    yield from line_matches(key_in_browser.info, path, lines, pat)


@rule("ACR-AI-007", "Full prompts or model responses written to logs (LLM02 Sensitive Information Disclosure)", Severity.LOW,
      "ai-security", AI,
      fix="Log metadata (model, token counts, latency, request id), not raw prompts or completions that may hold personal data.",
      references=[OWASP_LLM])
def prompt_logging(path, text, lines):
    pat = re.compile(r"\b(logger|logging|log|console)\.(info|debug|warning|warn|log|error)\([^)]*\b(prompt|messages|completion|llm_response|model_output)\b")
    yield from line_matches(prompt_logging.info, path, lines, pat)


@rule("ACR-AI-008", "Secret or credential placed in a system prompt (LLM07 System Prompt Leakage)", Severity.HIGH,
      "ai-security", AI,
      fix="Assume users can extract the system prompt. Keep credentials server-side and enforce access in code, not in prompt text.",
      references=[OWASP_LLM])
def system_prompt_secret(path, text, lines):
    pat = re.compile(r"""(["']role["']\s*:\s*["']system["'][^\n]*|\bsystem(_prompt|_message)?\s*=[^\n]*|SystemMessage\([^\n]*)"""
                     r"""(password|passwd|api[_ -]?key|secret|access[_ -]?token|connection string|os\.environ|getenv\(|settings\.\w*(KEY|TOKEN|SECRET))""",
                     re.I)
    yield from line_matches(system_prompt_secret.info, path, lines, pat)


@rule("ACR-AI-009", "Agent loop has no step or iteration limit (LLM10 Unbounded Consumption)", Severity.MEDIUM,
      "ai-security", AI,
      fix="Bound every agent loop: a maximum number of steps/tool calls, a wall-clock timeout and a token or cost budget.",
      references=[OWASP_LLM])
def unbounded_agent_loop(path, text, lines):
    info = unbounded_agent_loop.info
    explicit = re.compile(r"\b(max_iterations|max_turns|max_steps|recursion_limit)\s*=\s*(None|-1|float\(['\"]inf)")
    yield from line_matches(info, path, lines, explicit)
    agentic = re.compile(r"tool_calls|tool_use|stop_reason|finish_reason|run_tool|execute_tool|\.invoke\(|\.step\(")
    bounded = re.compile(r"max_(steps|iterations|turns|tool_calls)|\bstep(s)?\s*[<>]=?|\biteration|\bturns?\s*[<>]=?|budget|timeout")
    for i, line in enumerate(lines, start=1):
        if not re.match(r"^\s*while\s+(True|1)\s*:", line):
            continue
        body = "\n".join(lines[i:i + 30])
        if agentic.search(body) and not bounded.search(body):
            yield make(info, path, i, "A `while True` agent loop only stops when the model decides to.")


@rule("ACR-AI-010", "Coding agent run with its permission checks or sandbox turned off (LLM06 Excessive Agency)",
      Severity.HIGH, "ai-security", ["github-actions", "shell", "dockerfile", "agent-settings", "app"],
      fix="Keep approvals and the sandbox on. In CI, give the agent an explicit allow-list of tools and commands, a read-only "
          "token and no secrets it does not need; untrusted PR text can steer an unrestricted agent.",
      references=[OWASP_LLM, "https://docs.anthropic.com/en/docs/claude-code/security"])
def agent_permissions_off(path, text, lines):
    pat = re.compile(
        r"--dangerously-skip-permissions\b|--dangerously-bypass-approvals-and-sandbox\b"  # acr:ignore[ACR-AI-010]
        r"|\b(claude|codex|gemini)\b[^\n]*\s--yolo\b"  # acr:ignore[ACR-AI-010]
        r"|bypassPermissions|danger-full-access")  # acr:ignore[ACR-AI-010]
    yield from line_matches(agent_permissions_off.info, path, lines, pat)


@rule("ACR-AI-012", "Model server started with remote code execution enabled (LLM03 Supply Chain)", Severity.HIGH,
      "ai-security", ["kubernetes", "helm-template", "dockerfile", "shell", "github-actions"],
      fix="Drop --trust-remote-code. If a model really needs custom code, vendor and review it, and pin the model with "
          "--revision <commit> so the code you reviewed is the code that runs.",
      references=[OWASP_LLM, "https://huggingface.co/docs/transformers/models#custom-models"])
def server_remote_code(path, text, lines):
    pat = re.compile(r"--trust-remote-code\b|\bTRUST_REMOTE_CODE\s*[:=]\s*['\"]?(true|1)\b", re.I)
    yield from line_matches(server_remote_code.info, path, lines, pat)
