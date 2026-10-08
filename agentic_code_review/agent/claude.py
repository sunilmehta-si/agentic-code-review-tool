"""Claude review agent, using the official Anthropic Python SDK (install with `pip install agentic-code-review-tool[claude]`).

A manual tool-use loop keeps full control over step limits and lets tests drive it with a fake client.
Defaults: model claude-opus-5-5, effort high, structured JSON output, cached system prompt,
and server-side fallback on safety refusals (disable with ACR_CLAUDE_FALLBACKS=0).
"""
from __future__ import annotations

import os

from .review import SYSTEM_PROMPT, VERDICT_SCHEMA, AgentError, parse_result
from .tools import TOOL_SPECS, RepoTools

DEFAULT_MODEL = "claude-opus-5-5"
FALLBACK_BETA = "server-side-fallback-2026-07-01"


class ClaudeReviewer:
    def __init__(self, model: str | None = None, effort: str | None = None, max_steps: int = 12, client=None):
        self.model = model or os.environ.get("ACR_MODEL") or DEFAULT_MODEL
        self.effort = effort or os.environ.get("ACR_EFFORT", "high")
        self.max_steps = max_steps
        self.use_fallbacks = os.environ.get("ACR_CLAUDE_FALLBACKS", "1") != "0"
        self._client = client
        self.usage = {"input_tokens": 0, "output_tokens": 0, "cache_read_input_tokens": 0}

    def _sdk(self):
        try:
            import anthropic
        except ImportError as exc:
            raise AgentError("The Claude reviewer needs the Anthropic SDK: pip install 'agentic-code-review-tool[claude]'") from exc
        return anthropic

    def _create(self, **kwargs):
        client = self._client
        if client is None:
            client = self._client = self._sdk().Anthropic(max_retries=3)
        if self.use_fallbacks:
            return client.beta.messages.create(betas=[FALLBACK_BETA], fallbacks="default", **kwargs)
        return client.messages.create(**kwargs)

    def review(self, user_message: str, tools: RepoTools) -> dict:
        tool_defs = [{"name": t["name"], "description": t["description"], "input_schema": t["schema"], "strict": True}
                     for t in TOOL_SPECS]
        messages: list = [{"role": "user", "content": user_message}]
        request = dict(model=self.model, max_tokens=16000,
                       system=[{"type": "text", "text": SYSTEM_PROMPT, "cache_control": {"type": "ephemeral"}}],
                       tools=tool_defs,
                       output_config={"effort": self.effort, "format": {"type": "json_schema", "schema": VERDICT_SCHEMA}})
        for _ in range(self.max_steps):
            try:
                response = self._create(messages=messages, **request)
            except AgentError:
                raise
            except Exception as exc:  # SDK errors: classify without importing the SDK at module load
                raise AgentError(self._describe(exc)) from exc
            self._count(response)
            if response.stop_reason == "refusal":
                raise AgentError("Claude declined to review this change (safety refusal).")
            if response.stop_reason == "max_tokens":
                raise AgentError("Claude ran out of output tokens before finishing the review.")
            # Append the full assistant content unchanged (tool_use and thinking blocks included).
            messages.append({"role": "assistant", "content": response.content})
            if response.stop_reason == "tool_use":
                results = []
                for block in response.content:
                    if getattr(block, "type", None) == "tool_use":
                        text, is_error = tools.call(block.name, dict(block.input or {}))
                        results.append({"type": "tool_result", "tool_use_id": block.id, "content": text, "is_error": is_error})
                # All tool results go back together in one user message.
                messages.append({"role": "user", "content": results})
                continue
            if response.stop_reason == "pause_turn":
                continue
            text = "".join(getattr(b, "text", "") for b in response.content if getattr(b, "type", None) == "text")
            return parse_result(text)
        raise AgentError(f"Review did not finish within {self.max_steps} steps.")

    def _count(self, response) -> None:
        u = getattr(response, "usage", None)
        for key in self.usage:
            self.usage[key] += int(getattr(u, key, 0) or 0)

    def _describe(self, exc: Exception) -> str:
        name = type(exc).__name__
        if name == "AuthenticationError":
            return "Anthropic authentication failed: set ANTHROPIC_API_KEY (or run `ant auth login`)."
        if name == "RateLimitError":
            return "Anthropic rate limit reached after retries; try again later."
        if name == "BadRequestError" and self.use_fallbacks and "fallback" in str(exc).lower():
            return "This account or platform rejected server-side fallbacks; rerun with ACR_CLAUDE_FALLBACKS=0."
        if name == "APIConnectionError":
            return "Could not reach the Anthropic API (network error)."
        status = getattr(exc, "status_code", None)
        return f"Anthropic API error{f' {status}' if status else ''}: {str(exc)[:200]}"
