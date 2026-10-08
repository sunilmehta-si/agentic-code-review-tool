"""Review agent for any OpenAI-compatible chat-completions endpoint: OpenAI, vLLM, Ollama, LM Studio, LiteLLM.

Standard-library HTTP only, so self-hosted and air-gapped setups need no extra packages.
Configure with ACR_OPENAI_BASE_URL (default https://api.openai.com/v1), ACR_MODEL, and
ACR_OPENAI_API_KEY or OPENAI_API_KEY (optional for local servers).
"""
from __future__ import annotations

import json
import os
import random
import time
import urllib.error
import urllib.request

from .review import SYSTEM_PROMPT, AgentError, parse_result
from .tools import TOOL_SPECS, RepoTools

RETRYABLE = {408, 409, 429, 500, 502, 503, 504}


class OpenAICompatReviewer:
    def __init__(self, model: str | None = None, base_url: str | None = None, api_key: str | None = None,
                 max_steps: int = 12, timeout: float = 180.0, transport=None):
        self.model = model or os.environ.get("ACR_MODEL")
        if not self.model:
            raise AgentError("Set ACR_MODEL to the model name your endpoint serves (for example qwen2.5-coder:32b).")
        self.base_url = (base_url or os.environ.get("ACR_OPENAI_BASE_URL") or "https://api.openai.com/v1").rstrip("/")
        self.api_key = api_key or os.environ.get("ACR_OPENAI_API_KEY") or os.environ.get("OPENAI_API_KEY") or ""
        self.max_steps, self.timeout = max_steps, timeout
        self._transport = transport or self._post
        self.usage = {"input_tokens": 0, "output_tokens": 0}

    def _post(self, payload: dict) -> dict:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        body = json.dumps(payload).encode()
        for attempt in range(4):
            req = urllib.request.Request(f"{self.base_url}/chat/completions", data=body, headers=headers, method="POST")
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    return json.loads(resp.read().decode())
            except urllib.error.HTTPError as exc:
                if exc.code not in RETRYABLE or attempt == 3:
                    detail = exc.read().decode(errors="replace")[:200]
                    raise AgentError(f"Model endpoint returned HTTP {exc.code}: {detail}") from exc
            except (urllib.error.URLError, TimeoutError) as exc:
                if attempt == 3:
                    raise AgentError(f"Could not reach {self.base_url}: {exc}") from exc
            time.sleep(min(2 ** attempt + random.random(), 20))
        raise AgentError("Model endpoint did not respond.")

    def review(self, user_message: str, tools: RepoTools) -> dict:
        tool_defs = [{"type": "function", "function": {"name": t["name"], "description": t["description"],
                                                       "parameters": t["schema"]}} for t in TOOL_SPECS]
        messages: list = [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": user_message}]
        for _ in range(self.max_steps):
            data = self._transport({"model": self.model, "messages": messages, "tools": tool_defs,
                                    "max_tokens": 16000, "temperature": 0})
            usage = data.get("usage") or {}
            self.usage["input_tokens"] += int(usage.get("prompt_tokens", 0) or 0)
            self.usage["output_tokens"] += int(usage.get("completion_tokens", 0) or 0)
            choice = (data.get("choices") or [{}])[0]
            msg = choice.get("message") or {}
            calls = msg.get("tool_calls") or []
            if calls:
                messages.append({"role": "assistant", "content": msg.get("content") or "", "tool_calls": calls})
                for call in calls:
                    fn = call.get("function") or {}
                    try:
                        args = json.loads(fn.get("arguments") or "{}")
                    except ValueError:
                        text, _ = "Arguments were not valid JSON.", True
                    else:
                        text, _ = tools.call(fn.get("name", ""), args if isinstance(args, dict) else {})
                    messages.append({"role": "tool", "tool_call_id": call.get("id", ""), "content": text})
                continue
            if choice.get("finish_reason") == "length":
                raise AgentError("The model ran out of output tokens before finishing the review.")
            return parse_result(msg.get("content") or "")
        raise AgentError(f"Review did not finish within {self.max_steps} steps.")
