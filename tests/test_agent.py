"""AI-layer tests. A scripted fake model stands in for Claude/OpenAI, so no network or API key is needed."""
import json
import unittest
from types import SimpleNamespace as NS

from agentic_code_review import report
from agentic_code_review.agent.claude import ClaudeReviewer
from agentic_code_review.agent.openai_compat import OpenAICompatReviewer
from agentic_code_review.agent.review import AgentError, parse_result
from agentic_code_review.agent.run import apply_ai
from agentic_code_review.agent.tools import RepoTools
from agentic_code_review.engine import review
from tests.helpers import git_repo


class ScriptedClaude:
    """Fake Anthropic client: replays a list of responses and records each request."""

    def __init__(self, responses):
        self.responses, self.requests = list(responses), []
        self.beta = NS(messages=self)
        self.messages = self

    def create(self, **kwargs):
        # Snapshot the conversation as sent; the agent keeps appending to the same list afterwards.
        self.requests.append({**kwargs, "messages": list(kwargs["messages"])})
        return self.responses.pop(0)


def final(payload: dict):
    return NS(stop_reason="end_turn", usage=NS(input_tokens=10, output_tokens=5),
              content=[NS(type="text", text=json.dumps(payload))])


def tool_use(name, args, id_="t1"):
    return NS(stop_reason="tool_use", usage=NS(), content=[NS(type="tool_use", id=id_, name=name, input=args)])


class RepoToolsTests(unittest.TestCase):
    def setUp(self):
        self.root = git_repo({"src/app.py": "x = 1\n"})
        self.tools = RepoTools(self.root, {"src/app.py": {"app"}})

    def test_reads_inside_repo(self):
        text, err = self.tools.call("read_file", {"path": "src/app.py", "start_line": 1, "end_line": 1})
        self.assertFalse(err)
        self.assertIn("x = 1", text)

    def test_refuses_escape_and_unknown_tools(self):
        for path in ("../outside.txt", "/etc/passwd", "src/../../x"):
            _, err = self.tools.call("read_file", {"path": path, "start_line": 1, "end_line": 1})
            self.assertTrue(err, path)
        self.assertTrue(self.tools.call("write_file", {})[1])

    def test_symlink_escape_refused(self):
        (self.root / "link").symlink_to("/etc")
        self.assertTrue(self.tools.call("read_file", {"path": "link/hosts", "start_line": 1, "end_line": 1})[1])


class ClaudeLoopTests(unittest.TestCase):
    def test_tool_call_then_verdict(self):
        root = git_repo({"a.py": "print(1)\n"})
        client = ScriptedClaude([tool_use("read_file", {"path": "a.py", "start_line": 1, "end_line": 1}),
                                 final({"verdicts": [], "new_findings": [], "summary": "ok"})])
        data = ClaudeReviewer(client=client).review("msg", RepoTools(root, {}))
        self.assertEqual(data["summary"], "ok")
        second = client.requests[1]["messages"]
        self.assertEqual([m["role"] for m in second], ["user", "assistant", "user"])
        self.assertEqual(second[2]["content"][0]["type"], "tool_result")
        self.assertEqual(client.requests[0]["model"], "claude-opus-5-5")
        self.assertEqual(client.requests[0]["system"][0]["cache_control"], {"type": "ephemeral"})

    def test_refusal_and_runaway_loops_raise(self):
        root = git_repo({"a.py": "x\n"})
        refusal = NS(stop_reason="refusal", usage=NS(), content=[])
        with self.assertRaises(AgentError):
            ClaudeReviewer(client=ScriptedClaude([refusal])).review("m", RepoTools(root, {}))
        loop = [tool_use("list_changed_files", {}, f"t{i}") for i in range(3)]
        with self.assertRaises(AgentError):
            ClaudeReviewer(client=ScriptedClaude(loop), max_steps=3).review("m", RepoTools(root, {}))


class ApplyAiTests(unittest.TestCase):
    def setUp(self):
        self.root = git_repo({"README.md": "x\n"})
        (self.root / "Dockerfile").write_text("FROM python:latest\nUSER 1000\nRUN curl -s https://x.sh | sh\n")
        self.result = review(self.root, use_scanners=False)

    def test_verdicts_and_new_findings_are_merged(self):
        ids = {f.rule_id: i for i, f in enumerate(self.result.findings)}
        fake = ScriptedClaude([final({
            "verdicts": [{"id": ids["ACR-DOCKER-001"], "verdict": "false_positive", "explanation": "test image", "fix": ""},
                         {"id": ids["ACR-DOCKER-003"], "verdict": "confirmed", "explanation": "real", "fix": "pin it"}],
            "new_findings": [
                {"path": "Dockerfile", "line": 2, "severity": "high", "category": "container", "title": "on a changed line",
                 "explanation": "e", "fix": "f"},
                {"path": "README.md", "line": 1, "severity": "high", "category": "other", "title": "not in the diff",
                 "explanation": "e", "fix": "f"}],
            "summary": "One real issue."})])
        apply_ai(self.result, self.root, ClaudeReviewer(client=fake))
        by_rule = {f.rule_id: f for f in self.result.findings}
        self.assertEqual(by_rule["ACR-DOCKER-001"].ai_verdict, "false_positive")
        self.assertEqual(by_rule["ACR-DOCKER-003"].ai_fix, "pin it")
        agent = [f for f in self.result.findings if f.tool == "agent"]
        self.assertEqual([f.title for f in agent], ["on a changed line"])
        md = report.to_markdown(self.result)
        self.assertIn("One real issue.", md)
        self.assertNotIn("ACR-DOCKER-001", md)

    def test_agent_failure_keeps_deterministic_findings(self):
        before = len(self.result.findings)
        apply_ai(self.result, self.root, ClaudeReviewer(client=ScriptedClaude([NS(stop_reason="refusal", usage=NS(), content=[])])))
        self.assertEqual(len(self.result.findings), before)
        self.assertIn("declined", self.result.ai_error)


class OpenAICompatTests(unittest.TestCase):
    def test_function_calling_round_trip(self):
        root = git_repo({"a.py": "x\n"})
        calls = []

        def transport(payload):
            calls.append({**payload, "messages": list(payload["messages"])})
            if len(calls) == 1:
                return {"choices": [{"message": {"tool_calls": [{"id": "c1", "function": {"name": "list_changed_files", "arguments": "{}"}}]}}]}
            return {"choices": [{"finish_reason": "stop", "message": {"content": '{"verdicts": [], "new_findings": [], "summary": "fine"}'}}]}

        data = OpenAICompatReviewer(model="local", transport=transport).review("m", RepoTools(root, {"a.py": {"app"}}))
        self.assertEqual(data["summary"], "fine")
        self.assertEqual(calls[1]["messages"][-1]["role"], "tool")

    def test_requires_model(self):
        import os
        old = os.environ.pop("ACR_MODEL", None)
        try:
            with self.assertRaises(AgentError):
                OpenAICompatReviewer(transport=lambda p: {})
        finally:
            if old is not None:
                os.environ["ACR_MODEL"] = old


class ParseResultTests(unittest.TestCase):
    def test_fenced_json_and_garbage(self):
        self.assertEqual(parse_result('```json\n{"verdicts": []}\n```')["new_findings"], [])
        with self.assertRaises(AgentError):
            parse_result("not json")
