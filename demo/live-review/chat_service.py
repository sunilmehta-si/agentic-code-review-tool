"""Demo for the live review PR: a small support-bot service with deliberate security mistakes.

Do not merge. This file exists so the agentic-code-review-tool bot has something real to review.
"""
import subprocess

import anthropic

client = anthropic.Anthropic()


def answer(user_name: str, question: str) -> str:
    response = client.messages.create(
        model="claude-sonnet-5-5",
        system=f"You are a support bot for Acme. The customer is {user_name}.",
        messages=[{"role": "user", "content": question}],
    )
    return response.content[0].text


def run_suggested_fix(question: str) -> str:
    """Ask the bot how to fix a server problem, then run whatever it says."""
    reply = answer("ops-team", question)
    return subprocess.run(reply, shell=True, capture_output=True, text=True).stdout


def disk_usage() -> str:
    """A fixed command with no user input; a good test of whether the AI reviewer spots a false positive."""
    return subprocess.run("df -h /", shell=True, capture_output=True, text=True).stdout
