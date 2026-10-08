import subprocess
import tempfile
from pathlib import Path

from agentic_code_review.rules import base


def ids(path: str, text: str, kinds: set[str]) -> list[str]:
    return sorted(f.rule_id for f in base.run_rules(path, text, kinds))


def git_repo(initial: dict[str, str]) -> Path:
    """Create a throwaway git repo with one commit containing `initial`."""
    root = Path(tempfile.mkdtemp(prefix="acr-test-"))
    run = lambda *a: subprocess.run(["git", "-C", str(root), *a], check=True, capture_output=True)  # noqa: E731
    run("init", "-q")
    run("config", "user.email", "t@example.com")
    run("config", "user.name", "t")
    for rel, body in initial.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(body)
    run("add", ".")
    run("commit", "-qm", "init")
    return root
