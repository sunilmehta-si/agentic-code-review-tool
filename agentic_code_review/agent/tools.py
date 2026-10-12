"""Read-only, repository-confined tools the review agent may call.

The code under review is untrusted input and may contain prompt-injection text aimed at
the agent. These tools therefore can only read, never write or execute; they refuse paths
outside the repository (including via `..` or symlinks) and cap how much they return.
"""
from __future__ import annotations

import fnmatch
import json
import subprocess
from pathlib import Path

from .redact import redact

MAX_FILE_LINES = 400
MAX_SEARCH_RESULTS = 40
MAX_PATTERN = 200
# Files that usually hold credentials. Their contents would otherwise be sent to the model provider.
SECRET_FILES = (".env", ".env.*", "*.pem", "*.key", "*.p12", "*.pfx", "*.jks", "*.keystore", "id_rsa*", "id_ecdsa*",
                "id_ed25519*", ".npmrc", ".pypirc", ".netrc", ".git-credentials", "*.tfstate", "*.tfstate.*", "*.kdbx",
                "credentials", "credentials.json", "service-account*.json", "*.tfvars")
SAFE_TEMPLATES = (".env.example", ".env.sample", ".env.template", ".env.dist")


def is_secret_file(rel: str) -> bool:
    name = Path(rel).name.lower()
    return name not in SAFE_TEMPLATES and any(fnmatch.fnmatch(name, pat) for pat in SECRET_FILES)

# Provider-neutral JSON Schemas; each provider wraps them in its own tool format.
TOOL_SPECS = [
    {
        "name": "read_file",
        "description": "Read lines from a file in the repository under review. Use it to see the code around a finding "
                       f"before deciding. Returns at most {MAX_FILE_LINES} numbered lines.",
        "schema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Repository-relative path, e.g. src/app.py"},
                "start_line": {"type": "integer", "description": "First line to return (1-based)."},
                "end_line": {"type": "integer", "description": "Last line to return (inclusive)."},
            },
            "required": ["path", "start_line", "end_line"],
            "additionalProperties": False,
        },
    },
    {
        "name": "search_repo",
        "description": "Search tracked files with a regular expression (git grep). Use it to find where a value is "
                       f"defined, validated or sanitised. Returns at most {MAX_SEARCH_RESULTS} matching lines.",
        "schema": {
            "type": "object",
            "properties": {"pattern": {"type": "string", "description": "Extended regular expression."}},
            "required": ["pattern"],
            "additionalProperties": False,
        },
    },
    {
        "name": "list_changed_files",
        "description": "List the files changed in this pull request and the kind of each (app, kubernetes, ai-code, ...).",
        "schema": {"type": "object", "properties": {}, "required": [], "additionalProperties": False},
    },
]


class RepoTools:
    def __init__(self, root: Path, changed: dict[str, set[str]]):
        self.root = root.resolve()
        self.changed = changed

    # -- dispatch ---------------------------------------------------------------------
    def call(self, name: str, args: dict) -> tuple[str, bool]:
        """Run a tool by name. Returns (text, is_error); never raises."""
        try:
            if name == "read_file":
                return self.read_file(str(args["path"]), int(args.get("start_line", 1)), int(args.get("end_line", 0) or 0)), False
            if name == "search_repo":
                return self.search_repo(str(args["pattern"])), False
            if name == "list_changed_files":
                return json.dumps({p: sorted(k) for p, k in sorted(self.changed.items())}), False
            return f"Unknown tool: {name}", True
        except (KeyError, ValueError, TypeError) as exc:
            return f"Invalid arguments for {name}: {exc}", True
        except PermissionError as exc:
            return str(exc), True

    # -- tools ------------------------------------------------------------------------
    def _safe(self, rel: str) -> Path:
        candidate = (self.root / rel).resolve()
        if Path(rel).is_absolute() or (candidate != self.root and self.root not in candidate.parents):
            raise PermissionError(f"Refused: '{rel}' is outside the repository.")
        return candidate

    def read_file(self, rel: str, start: int, end: int) -> str:
        path = self._safe(rel)
        if is_secret_file(rel):
            raise PermissionError(f"Refused: '{rel}' usually holds credentials, so it is never sent to the model.")
        if not path.is_file():
            return f"No such file: {rel}"
        lines = path.read_text(errors="replace").splitlines()
        start = max(1, start)
        end = min(len(lines), end if end >= start else start + MAX_FILE_LINES - 1, start + MAX_FILE_LINES - 1)
        body = "\n".join(f"{n:>5}  {lines[n - 1]}" for n in range(start, end + 1))
        return redact(f"{rel} (lines {start}-{end} of {len(lines)})\n{body}")

    def search_repo(self, pattern: str) -> str:
        if not pattern or len(pattern) > MAX_PATTERN:
            return f"Pattern must be 1-{MAX_PATTERN} characters."
        proc = subprocess.run(["git", "-C", str(self.root), "grep", "-n", "-I", "-E", "--max-count", "5", "-e", pattern],
                              capture_output=True, text=True, timeout=30)
        hits = [h for h in proc.stdout.splitlines() if not is_secret_file(h.split(":", 1)[0])]
        if proc.returncode not in (0, 1):
            return f"Search failed: {proc.stderr.strip()[:200]}"
        shown = [h[:300] for h in hits[:MAX_SEARCH_RESULTS]]
        more = f"\n... {len(hits) - len(shown)} more" if len(hits) > len(shown) else ""
        return redact("\n".join(shown) + more) if shown else "No matches."
