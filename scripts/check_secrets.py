#!/usr/bin/env python3
"""Dependency-free secret scanner used locally, in the pre-commit hook and in CI.

Modes:
  --staged   scan lines added to the git index (pre-commit hook)
  --all      scan every tracked file in the working tree
  --history  scan every line ever added in any commit

Exit code 1 when a finding exists. Add the marker ``secret-scan:allow`` to a line
that is a deliberate, harmless fixture.
"""
from __future__ import annotations

import argparse
import fnmatch
import re
import subprocess
import sys
from dataclasses import dataclass

ALLOW_MARKER = "secret-scan:allow"

RULES: list[tuple[str, re.Pattern[str]]] = [
    ("aws-access-key-id", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("github-fine-grained-token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{50,}\b")),
    ("slack-token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("anthropic-api-key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b")),
    ("openai-api-key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{32,}\b")),
    ("stripe-live-key", re.compile(r"\b[sr]k_live_[A-Za-z0-9]{16,}\b")),
    ("huggingface-token", re.compile(r"\bhf_[A-Za-z0-9]{30,}\b")),
    ("private-key-block", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    (
        "hardcoded-credential",
        re.compile(
            r"(?i)[a-z0-9_.-]*(?:password|passwd|secret|token|api[_-]?key|access[_-]?key)[a-z0-9_.-]*"
            r"\s*[:=]\s*['\"]([^'\"\s]{12,})['\"]"
        ),
    ),
]

PLACEHOLDER = re.compile(r"(?i)(example|changeme|placeholder|dummy|your[_-]|<[^>]+>|\$\{|\$\(|x{4,}|\*{4,}|redacted)")

FORBIDDEN_FILES = [
    ".env", ".env.*", "*.pem", "*.key", "*.p12", "*.pfx", "*.jks", "id_rsa*", "id_ed25519*",
    "*.tfstate", "*.tfstate.*", "kubeconfig", "*.kubeconfig", "credentials.json", ".npmrc", ".pypirc", ".netrc",
]
FORBIDDEN_ALLOW = {".env.example"}


@dataclass(frozen=True)
class Finding:
    rule: str
    where: str
    line: str

    def render(self) -> str:
        # Never echo the offending line: a CI log must not become a second leak.
        return f"  [{self.rule}] {self.where}"


def scan_line(line: str) -> list[str]:
    if ALLOW_MARKER in line:
        return []
    hits = []
    for name, pattern in RULES:
        match = pattern.search(line)
        if not match:
            continue
        if name == "hardcoded-credential" and PLACEHOLDER.search(match.group(1)):
            continue
        hits.append(name)
    return hits


def forbidden_name(path: str) -> bool:
    base = path.rsplit("/", 1)[-1]
    if base in FORBIDDEN_ALLOW:
        return False
    return any(fnmatch.fnmatch(base, pat) for pat in FORBIDDEN_FILES)


def git(*args: str) -> str:
    return subprocess.run(["git", *args], check=True, capture_output=True, text=True, errors="replace").stdout


def added_lines(diff: str) -> list[tuple[str, str]]:
    current, out = "?", []
    for raw in diff.splitlines():
        if raw.startswith("+++ b/"):
            current = raw[6:]
        elif raw.startswith("+") and not raw.startswith("+++"):
            out.append((current, raw[1:]))
    return out


def scan_added(diff: str, label: str = "") -> list[Finding]:
    findings = []
    for path, line in added_lines(diff):
        for rule in scan_line(line):
            findings.append(Finding(rule, f"{label}{path}", line))
    return findings


def run_staged() -> list[Finding]:
    findings = [Finding("forbidden-file", p, p) for p in git("diff", "--cached", "--name-only", "--diff-filter=ACMR").split() if forbidden_name(p)]
    return findings + scan_added(git("diff", "--cached", "-U0", "--no-color"))


def run_all() -> list[Finding]:
    findings = []
    for path in git("ls-files").splitlines():
        if forbidden_name(path):
            findings.append(Finding("forbidden-file", path, path))
        try:
            with open(path, encoding="utf-8", errors="strict") as handle:
                for number, line in enumerate(handle, 1):
                    findings += [Finding(r, f"{path}:{number}", line) for r in scan_line(line)]
        except (UnicodeDecodeError, IsADirectoryError, FileNotFoundError):
            continue
    return findings


def run_history() -> list[Finding]:
    findings = []
    for commit in git("rev-list", "--all").split():
        short = commit[:8]
        for path in git("show", "--name-only", "--format=", commit).split():
            if forbidden_name(path):
                findings.append(Finding("forbidden-file", f"{short}:{path}", path))
        findings += scan_added(git("show", "-U0", "--no-color", "--format=", commit), f"{short}:")
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--staged", action="store_true")
    mode.add_argument("--all", action="store_true")
    mode.add_argument("--history", action="store_true")
    args = parser.parse_args(argv)
    findings = run_staged() if args.staged else run_all() if args.all else run_history()
    if findings:
        print(f"Secret scan FAILED: {len(findings)} finding(s)", file=sys.stderr)
        for finding in findings:
            print(finding.render(), file=sys.stderr)
        return 1
    print("Secret scan passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
