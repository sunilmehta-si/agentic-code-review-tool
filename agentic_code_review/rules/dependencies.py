"""Rules for lock files and pip pins: what the exact versions a project installs say about its supply chain.

Each lock format is read with a small line scanner rather than a parser, so a finding points at the line that
pins the version, and a malformed or half-merged lock still gets checked.
"""
from __future__ import annotations

import re
from typing import Iterable, Iterator

from ..models import Finding, Severity
from .base import ignored, make, rule

LOCK = {"lockfile"}

TOML_NAME = re.compile(r'^name\s*=\s*"([^"]+)"\s*$')
TOML_VERSION = re.compile(r'^version\s*=\s*"([^"]+)"\s*$')
PIPFILE_ENTRY = re.compile(r'^\s*"([A-Za-z0-9_.-]+)"\s*:\s*\{')
PIPFILE_VERSION = re.compile(r'^\s*"version"\s*:\s*"==([^"]+)"')
PIP_PIN = re.compile(r"^\s*([A-Za-z0-9_.-]+)(\[[^\]]*\])?\s*==\s*([^\s;#\\]+)")


def _canonical(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def pinned_versions(path: str, lines: list[str]) -> Iterator[tuple[str, str, int]]:
    """(package, version, line) for every exact pin in a uv/Poetry/PDM lock, a Pipfile.lock or a pip file."""
    name = path.rsplit("/", 1)[-1].lower()
    if name.endswith(".lock") and name != "pipfile.lock":            # uv.lock, poetry.lock, pdm.lock: TOML tables
        current = None
        for i, text in enumerate(lines, start=1):
            stripped = text.strip()
            if stripped.startswith("[["):
                current = None
            elif m := TOML_NAME.match(stripped):
                current = m.group(1)
            elif current and (m := TOML_VERSION.match(stripped)):
                yield _canonical(current), m.group(1), i
                current = None
    elif name == "pipfile.lock":
        current = None
        for i, text in enumerate(lines, start=1):
            if m := PIPFILE_ENTRY.match(text):
                current = m.group(1)
            elif current and (m := PIPFILE_VERSION.match(text)):
                yield _canonical(current), m.group(1), i
                current = None
    elif name.endswith((".txt", ".in")):
        for i, text in enumerate(lines, start=1):
            if m := PIP_PIN.match(text):
                yield _canonical(m.group(1)), m.group(3), i


def _calendar(version: str) -> tuple[int, ...] | None:
    parts = version.split(".")
    return tuple(int(p) for p in parts) if all(p.isdigit() for p in parts) else None


CERTIFI_FIXED = (2026, 10, 23)


@rule("ACR-DEP-001", "certifi pinned before 2026.10.23, which still trusts the compromised emSign roots",
      Severity.HIGH, "dependency", LOCK,
      fix="Upgrade certifi to 2026.10.23 or later (`uv lock --upgrade-package certifi`, `poetry update certifi`, or "
          "bump the pin), using the same uv or Poetry version your CI checks the lock with.",
      references=("https://github.com/certifi/python-certifi",))
def certifi_with_compromised_roots(path: str, text: str, lines: list[str]) -> Iterable[Finding]:
    info = certifi_with_compromised_roots.info
    for package, version, line in pinned_versions(path, lines):
        when = _calendar(version)
        if package == "certifi" and when and when < CERTIFI_FIXED and not ignored(lines[line - 1], info.rule_id):
            yield make(info, path, line, f"certifi {version}: any TLS connection that trusts this bundle also trusts "
                                         "certificates issued under the emSign roots.")
