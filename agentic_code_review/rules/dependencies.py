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


# A package URL or index over plain http, except on this machine (a local mirror or a test server).
INSECURE_SOURCE = re.compile(
    r"""(registry\s*=\s*"|url\s*=\s*"|"resolved"\s*:\s*"|--(?:extra-)?index-url[=\s]+|(?:^|\s)-i\s+|--find-links[=\s]+|-f\s+)"""
    r"""(http://(?!(?:localhost|127\.0\.0\.1|\[::1\])(?:[:/]|$))[^\s"']+)""")
TRUSTED_HOST = re.compile(r"^\s*--trusted-host[=\s]+(\S+)")


@rule("ACR-DEP-002", "Packages fetched over plain HTTP or from a host exempted from TLS checks",
      Severity.HIGH, "dependency", LOCK,
      fix="Serve the index over HTTPS and drop `--trusted-host`; a mirror behind a private CA can use "
          "`--cert` or `UV_NATIVE_TLS` instead of turning verification off.",
      references=("https://pip.pypa.io/en/stable/topics/https-certificates/",))
def insecure_package_source(path: str, text: str, lines: list[str]) -> Iterable[Finding]:
    info = insecure_package_source.info
    for i, line in enumerate(lines, start=1):
        if line.lstrip().startswith("#") or ignored(line, info.rule_id):
            continue
        if m := INSECURE_SOURCE.search(line):
            yield make(info, path, i, f"{m.group(2)}: anyone on the network path can serve a different package.")
        elif m := TRUSTED_HOST.match(line):
            yield make(info, path, i, f"--trusted-host {m.group(1)} accepts any certificate, or none, from that host.")


EXTRA_INDEX = re.compile(r"^\s*--extra-index-url[=\s]+(\S+)")


@rule("ACR-DEP-003", "Extra package index next to PyPI, open to dependency confusion",
      Severity.MEDIUM, "dependency", LOCK,
      fix="Serve internal packages through one index that proxies PyPI (`--index-url` only), or use uv's index "
          "pinning (`[tool.uv.sources]` with `explicit = true`) so each internal package comes from one index only.",
      references=("https://docs.astral.sh/uv/configuration/indexes/",
                  "https://pip.pypa.io/en/stable/cli/pip_install/#finding-packages"))
def extra_index_confusion(path: str, text: str, lines: list[str]) -> Iterable[Finding]:
    """pip treats every index as equal and installs the highest version it finds, so a public package that takes an
    internal package's name and a higher version number wins; pinning the version does not help if the attacker
    publishes the same one."""
    info = extra_index_confusion.info
    if not path.lower().endswith((".txt", ".in")):
        return
    for i, line in enumerate(lines, start=1):
        if (m := EXTRA_INDEX.match(line)) and not ignored(line, info.rule_id):
            yield make(info, path, i, f"{m.group(1)} is searched alongside the default index for every package.")


NPM_RESOLVED = re.compile(r'^\s*"resolved"\s*:\s*"((?:git\+[a-z]+://|git://|github:|https://codeload\.github\.com/)[^"]+)"')
NPM_INTEGRITY = re.compile(r'^\s*"integrity"\s*:\s*"sha(256|384|512)-')


@rule("ACR-DEP-004", "npm lock installs a package from git with no integrity hash", Severity.LOW, "dependency", LOCK,
      fix="Depend on a published registry version, whose tarball the lock pins by hash; if the git source is needed, "
          "vendor it or publish it to your own registry.",
      references=("https://docs.npmjs.com/cli/configuring-npm/package-lock-json",))
def npm_git_without_integrity(path: str, text: str, lines: list[str]) -> Iterable[Finding]:
    """npm checks a registry tarball against the lock's integrity hash; a git dependency has none, so the code that
    installs is whatever the remote serves for that commit, unverified."""
    info = npm_git_without_integrity.info
    if not path.lower().endswith(("package-lock.json", "npm-shrinkwrap.json")):
        return
    for i, line in enumerate(lines, start=1):
        if not (m := NPM_RESOLVED.match(line)) or ignored(line, info.rule_id):
            continue
        entry = lines[max(0, i - 6):i + 6]                    # the package's own object: a few lines either side
        if not any(NPM_INTEGRITY.match(other) for other in entry):
            yield make(info, path, i, f"{m.group(1)[:120]} is installed without a hash to check it against.")
