"""Run external scanners and normalise their output into Findings.

Every adapter: checks the binary exists, runs with a timeout, parses JSON defensively,
and returns repo-relative paths with real line numbers so findings can be placed on the PR diff.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from ..models import Finding, Severity

TIMEOUT = int(os.environ.get("ACR_SCANNER_TIMEOUT", "300"))


@dataclass
class Scanner:
    name: str
    binary: str
    kinds: frozenset[str]                      # file kinds this scanner cares about ("*" = any)
    run: Callable[[Path, list[str]], list[Finding]]

    def installed(self) -> bool:
        return shutil.which(self.binary) is not None


class ScannerError(RuntimeError):
    """The scanner could not finish, so its silence must not be read as a clean result."""


def _exec(cmd: list[str], cwd: Path) -> str:
    """Run a scanner. Most exit 1 when they find issues, so only a timeout, a failure to start, or an
    exit code of 2+ with no output counts as an error."""
    try:
        proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=TIMEOUT)
    except subprocess.TimeoutExpired as exc:
        raise ScannerError(f"timed out after {TIMEOUT}s (ACR_SCANNER_TIMEOUT)") from exc
    except OSError as exc:
        raise ScannerError(f"could not start: {exc}") from exc
    if proc.returncode >= 2 and not proc.stdout.strip():
        last = (proc.stderr.strip().splitlines() or [""])[-1][:160]
        raise ScannerError(f"exited with {proc.returncode}" + (f": {last}" if last else ""))
    return proc.stdout


def _loads(raw: str):
    raw = raw.strip()
    if not raw:
        return None
    try:
        return json.loads(raw)
    except ValueError:
        # Some tools print a banner before the JSON document.
        for opener in ("{", "["):
            idx = raw.find(opener)
            if idx > 0:
                try:
                    return json.loads(raw[idx:])
                except ValueError:
                    continue
    return None


def _rel(root: Path, p: str) -> str:
    p = p.lstrip("/") if not Path(p).is_absolute() or not str(p).startswith(str(root)) else str(Path(p).relative_to(root))
    return p.replace("\\", "/")


def _line_of(root: Path, rel: str, needle: str) -> int:
    try:
        for i, line in enumerate((root / rel).read_text(errors="ignore").splitlines(), start=1):
            if needle and needle in line:
                return i
    except OSError:
        pass
    return 1


# --- gitleaks -------------------------------------------------------------------------
def run_gitleaks(root: Path, files: list[str]) -> list[Finding]:
    data = _loads(_exec(["gitleaks", "dir", ".", "--report-format", "json", "--report-path", "-", "--redact", "--no-banner",
                         "--exit-code", "0"], root)) or []
    return [Finding(rule_id=f"gitleaks:{d.get('RuleID', 'secret')}", title=d.get("Description") or "Secret detected",
                    severity=Severity.CRITICAL, path=_rel(root, d.get("File", "")), line=int(d.get("StartLine") or 1),
                    end_line=d.get("EndLine"), tool="gitleaks", category="secrets",
                    detail="Secret value redacted.", fix="Rotate the credential, then remove it from the code.")
            for d in data if isinstance(d, dict)]


# --- semgrep --------------------------------------------------------------------------
def run_semgrep(root: Path, files: list[str]) -> list[Finding]:
    config = os.environ.get("ACR_SEMGREP_CONFIG", "p/default")
    data = _loads(_exec(["semgrep", "scan", "--config", config, "--json", "--quiet", "--metrics=off", *files], root)) or {}
    out = []
    for r in data.get("results", []) if isinstance(data, dict) else []:
        extra = r.get("extra") or {}
        out.append(Finding(rule_id=f"semgrep:{r.get('check_id', '').rsplit('.', 1)[-1]}",
                           title=(extra.get("message") or "Semgrep finding").split("\n")[0][:160],
                           severity=Severity.parse(extra.get("severity")), path=_rel(root, r.get("path", "")),
                           line=int((r.get("start") or {}).get("line") or 1), end_line=(r.get("end") or {}).get("line"),
                           tool="semgrep", category="app-security", references=[(extra.get("metadata") or {}).get("source", "")][:1]))
    return out


# --- trivy (dependencies, misconfiguration, secrets) ----------------------------------
def run_trivy(root: Path, files: list[str]) -> list[Finding]:
    data = _loads(_exec(["trivy", "fs", "--quiet", "--format", "json", "--scanners", "vuln,misconfig", "."], root)) or {}
    out = []
    for res in data.get("Results", []) if isinstance(data, dict) else []:
        target = _rel(root, res.get("Target", ""))
        for v in res.get("Vulnerabilities") or []:
            fixed = v.get("FixedVersion")
            out.append(Finding(rule_id=f"trivy:{v.get('VulnerabilityID')}",
                               title=f"{v.get('PkgName')} {v.get('InstalledVersion')}: {v.get('Title') or v.get('VulnerabilityID')}"[:160],
                               severity=Severity.parse(v.get("Severity")), path=target,
                               line=_line_of(root, target, v.get("PkgName", "")), tool="trivy", category="dependency",
                               fix=f"Upgrade to {fixed}." if fixed else "No fixed version yet; assess exposure or replace the package.",
                               references=[v.get("PrimaryURL")] if v.get("PrimaryURL") else []))
        for m in res.get("Misconfigurations") or []:
            cause = m.get("CauseMetadata") or {}
            out.append(Finding(rule_id=f"trivy:{m.get('AVDID') or m.get('ID')}", title=(m.get("Title") or "Misconfiguration")[:160],
                               severity=Severity.parse(m.get("Severity")), path=target, line=int(cause.get("StartLine") or 1),
                               end_line=cause.get("EndLine"), tool="trivy", category="iac", detail=m.get("Message", ""),
                               fix=m.get("Resolution", "")))
    return out


# --- checkov --------------------------------------------------------------------------
def run_checkov(root: Path, files: list[str]) -> list[Finding]:
    args = ["checkov", "--output", "json", "--quiet", "--compact"]
    for f in files:
        args += ["-f", f]
    data = _loads(_exec(args, root))
    reports = data if isinstance(data, list) else [data] if isinstance(data, dict) else []
    out = []
    for rep in reports:
        for c in ((rep or {}).get("results") or {}).get("failed_checks", []):
            lr = c.get("file_line_range") or [1, 1]
            out.append(Finding(rule_id=f"checkov:{c.get('check_id')}", title=(c.get("check_name") or "Checkov finding")[:160],
                               severity=Severity.parse(c.get("severity"), Severity.MEDIUM), path=_rel(root, c.get("file_path", "")),
                               line=int(lr[0] or 1), end_line=int(lr[-1] or lr[0] or 1), tool="checkov",
                               category="iac", references=[c["guideline"]] if c.get("guideline") else []))
    return out


# --- hadolint -------------------------------------------------------------------------
def run_hadolint(root: Path, files: list[str]) -> list[Finding]:
    data = _loads(_exec(["hadolint", "--format", "json", "--no-fail", *files], root)) or []
    return [Finding(rule_id=f"hadolint:{d.get('code')}", title=(d.get("message") or "")[:160],
                    severity=Severity.parse(d.get("level"), Severity.LOW), path=_rel(root, d.get("file", "")),
                    line=int(d.get("line") or 1), tool="hadolint", category="container")
            for d in data if isinstance(d, dict)]


# --- actionlint -----------------------------------------------------------------------
def run_actionlint(root: Path, files: list[str]) -> list[Finding]:
    data = _loads(_exec(["actionlint", "-format", "{{json .}}", "-no-color", *files], root)) or []
    return [Finding(rule_id=f"actionlint:{d.get('kind', 'lint')}", title=(d.get("message") or "")[:160],
                    severity=Severity.HIGH if d.get("kind") in ("expression", "credentials", "permissions") and "injection" in (d.get("message") or "").lower()
                    else Severity.LOW,
                    path=_rel(root, d.get("filepath", "")), line=int(d.get("line") or 1), tool="actionlint", category="ci-cd")
            for d in data if isinstance(d, dict)]


# --- kube-linter ----------------------------------------------------------------------
def run_kube_linter(root: Path, files: list[str]) -> list[Finding]:
    data = _loads(_exec(["kube-linter", "lint", "--format", "json", *files], root)) or {}
    out = []
    for r in data.get("Reports") or [] if isinstance(data, dict) else []:
        obj = r.get("Object") or {}
        path = _rel(root, (obj.get("Metadata") or {}).get("FilePath", ""))
        name = ((obj.get("K8sObject") or {}).get("Name")) or ""
        out.append(Finding(rule_id=f"kube-linter:{r.get('Check')}", title=((r.get("Diagnostic") or {}).get("Message") or "")[:160],
                           severity=Severity.MEDIUM, path=path, line=_line_of(root, path, f"name: {name}") if name else 1,
                           tool="kube-linter", category="kubernetes", fix=r.get("Remediation", "")))
    return out


ALL_SCANNERS: list[Scanner] = [
    Scanner("gitleaks", "gitleaks", frozenset({"*"}), run_gitleaks),
    Scanner("semgrep", "semgrep", frozenset({"app"}), run_semgrep),
    Scanner("trivy", "trivy", frozenset({"*"}), run_trivy),
    Scanner("checkov", "checkov", frozenset({"terraform", "kubernetes", "dockerfile", "github-actions"}), run_checkov),
    Scanner("hadolint", "hadolint", frozenset({"dockerfile"}), run_hadolint),
    Scanner("actionlint", "actionlint", frozenset({"github-actions"}), run_actionlint),
    Scanner("kube-linter", "kube-linter", frozenset({"kubernetes"}), run_kube_linter),
]


def available_scanners(only: set[str] | None = None) -> list[Scanner]:
    return [s for s in ALL_SCANNERS if s.installed() and (only is None or s.name in only)]
