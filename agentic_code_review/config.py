r"""Repository policy in `.acr.yml`, so teams set rules once instead of on every command line.

    fail_on: high                  # critical | high | medium | low | never
    exclude: ["docs/*", "*.generated.go"]
    include: ["services/api/*"]    # only review these paths (default: everything)
    disable: ["ACR-AI-007", "hadolint:*"]   # rule ids or globs
    severity:                      # per-rule overrides (ids or globs; an exact id wins)
      ACR-K8S-009: medium
      "hadolint:*": low
    scanners: [semgrep, trivy]     # subset of installed scanners
    ai: claude                     # none | claude | openai
    baseline: .acr-baseline.json   # suppress already-known findings
    custom_rules:                  # your own line patterns, reported like built-in rules
      - id: ORG-001
        title: Internal service called over plain HTTP
        pattern: 'http://[a-z0-9-]+\.internal\b'
        severity: medium
        files: ["*.py", "*.go"]    # optional globs (default: every file)
        fix: Use the https:// endpoint through the service mesh.

Command-line flags win over the file.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from .models import CATEGORIES, Severity

FILENAMES = (".acr.yml", ".acr.yaml")
FAIL_VALUES = ("critical", "high", "medium", "low", "never")
KNOWN_KEYS = {"fail_on", "exclude", "include", "disable", "severity", "scanners", "ai", "baseline", "custom_rules"}
RULE_KEYS = {"id", "title", "pattern", "severity", "files", "fix", "category", "references"}
CUSTOM_ID = re.compile(r"^[A-Z][A-Z0-9]*(-[A-Z0-9]+)+$")


STARTER = """\
# agentic-code-review-tool settings. Command-line flags win over this file.
# Docs: https://github.com/sunilmehta-si/agentic-code-review-tool#configure-once-per-repository

fail_on: high                 # critical | high | medium | low | never

exclude:                      # globs that are never reviewed
  - "docs/*"

disable: []                   # rule ids or globs, e.g. ["ACR-AI-007", "hadolint:*"]

severity: {}                  # per-rule overrides, e.g. {ACR-K8S-009: medium}

# scanners: [semgrep, trivy]  # default: every installed scanner
# ai: claude                  # none | claude | openai
# baseline: .acr-baseline.json
"""


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class CustomRule:
    rule_id: str
    title: str
    pattern: re.Pattern
    severity: Severity
    files: tuple[str, ...] = ()
    fix: str = ""
    category: str = "other"
    references: tuple[str, ...] = ()


@dataclass
class Config:
    fail_on: str | None = None
    exclude: list[str] = field(default_factory=list)
    include: list[str] = field(default_factory=list)
    disable: list[str] = field(default_factory=list)
    severity: dict[str, Severity] = field(default_factory=dict)
    scanners: list[str] | None = None
    ai: str | None = None
    baseline: str | None = None
    custom_rules: list[CustomRule] = field(default_factory=list)
    source: str | None = None


def _list(value, key: str) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and all(isinstance(v, str) for v in value):
        return value
    raise ConfigError(f"'{key}' must be a string or a list of strings.")


def _custom_rules(value) -> list[CustomRule]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise ConfigError("custom_rules must be a list of rules.")
    out: list[CustomRule] = []
    for n, raw in enumerate(value, start=1):
        where = f"custom_rules[{n}]"
        if not isinstance(raw, dict):
            raise ConfigError(f"{where} must be a mapping.")
        unknown = set(raw) - RULE_KEYS
        if unknown:
            raise ConfigError(f"{where}: unknown key(s) {', '.join(sorted(unknown))}.")
        missing = [k for k in ("id", "title", "pattern") if not raw.get(k)]
        if missing:
            raise ConfigError(f"{where}: missing {', '.join(missing)}.")
        rid = str(raw["id"]).upper()
        if not CUSTOM_ID.match(rid) or rid.startswith("ACR-"):
            raise ConfigError(f"{where}: id '{raw['id']}' must look like ORG-001 and must not use the reserved ACR- prefix.")
        if any(r.rule_id == rid for r in out):
            raise ConfigError(f"{where}: duplicate id {rid}.")
        try:
            pattern = re.compile(str(raw["pattern"]))
        except re.error as exc:
            raise ConfigError(f"{where} ({rid}): pattern is not a valid regular expression: {exc}.") from exc
        level = str(raw.get("severity", "medium")).lower()
        if level not in ("critical", "high", "medium", "low", "info"):
            raise ConfigError(f"{where} ({rid}): severity must be critical, high, medium, low or info.")
        category = str(raw.get("category", "other"))
        if category not in CATEGORIES:
            raise ConfigError(f"{where} ({rid}): category must be one of {', '.join(CATEGORIES)}.")
        out.append(CustomRule(rid, str(raw["title"]), pattern, Severity.parse(level), tuple(_list(raw.get("files"), f"{where}.files")),
                              str(raw.get("fix", "")), category, tuple(_list(raw.get("references"), f"{where}.references"))))
    return out


def load(root: Path) -> Config:
    path = next((root / n for n in FILENAMES if (root / n).is_file()), None)
    if path is None:
        return Config()
    try:
        import yaml
    except ImportError as exc:  # PyYAML is a declared dependency; this only guards odd environments
        raise ConfigError("Reading .acr.yml needs PyYAML.") from exc
    try:
        data = yaml.safe_load(path.read_text()) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"{path.name} is not valid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"{path.name} must be a mapping of settings.")
    unknown = set(data) - KNOWN_KEYS
    if unknown:
        raise ConfigError(f"Unknown setting(s) in {path.name}: {', '.join(sorted(unknown))}. Known: {', '.join(sorted(KNOWN_KEYS))}.")

    fail_on = data.get("fail_on")
    if fail_on is not None and str(fail_on).lower() not in FAIL_VALUES:
        raise ConfigError(f"fail_on must be one of {', '.join(FAIL_VALUES)}.")
    sev: dict[str, Severity] = {}
    for rule_id, level in (data.get("severity") or {}).items():
        parsed = Severity.parse(str(level), default=None)
        if str(level).lower() not in ("critical", "high", "medium", "low", "info") or parsed is None:
            raise ConfigError(f"severity for {rule_id} must be critical, high, medium, low or info.")
        sev[str(rule_id)] = parsed
    ai = data.get("ai")
    if ai is not None and str(ai) not in ("none", "claude", "openai"):
        raise ConfigError("ai must be none, claude or openai.")
    scanners = data.get("scanners")
    return Config(fail_on=str(fail_on).lower() if fail_on is not None else None,
                  exclude=_list(data.get("exclude"), "exclude"), include=_list(data.get("include"), "include"), disable=_list(data.get("disable"), "disable"),
                  severity=sev, scanners=_list(scanners, "scanners") if scanners is not None else None,
                  ai=None if ai in (None, "none") else str(ai), baseline=data.get("baseline"),
                  custom_rules=_custom_rules(data.get("custom_rules")), source=path.name)
