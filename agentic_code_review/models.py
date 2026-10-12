"""Core data types shared by rules, scanners, the AI layer and reporters."""
from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from enum import IntEnum


def fingerprint(rule_id: str, path: str, line_text: str) -> str:
    """Stable identity of a finding: rule, file and the flagged line's normalised text, not its number,
    so it survives code moving above it and changes when the line itself changes."""
    raw = f"{rule_id}|{path}|{' '.join(line_text.split())}"
    return hashlib.sha256(raw.encode()).hexdigest()[:24]


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str | None, default: "Severity" = None) -> "Severity":
        """Map the many severity vocabularies scanners use onto one scale."""
        if value is None:
            return default if default is not None else cls.MEDIUM
        v = str(value).strip().lower()
        aliases = {
            "critical": cls.CRITICAL, "blocker": cls.CRITICAL,
            "high": cls.HIGH, "error": cls.HIGH,
            "medium": cls.MEDIUM, "moderate": cls.MEDIUM, "warning": cls.MEDIUM,
            "low": cls.LOW, "minor": cls.LOW, "style": cls.LOW,
            "info": cls.INFO, "informational": cls.INFO, "note": cls.INFO, "none": cls.INFO, "unknown": cls.MEDIUM,
        }
        return aliases.get(v, default if default is not None else cls.MEDIUM)

    def label(self) -> str:
        return self.name.lower()


# Categories keep the report readable for both developers and platform teams.
CATEGORIES = ("secrets", "app-security", "ai-security", "kubernetes", "container", "ci-cd", "iac", "dependency", "other")


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: Severity
    path: str
    line: int
    tool: str
    category: str = "other"
    end_line: int | None = None
    detail: str = ""
    fix: str = ""
    references: list[str] = field(default_factory=list)
    # Filled in by the AI layer when enabled.
    ai_verdict: str | None = None          # "confirmed" | "false_positive" | "uncertain"
    ai_explanation: str = ""
    ai_fix: str = ""
    fingerprint: str = ""                  # set by the engine; see models.fingerprint

    def key(self) -> tuple:
        """Identity used to de-duplicate the same issue reported by several tools."""
        return (self.path, self.line, self.category, self.title.lower()[:40])

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.label()
        return d


@dataclass
class ChangedFile:
    path: str
    added_lines: set[int] = field(default_factory=set)   # 1-based line numbers in the new file
    deleted: bool = False

    def touches(self, line: int, end_line: int | None = None) -> bool:
        if not self.added_lines:
            return False
        end = end_line or line
        return any(n in self.added_lines for n in range(line, end + 1))
