"""Application-code security rules for Python and JavaScript/TypeScript.

These are intentionally narrow, high-precision patterns. Broad SAST coverage comes from
Semgrep/CodeQL when installed; these keep the review useful when they are not.
"""
from __future__ import annotations

import re

from ..models import Severity
from .base import line_matches, rule

PY = ["lang:python"]
JS = ["lang:javascript", "lang:typescript"]


@rule("ACR-APP-001", "SQL built with string formatting", Severity.HIGH, "app-security", PY + JS,
      fix="Use parameterised queries (placeholders + a parameters tuple), never f-strings, % or + to build SQL.",
      references=["https://owasp.org/Top10/A03_2021-Injection/"])
def sql_formatting(path, text, lines):
    pat = re.compile(r"""\.(execute|executemany|raw|query)\(\s*(f["']|["'][^"']*["']\s*(%|\+|\.format\())""", re.I)
    sql_js = re.compile(r"""\.query\(\s*`[^`]*\$\{""")
    yield from line_matches(sql_formatting.info, path, lines, pat)
    yield from line_matches(sql_formatting.info, path, lines, sql_js)


@rule("ACR-APP-002", "Shell command built from a string", Severity.HIGH, "app-security", PY + JS,
      fix="Pass an argument list without a shell (subprocess.run([...]) / execFile), and validate any user input.",
      references=["https://cwe.mitre.org/data/definitions/78.html"])
def shell_injection(path, text, lines):
    py = re.compile(r"\b(subprocess\.(run|call|Popen|check_output|check_call)\(.*shell\s*=\s*True|os\.system\(|os\.popen\()")
    js = re.compile(r"""\b(child_process\.)?exec(Sync)?\(\s*(`[^`]*\$\{|[^)]*\+)""")  # acr:ignore - rule pattern, not a call
    yield from line_matches(shell_injection.info, path, lines, py)
    yield from line_matches(shell_injection.info, path, lines, js)


@rule("ACR-APP-003", "Dynamic code execution", Severity.HIGH, "app-security", PY + JS,
      fix="Remove eval/exec/new Function. Parse data with a real parser (json.loads, ast.literal_eval) instead.")
def dynamic_exec(path, text, lines):
    pat = re.compile(r"(?<![\w.])(eval|exec)\(|\bnew Function\(")
    yield from line_matches(dynamic_exec.info, path, lines, pat)


@rule("ACR-APP-004", "Unsafe deserialisation", Severity.HIGH, "app-security", PY,
      fix="Use yaml.safe_load / json; never unpickle data that can come from outside the process.",
      references=["https://cwe.mitre.org/data/definitions/502.html"])
def unsafe_deserialise(path, text, lines):
    pat = re.compile(r"\b(pickle|cPickle|dill|shelve)\.(loads?|Unpickler)\(|\byaml\.load\((?![^)]*SafeLoader)|\byaml\.unsafe_load\(")
    yield from line_matches(unsafe_deserialise.info, path, lines, pat)


@rule("ACR-APP-005", "TLS certificate verification disabled", Severity.MEDIUM, "app-security", PY + JS,
      fix="Keep verification on. If a private CA is needed, point the client at that CA bundle instead.")
def tls_off(path, text, lines):
    pat = re.compile(r"verify\s*=\s*False|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0|ssl\._create_unverified_context")
    yield from line_matches(tls_off.info, path, lines, pat)


@rule("ACR-APP-006", "Debug mode enabled in application code", Severity.MEDIUM, "app-security", PY,
      fix="Drive debug from configuration that is off by default; never ship debug=True.")
def debug_on(path, text, lines):
    pat = re.compile(r"\.run\([^)]*debug\s*=\s*True|^\s*DEBUG\s*=\s*True\b")
    yield from line_matches(debug_on.info, path, lines, pat)


@rule("ACR-APP-007", "Weak hash used for security", Severity.LOW, "app-security", PY + JS,
      fix="Use SHA-256+ for integrity, and bcrypt/scrypt/argon2 for passwords.")
def weak_hash(path, text, lines):
    pat = re.compile(r"hashlib\.(md5|sha1)\(|createHash\(\s*['\"](md5|sha1)['\"]")
    yield from line_matches(weak_hash.info, path, lines, pat)
