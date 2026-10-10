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


@rule("ACR-APP-008", "JWT accepted without verifying its signature or expiry", Severity.CRITICAL, "app-security", PY + JS,
      fix="Always verify: pass the key and an explicit algorithms list (never 'none'), and keep expiry checks on.",
      references=["https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html"])
def jwt_unverified(path, text, lines):
    pat = re.compile(r"""["']verify_signature["']\s*:\s*False|["']verify_exp["']\s*:\s*False|jwt\.decode\([^)]*verify\s*=\s*False"""
                     r"""|algorithms\s*[:=]\s*\[\s*["']none["']|ignoreExpiration\s*:\s*true|\bjwt\.decode\(\s*\w+\s*\)""", re.I)
    yield from line_matches(jwt_unverified.info, path, lines, pat)


@rule("ACR-APP-009", "CORS allows any origin together with credentials", Severity.HIGH, "app-security", PY + JS,
      fix="List the exact trusted origins. Never combine a wildcard or reflected origin with credentials (cookies, auth headers).",
      references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"])
def cors_wildcard(path, text, lines):
    creds = re.compile(r"allow_credentials\s*=\s*True|supports_credentials\s*=\s*True|credentials\s*:\s*true", re.I)
    if not creds.search(text):
        return
    wildcard = re.compile(r"""allow_origins\s*=\s*\[\s*["']\*["']|origins\s*=\s*["']\*["']|origin\s*:\s*(["']\*["']|true)\b"""
                          r"""|CORS\([^)]*resources\s*=\s*\{[^}]*["']origins["']\s*:\s*["']\*["']""")
    yield from line_matches(cors_wildcard.info, path, lines, wildcard)
