"""Hardcoded secrets in any text file. Findings never echo the secret value."""
from __future__ import annotations

import re

from ..models import Severity
from .base import make, rule

PROVIDER_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("AWS access key ID", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("GitHub fine-grained token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{50,}\b")),
    ("Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("Anthropic API key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b")),
    ("OpenAI API key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{32,}\b")),
    ("Hugging Face token", re.compile(r"\bhf_[A-Za-z0-9]{30,}\b")),
    ("Stripe live key", re.compile(r"\b[sr]k_live_[A-Za-z0-9]{16,}\b")),
    ("Private key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY")),
]
GENERIC = re.compile(
    r"(?i)\b([a-z0-9_.-]*(password|passwd|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret)[a-z0-9_.-]*)"
    r"\s*[:=]\s*['\"]([^'\"\s]{8,})['\"]")
# Plural "tokens" names are settings, not credentials: max_tokens, http_tokens = "required", tokens_per_minute. A name
# that ends in name, ref, key-name, path, flag and the like holds where a secret lives, not the secret: a
# secret_name set to aws-creds, an initialPasswordSecretName naming a Kubernetes Secret, a TokenKey naming a key in it.
NOT_A_SECRET_NAME = re.compile(r"(?i)tokens\b|tokens_|(_|[a-z])(names?|ref|refs|path|file|flag|flagname|header|field|label|prefix|suffix|"
                               r"type|kind|mode|url|uri|env|var|id|interval|ttl|count|length|len|endpoint|audience|annotation|"
                               r"format|version|subject|claims)$|"
                               r"(secret|token|password|passwd)[_-]?key$|(secret|token|password)key$")
# A value made of lower-case words joined by separators is a setting, a reference or a fixture label, not a credential
# (a dotted settings key, a snake_case constant, a hyphenated label). Credentials mix cases and digits.
SLUG_VALUE = re.compile(r"^[a-z][a-z0-9]*([._/-][a-z0-9]+)+$")
# An UPPER_SNAKE value is the name of the environment variable the secret is read from; a URL is where to get one
# (an OAuth token endpoint).
NAME_OR_URL_VALUE = re.compile(r"^[A-Z][A-Z0-9_]{6,}$|^[a-z][a-z0-9+.-]*://")
PLACEHOLDER = re.compile(r"(?i)(example|changeme|placeholder|dummy|sample|test|your[_-]|<[^>]+>|\$\{|\$\(|\{\{|x{4,}|\*{4,}|redacted|env\[|getenv)")

FIX = ("Remove the value from the code, rotate it immediately (it is already in git history), and load it at runtime "
       "from a secret manager or an injected environment variable.")


@rule("ACR-SEC-001", "Provider credential committed to source", Severity.CRITICAL, "secrets", ["*"], fix=FIX,
      references=["https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"])
def provider_secret(path, text, lines):
    info = provider_secret.info
    for i, line in enumerate(lines, start=1):
        for name, pat in PROVIDER_PATTERNS:
            if pat.search(line):
                yield make(info, path, i, f"Looks like a {name}. The value is not shown here on purpose.")
                break


@rule("ACR-SEC-002", "Hardcoded password or token", Severity.HIGH, "secrets", ["*"], fix=FIX)
def generic_secret(path, text, lines):
    info = generic_secret.info
    for i, line in enumerate(lines, start=1):
        m = GENERIC.search(line)
        if (m and not PLACEHOLDER.search(m.group(3)) and not NOT_A_SECRET_NAME.search(m.group(1))
                and not SLUG_VALUE.match(m.group(3)) and not NAME_OR_URL_VALUE.match(m.group(3))):
            yield make(info, path, i, f"A value is assigned to a '{m.group(2).lower()}'-like name in source.")
