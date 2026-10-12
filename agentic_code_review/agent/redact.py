"""Mask credentials before any text leaves the machine for a model provider.

The deterministic rules already report these secrets; the model only needs to know a secret is
there, never its value.
"""
from __future__ import annotations

import re

from ..rules.secrets import GENERIC, PLACEHOLDER, PROVIDER_PATTERNS

PEM_BLOCK = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(-----END [A-Z ]*PRIVATE KEY-----|\Z)")


def redact(text: str) -> str:
    text = PEM_BLOCK.sub("[REDACTED private key]", text)
    for name, pat in PROVIDER_PATTERNS:
        text = pat.sub(f"[REDACTED {name}]", text)

    def _value(m: re.Match) -> str:
        if PLACEHOLDER.search(m.group(3)):
            return m.group(0)
        start, end = m.start(3) - m.start(0), m.end(3) - m.start(0)
        return m.group(0)[:start] + "[REDACTED]" + m.group(0)[end:]
    return GENERIC.sub(_value, text)
