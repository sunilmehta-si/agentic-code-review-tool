"""Docker Compose rules: the same container risks as Kubernetes, in the files teams run on laptops and single hosts."""
from __future__ import annotations

import re

from ..models import Severity
from .base import line_matches, rule

COMPOSE = ["compose"]
COMPOSE_REF = "https://docs.docker.com/reference/compose-file/services/"


@rule("ACR-COMPOSE-001", "Compose service runs privileged or shares a host namespace", Severity.CRITICAL, "container",
      COMPOSE,
      fix="Remove privileged: true and network_mode/pid/ipc: host; add only the specific capability the service needs with cap_add.",
      references=[COMPOSE_REF])
def compose_privileged(path, text, lines):
    pat = re.compile(r"^\s*privileged\s*:\s*true\b|^\s*(network_mode|pid|ipc)\s*:\s*['\"]?host\b")
    yield from line_matches(compose_privileged.info, path, lines, pat)
