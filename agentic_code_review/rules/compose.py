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


@rule("ACR-COMPOSE-002", "Compose service mounts the Docker socket or a sensitive host path", Severity.HIGH, "container",
      COMPOSE,
      fix="Don't mount /var/run/docker.sock (it is root on the host) or host system directories; use named volumes, "
          "and a socket proxy with an allow-list if a tool truly needs the Docker API.",
      references=["https://docs.docker.com/engine/security/#docker-daemon-attack-surface"])
def compose_host_mount(path, text, lines):
    host = r"(/var/run/docker\.sock|/run/docker\.sock|/run/containerd/containerd\.sock|/|/etc|/root|/home|/proc|/sys)"
    pat = re.compile(rf"""^\s*-\s*['"]?{host}(:|['"]?\s*$)|^\s*source\s*:\s*['"]?{host}['"]?\s*$""")
    yield from line_matches(compose_host_mount.info, path, lines, pat)
