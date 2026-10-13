"""Docker Compose rules: the same container risks as Kubernetes, in the files teams run on laptops and single hosts."""
from __future__ import annotations

import re

from ..models import Severity
from .base import line_matches, make, rule
from .kubernetes import UNAUTHENTICATED_PORTS

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


@rule("ACR-COMPOSE-003", "Compose image not pinned (latest or no tag)", Severity.MEDIUM, "container", COMPOSE,
      fix="Pin each image to a version tag, ideally with its digest (image: postgres:16.4@sha256:...).",
      references=[COMPOSE_REF])
def compose_image_pin(path, text, lines):
    info = compose_image_pin.info
    pat = re.compile(r"""^\s*image\s*:\s*['"]?([^'"\s#]+)""")
    for f in line_matches(info, path, lines, pat):
        ref = pat.match(lines[f.line - 1]).group(1)
        name = ref.rsplit("/", 1)[-1]
        if "@sha256:" in ref or "$" in ref or (":" in name and not name.endswith(":latest")):
            continue
        f.detail = f"Image '{ref}' can change between pulls."
        yield f


# Databases have passwords, but exposing them to every network is still how most get breached.
EXPOSED_PORTS = {**UNAUTHENTICATED_PORTS, 5432: "PostgreSQL", 3306: "MySQL", 1433: "SQL Server", 5672: "RabbitMQ",
                 9092: "Kafka", 2379: "etcd"}


@rule("ACR-COMPOSE-004", "Compose publishes a database or unauthenticated port on all interfaces", Severity.HIGH,
      "container", COMPOSE,
      fix="Bind to loopback (\"127.0.0.1:6379:6379\"), or drop ports: and let other services reach it over the Compose network. "
          "Docker publishes ports through its own firewall rules, so host firewalls such as ufw do not block them.",
      references=["https://docs.docker.com/engine/network/packet-filtering-firewalls/"])
def compose_exposed_port(path, text, lines):
    info = compose_exposed_port.info
    entry = re.compile(r"""^\s*-\s*['"]?(?:(\[?[0-9a-fA-F.:]*\]?):)?(\d+)(?:-\d+)?:(\d+)(?:/\w+)?['"]?\s*(#.*)?$""")
    for f in line_matches(info, path, lines, entry):
        m = entry.match(lines[f.line - 1])
        ip, target = m.group(1), int(m.group(3))
        if target in EXPOSED_PORTS and ip in (None, "", "0.0.0.0", "[::]", "::"):
            f.detail = f"{EXPOSED_PORTS[target]} (port {target}) is published on every interface of the host."
            yield f
