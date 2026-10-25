"""Dockerfile rules: base image pinning, root user, remote downloads and baked-in secrets."""
from __future__ import annotations

import re

from ..models import Severity
from .base import line_matches, make, rule

DF = ["dockerfile"]
CIS = "https://docs.docker.com/build/building/best-practices/"


@rule("ACR-DOCKER-001", "Base image not pinned (latest or no tag)", Severity.MEDIUM, "container", DF,
      fix="Pin the base image to a version and, ideally, a digest: FROM python:3.12-slim@sha256:...", references=[CIS])
def base_pin(path, text, lines):
    info = base_pin.info
    stages = set()
    for i, line in enumerate(lines, start=1):
        m = re.match(r"^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?", line, re.I)
        if not m:
            continue
        ref, alias = m.group(1), m.group(2)
        if alias:
            stages.add(alias.lower())
        if ref.lower() in stages or ref.lower() == "scratch" or "@sha256:" in ref or "$" in ref:
            continue
        name = ref.rsplit("/", 1)[-1]
        if ":" not in name or name.endswith(":latest"):
            yield make(info, path, i, f"'{ref}' can change between builds.")


@rule("ACR-DOCKER-002", "Image runs as root (no USER instruction)", Severity.MEDIUM, "container", DF,
      fix="Create an unprivileged user and switch to it before CMD/ENTRYPOINT: USER 10001.", references=[CIS])
def root_user(path, text, lines):
    info = root_user.info
    users = [(i, l) for i, l in enumerate(lines, start=1) if re.match(r"^\s*USER\s+", l, re.I)]
    if not users:
        last_from = max((i for i, l in enumerate(lines, start=1) if re.match(r"^\s*FROM\s", l, re.I)), default=1)
        yield make(info, path, last_from, "The final stage never switches away from root.")
        return
    i, l = users[-1]
    if re.match(r"^\s*USER\s+(root|0)(:|\s|$)", l, re.I):
        yield make(info, path, i, "The last USER instruction is root.")


@rule("ACR-DOCKER-003", "Remote script piped straight into a shell", Severity.HIGH, "container", DF,
      fix="Download to a file, verify its checksum or signature, then run it, or install from a package manager.")
def curl_pipe(path, text, lines):
    pat = re.compile(r"\b(curl|wget)\b[^|\n]*\|\s*(sudo\s+)?(ba|z|da)?sh\b")
    yield from line_matches(curl_pipe.info, path, lines, pat)


@rule("ACR-DOCKER-004", "ADD fetches a remote URL", Severity.LOW, "container", DF,
      fix="Use COPY for local files; for remote files, download with checksum verification in a RUN step.",
      references=[CIS])
def add_url(path, text, lines):
    yield from line_matches(add_url.info, path, lines, re.compile(r"^\s*ADD\s+(--\S+\s+)*https?://", re.I))


@rule("ACR-DOCKER-005", "Secret baked into the image via ENV or ARG", Severity.HIGH, "container", DF,
      fix="Use BuildKit secrets (RUN --mount=type=secret) at build time and inject runtime secrets from the platform.",
      references=["https://docs.docker.com/build/building/secrets/"])
def secret_env(path, text, lines):
    pat = re.compile(r"^\s*(ENV|ARG)\s+\w*(PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY)\w*(\s*=\s*|\s+)\S+", re.I)
    yield from line_matches(secret_env.info, path, lines, pat)


@rule("ACR-DOCKER-006", "Package manager cache or sudo left in the image", Severity.LOW, "container", DF,
      fix="Use apt-get install --no-install-recommends ... && rm -rf /var/lib/apt/lists/*, and don't install sudo.")
def apt_hygiene(path, text, lines):
    info = apt_hygiene.info
    for i, line in enumerate(lines, start=1):
        if re.search(r"\bapt-get\s+install\b", line) and "rm -rf /var/lib/apt/lists" not in text:
            yield make(info, path, i, "apt lists are never cleaned, which bloats the image and widens the attack surface.")
        elif re.search(r"\b(apt-get|apk|yum|dnf)\s+(install|add)\b.*\bsudo\b", line):
            yield make(info, path, i, "sudo inside a container is almost never needed.")


@rule("ACR-DOCKER-007", "World-writable permissions set in the image", Severity.MEDIUM, "container", DF,
      fix="Give ownership to the runtime user (COPY --chown / chown) and use 755 for directories and 644 for files.")
def world_writable(path, text, lines):
    pat = re.compile(r"\bchmod\s+(-R\s+)?(0?777|a\+w|o\+w|ugo\+w)\b|--chmod=0?777\b")
    yield from line_matches(world_writable.info, path, lines, pat)


@rule("ACR-DOCKER-008", "TLS or package signature checks disabled during the build", Severity.HIGH, "container", DF,
      fix="Keep verification on. Add the private CA to the image (COPY ca.crt + update-ca-certificates) or use a trusted "
          "mirror instead of skipping checks; a man-in-the-middle can otherwise swap what gets installed.")
def build_verification_off(path, text, lines):
    pat = re.compile(r"\bcurl\b[^|\n]*\s(-[a-zA-Z]*k[a-zA-Z]*|--insecure)\b|\bwget\b[^|\n]*--no-check-certificate"
                     r"|--trusted-host\b|strict-ssl\s+false|--allow-untrusted\b|--allow-unauthenticated\b|--nogpgcheck\b"
                     r"|http\.sslVerify\s+false|GIT_SSL_NO_VERIFY|PIP_TRUSTED_HOST", re.I)
    yield from line_matches(build_verification_off.info, path, lines, pat)


@rule("ACR-DOCKER-009", "Credential file copied into the image", Severity.HIGH, "container", DF,
      fix="Never COPY credential files: anyone who can pull the image can read every layer. Use RUN --mount=type=secret "
          "for build-time credentials and inject runtime secrets from the platform; add the files to .dockerignore.",
      references=["https://docs.docker.com/build/building/secrets/"])
def copied_credentials(path, text, lines):
    pat = re.compile(r"^\s*(COPY|ADD)\s+(--\S+\s+)*[^\n]*?(?<=[\s/])(\.env(?![\w.-]*(example|sample|template))[\w.-]*|id_rsa|id_ecdsa|id_ed25519"
                     r"|\.npmrc|\.pypirc|\.netrc|\.git-credentials|\.aws/?|\.ssh/?|[\w.-]*\.key|credentials\.json|[\w.-]*\.tfstate)(\s|$)",
                     re.I)
    yield from line_matches(copied_credentials.info, path, lines, pat)


@rule("ACR-DOCKER-010", "SSH server installed or exposed in the image", Severity.MEDIUM, "container", DF,
      fix="Don't run sshd in containers; use docker exec / kubectl exec (or an ephemeral debug container) for access, "
          "so there are no long-lived keys or passwords in the image.",
      references=[CIS])
def ssh_in_image(path, text, lines):
    pat = re.compile(r"\b(apt-get|apt|apk|yum|dnf|microdnf|zypper)\b[^\n]*\b(install|add)\b[^\n]*\bopenssh-server\b"
                     r"|^\s*EXPOSE\s+([^\n#]*\s)?22(/tcp)?(\s|$)", re.I)
    yield from line_matches(ssh_in_image.info, path, lines, pat)


@rule("ACR-DOCKER-011", "Stage copies from an external image not pinned (latest or no tag)", Severity.MEDIUM, "container", DF,
      fix="Pin the image a COPY --from takes files from, ideally by digest: COPY --from=ghcr.io/astral-sh/uv:0.13.5@sha256:... "
          "The copied binary runs in your image with none of the base-image checks applied to it.",
      references=[CIS])
def copy_from_pin(path, text, lines):
    info = copy_from_pin.info
    stages = {m.group(1).lower() for l in lines for m in [re.match(r"^\s*FROM\s+(?:--platform=\S+\s+)?\S+\s+AS\s+(\S+)", l, re.I)] if m}
    for i, line in enumerate(lines, start=1):
        m = re.match(r"^\s*COPY\s+(?:--[\w-]+(?:=\S+)?\s+)*--from=(\S+)", line, re.I)
        if not m:
            continue
        ref = m.group(1).strip("\"'")
        if ref.lower() in stages or ref.isdigit() or "@sha256:" in ref or "$" in ref:
            continue
        name = ref.rsplit("/", 1)[-1]
        if ":" not in name or name.endswith(":latest"):
            yield make(info, path, i, f"'{ref}' can change between builds.")
