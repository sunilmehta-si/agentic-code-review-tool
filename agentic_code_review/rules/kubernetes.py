"""Kubernetes manifest rules: pod security, image pinning, resources and GPU scheduling.

Line-level checks need no parser. Structural checks (missing limits, missing runAsNonRoot)
use PyYAML when installed and are skipped quietly when it is not.
"""
from __future__ import annotations

import re

from ..models import Severity
from .base import find_line, line_matches, make, rule

K8S = ["kubernetes", "helm-template"]
PSS = "https://kubernetes.io/docs/concepts/security/pod-security-standards/"
POLICY_DOC = re.compile(r"^apiVersion:\s*(kyverno\.io|templates\.gatekeeper\.sh|constraints\.gatekeeper\.sh)/", re.M)
WORKLOADS = {"Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob"}


@rule("ACR-K8S-001", "Privileged container or privilege escalation allowed", Severity.CRITICAL, "kubernetes", K8S,
      fix="Set privileged: false and allowPrivilegeEscalation: false; add only the specific capability you need.",
      references=[PSS])
def privileged(path, text, lines):
    pat = re.compile(r"^\s*(privileged|allowPrivilegeEscalation)\s*:\s*true\b")
    yield from line_matches(privileged.info, path, lines, pat)


@rule("ACR-K8S-002", "Pod shares the host's network, PID or IPC namespace", Severity.HIGH, "kubernetes", K8S,
      fix="Remove hostNetwork/hostPID/hostIPC; expose the workload through a Service instead.", references=[PSS])
def host_namespaces(path, text, lines):
    pat = re.compile(r"^\s*(hostNetwork|hostPID|hostIPC)\s*:\s*true\b")
    yield from line_matches(host_namespaces.info, path, lines, pat)


@rule("ACR-K8S-003", "hostPath volume mounts the node's filesystem", Severity.HIGH, "kubernetes", K8S,
      fix="Use a PersistentVolumeClaim, emptyDir or a CSI volume instead of hostPath.", references=[PSS])
def host_path(path, text, lines):
    info = host_path.info
    sock = re.compile(r"\b(docker|containerd|crio|cri-dockerd)\.sock\b")
    for f in line_matches(info, path, lines, re.compile(r"(^\s*|[{,]\s*)hostPath\s*:")):
        # Mounting the container runtime's socket hands the pod the whole node, so it is critical.
        if sock.search("\n".join(lines[f.line - 1:f.line + 3])):
            f.severity = Severity.CRITICAL
            f.detail = "The container runtime socket is mounted: anything in this pod can start privileged containers on the node."
        yield f


@rule("ACR-K8S-004", "Dangerous Linux capability added", Severity.HIGH, "kubernetes", K8S,
      fix="Drop ALL capabilities and add back only what the process needs (rarely more than NET_BIND_SERVICE).",
      references=[PSS])
def capabilities(path, text, lines):
    pat = re.compile(r"\b(SYS_ADMIN|NET_ADMIN|SYS_PTRACE|SYS_MODULE|NET_RAW|DAC_READ_SEARCH|\"?ALL\"?)\b")
    in_add = False
    for i, line in enumerate(lines, start=1):
        if re.match(r"^\s*add\s*:", line):
            in_add = True
            if pat.search(line.split(":", 1)[1]):
                yield make(capabilities.info, path, i)
            continue
        if in_add:
            if re.match(r"^\s*-\s*", line) and pat.search(line):
                yield make(capabilities.info, path, i)
            elif not re.match(r"^\s*-", line):
                in_add = False


@rule("ACR-K8S-005", "Container image not pinned (latest or no tag)", Severity.MEDIUM, "kubernetes", K8S,
      fix="Pin images to an immutable digest (image@sha256:...) or at least a specific version tag.")
def image_pin(path, text, lines):
    info = image_pin.info
    if POLICY_DOC.search(text):
        return  # Kyverno/Gatekeeper policies contain image *patterns* that enforce pinning, not images
    pat = re.compile(r"^\s*-?\s*image\s*:\s*['\"]?([^'\"\s#]+)")
    for i, line in enumerate(lines, start=1):
        m = pat.match(line)
        if not m or "{{" in line:
            continue
        ref = m.group(1)
        if "@sha256:" in ref or "*" in ref or ref.startswith("!"):
            continue
        name = ref.rsplit("/", 1)[-1]
        if ":" not in name or name.endswith(":latest"):
            yield make(info, path, i, f"Image '{ref}' can change underneath you.")


@rule("ACR-K8S-006", "Container runs as root (UID 0)", Severity.HIGH, "kubernetes", K8S,
      fix="Set securityContext.runAsNonRoot: true and a non-zero runAsUser.", references=[PSS])
def run_as_root(path, text, lines):
    yield from line_matches(run_as_root.info, path, lines,
                            re.compile(r"^\s*runAsUser\s*:\s*0\b|^\s*runAsNonRoot\s*:\s*false\b"))


@rule("ACR-K8S-012", "Seccomp or AppArmor confinement turned off", Severity.HIGH, "kubernetes", K8S,
      fix="Use seccompProfile: { type: RuntimeDefault } (and the runtime's default AppArmor profile); write a Localhost "
          "profile if a workload needs an extra syscall instead of disabling filtering.",
      references=[PSS, "https://kubernetes.io/docs/tutorials/security/seccomp/"])
def unconfined(path, text, lines):
    pat = re.compile(r"^\s*type\s*:\s*['\"]?Unconfined\b"
                     r"|(seccomp|apparmor)\.security\.(alpha|beta)\.kubernetes\.io/[^:\s]*\s*:\s*['\"]?unconfined\b", re.I)
    yield from line_matches(unconfined.info, path, lines, pat)


def _workloads(text: str):
    try:
        import yaml  # optional dependency
    except ImportError:
        return []
    try:
        docs = [d for d in yaml.safe_load_all(text) if isinstance(d, dict)]
    except yaml.YAMLError:
        return []
    return [d for d in docs if d.get("kind") in WORKLOADS]


def _container_line(lines: list[str], name) -> int:
    """Line of the container's own list entry ('- name: x'), not the workload's metadata name."""
    return find_line(lines, re.compile(rf"^\s*-\s*name\s*:\s*['\"]?{re.escape(str(name))}['\"]?\s*(#.*)?$"))


def _pod_spec(doc: dict) -> dict:
    spec = doc.get("spec") or {}
    if doc.get("kind") == "Pod":
        return spec
    if doc.get("kind") == "CronJob":
        spec = ((spec.get("jobTemplate") or {}).get("spec") or {})
    return ((spec.get("template") or {}).get("spec") or {})


@rule("ACR-K8S-007", "Container has no CPU/memory limits", Severity.MEDIUM, "kubernetes", ["kubernetes"],
      fix="Set resources.requests and resources.limits (at least memory) so one pod cannot starve the node.")
def limits(path, text, lines):
    for doc in _workloads(text):
        for c in (_pod_spec(doc).get("containers") or []):
            res = c.get("resources") or {}
            if not (res.get("limits") or {}).get("memory"):
                yield make(limits.info, path, _container_line(lines, c.get('name')),
                           f"Container '{c.get('name')}' has no memory limit.")


@rule("ACR-K8S-008", "GPU requested without a matching limit", Severity.MEDIUM, "kubernetes", ["kubernetes"],
      fix="Kubernetes schedules GPUs from limits: set limits: nvidia.com/gpu (equal to requests), and use taints/tolerations "
          "to keep GPU nodes for GPU work.",
      references=["https://kubernetes.io/docs/tasks/manage-gpus/scheduling-gpus/"])
def gpu(path, text, lines):
    for doc in _workloads(text):
        for c in (_pod_spec(doc).get("containers") or []):
            res = c.get("resources") or {}
            req = {k for k in (res.get("requests") or {}) if k.endswith("/gpu")}
            lim = {k for k in (res.get("limits") or {}) if k.endswith("/gpu")}
            if req - lim:
                yield make(gpu.info, path, find_line(lines, re.compile(r"/gpu\s*:")),
                           f"Container '{c.get('name')}' requests {', '.join(sorted(req - lim))} only under requests.")


@rule("ACR-K8S-009", "Pod does not require a non-root user", Severity.LOW, "kubernetes", ["kubernetes"],
      fix="Add securityContext.runAsNonRoot: true at pod or container level.", references=[PSS])
def non_root_missing(path, text, lines):
    for doc in _workloads(text):
        spec = _pod_spec(doc)
        pod_ok = (spec.get("securityContext") or {}).get("runAsNonRoot") is True
        for c in (spec.get("containers") or []):
            if not pod_ok and (c.get("securityContext") or {}).get("runAsNonRoot") is not True:
                yield make(non_root_missing.info, path, _container_line(lines, c.get('name')),
                           f"Container '{c.get('name')}' may run as root.")


def _docs(text: str, kinds: set[str]):
    try:
        import yaml
    except ImportError:
        return []
    try:
        return [d for d in yaml.safe_load_all(text) if isinstance(d, dict) and d.get("kind") in kinds]
    except yaml.YAMLError:
        return []


@rule("ACR-K8S-010", "RBAC grants wildcard permissions or cluster-admin", Severity.HIGH, "kubernetes", ["kubernetes"],
      fix="Grant only the verbs and resources the workload uses, in its own namespace (Role, not ClusterRole), and never bind service accounts to cluster-admin.",
      references=["https://kubernetes.io/docs/concepts/security/rbac-good-practices/"])
def rbac_wildcard(path, text, lines):
    info = rbac_wildcard.info
    for doc in _docs(text, {"Role", "ClusterRole"}):
        name = (doc.get("metadata") or {}).get("name", "")
        for r in doc.get("rules") or []:
            wild = [k for k in ("verbs", "resources", "apiGroups") if "*" in (r.get(k) or [])]
            if wild and wild != ["apiGroups"]:
                yield make(info, path, find_line(lines, re.compile(r"^\s*-?\s*(verbs|resources)\s*:.*\*")),
                           f"{doc['kind']} '{name}' uses '*' in {', '.join(wild)}.")
    for doc in _docs(text, {"ClusterRoleBinding", "RoleBinding"}):
        if (doc.get("roleRef") or {}).get("name") == "cluster-admin":
            yield make(info, path, find_line(lines, "cluster-admin"),
                       f"{doc['kind']} '{(doc.get('metadata') or {}).get('name', '')}' hands out cluster-admin.")


@rule("ACR-K8S-011", "Kubernetes Secret with real values committed to git", Severity.HIGH, "secrets", ["kubernetes"],
      fix="Secrets are only base64-encoded. Commit a SealedSecret, SOPS-encrypted file or ExternalSecret reference instead, and rotate this value.",
      references=["https://kubernetes.io/docs/concepts/security/secrets-good-practices/"])
def committed_secret(path, text, lines):
    info = committed_secret.info
    for doc in _docs(text, {"Secret"}):
        values = {**(doc.get("data") or {}), **(doc.get("stringData") or {})}
        real = [k for k, v in values.items() if v not in (None, "") and not re.search(r"\{\{|\$\{|<|CHANGE|REPLACE", str(v), re.I)]
        if real:
            yield make(info, path, find_line(lines, re.compile(r"^\s*(data|stringData)\s*:")),
                       f"Secret '{(doc.get('metadata') or {}).get('name', '')}' holds {len(real)} literal value(s) (not shown).")
