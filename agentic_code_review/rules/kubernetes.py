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
        # A ${VAR} or $(VAR) is filled in at deploy time (envsubst, kustomize, Tekton), so the pin is not in this file.
        if "@sha256:" in ref or "*" in ref or ref.startswith("!") or "$" in ref:
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


@rule("ACR-K8S-013", "Container binds a port directly on the node (hostPort)", Severity.MEDIUM, "kubernetes", K8S,
      fix="Expose the workload through a Service (ClusterIP, or LoadBalancer/Ingress for outside traffic) instead of hostPort.",
      references=[PSS])
def host_port(path, text, lines):
    yield from line_matches(host_port.info, path, lines, re.compile(r"(^\s*-?\s*|[{,]\s*)hostPort\s*:\s*['\"]?[1-9]\d*"))


@rule("ACR-K8S-014", "Container sees the host's unmasked /proc (procMount: Unmasked)", Severity.HIGH, "kubernetes", K8S,
      fix="Remove procMount or set it to Default; the masked /proc hides kernel interfaces a container can abuse to escape.",
      references=[PSS])
def unmasked_proc(path, text, lines):
    yield from line_matches(unmasked_proc.info, path, lines, re.compile(r"\bprocMount\s*:\s*['\"]?Unmasked\b"))


@rule("ACR-K8S-015", "Ingress injects raw NGINX configuration through a snippet annotation", Severity.MEDIUM, "kubernetes", K8S,
      fix="Use the controller's dedicated annotations or a ConfigMap reviewed by the platform team, and keep "
          "allow-snippet-annotations off: snippets let anyone who can create an Ingress change the shared proxy.",
      references=["https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/annotations/"])
def nginx_snippet(path, text, lines):
    pat = re.compile(r"nginx\.ingress\.kubernetes\.io/(configuration|server|stream|auth)-snippet\s*:"
                     r"|allow-snippet-annotations\s*:\s*['\"]?true\b")
    yield from line_matches(nginx_snippet.info, path, lines, pat)


@rule("ACR-K8S-016", "Namespace switches Pod Security Admission to privileged", Severity.MEDIUM, "kubernetes", K8S,
      fix="Enforce baseline or restricted on application namespaces; keep privileged for the few system namespaces that need it.",
      references=["https://kubernetes.io/docs/concepts/security/pod-security-admission/"])
def psa_privileged(path, text, lines):
    pat = re.compile(r"pod-security\.kubernetes\.io/enforce\s*:\s*['\"]?privileged\b")
    yield from line_matches(psa_privileged.info, path, lines, pat)


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


# Escalation paths from the Kubernetes RBAC good-practices page: (verbs, resources, cluster roles only, why, severity).
# Operators routinely hold the last two, so they are worth a look in review rather than a failed build.
ESCALATIONS = [
    ({"escalate"}, None, False, "'escalate' lets it grant permissions it does not hold", Severity.HIGH),
    ({"bind"}, None, False, "'bind' lets it bind roles with permissions it does not hold", Severity.HIGH),
    ({"impersonate"}, None, False, "'impersonate' lets it act as other users, groups or service accounts", Severity.HIGH),
    (None, {"nodes/proxy"}, False, "nodes/proxy reaches the kubelet API, which can run commands in any pod on the node",
     Severity.HIGH),
    ({"create"}, {"serviceaccounts/token"}, False, "it can mint tokens for any service account it can name", Severity.HIGH),
    ({"update", "patch"}, {"certificatesigningrequests/approval"}, False, "it can approve its own client certificates",
     Severity.HIGH),
    ({"create", "update", "patch"}, {"mutatingwebhookconfigurations", "validatingwebhookconfigurations"}, False,
     "an admission webhook it controls sees, and can rewrite, every object the API server admits", Severity.MEDIUM),
    ({"get", "list", "watch"}, {"secrets"}, True, "it can read every Secret in the cluster; list and watch return values too",
     Severity.MEDIUM),
]


@rule("ACR-K8S-020", "RBAC grants a privilege-escalation path", Severity.HIGH, "kubernetes", ["kubernetes"],
      fix="Remove the permission, or narrow it with resourceNames to the exact objects the workload needs and bind it "
          "with a namespaced RoleBinding. If a controller truly needs it, run that controller in its own namespace and "
          "suppress the finding there with a reason.",
      references=["https://kubernetes.io/docs/concepts/security/rbac-good-practices/#privilege-escalation-risks"])
def rbac_escalation(path, text, lines):
    """Short of '*', a few permissions let a holder gain more than it was given; the API server documents them."""
    info = rbac_escalation.info
    for doc in _docs(text, {"Role", "ClusterRole"}):
        name = (doc.get("metadata") or {}).get("name", "")
        start = find_line(lines, re.compile(rf"^\s*name\s*:\s*['\"]?{re.escape(str(name))}['\"]?\s*$")) if name else 1
        for r in doc.get("rules") or []:
            verbs, resources = set(r.get("verbs") or []), set(r.get("resources") or [])
            if "*" in verbs or "*" in resources or r.get("resourceNames"):
                continue                                    # '*' is ACR-K8S-010; resourceNames scope it to named objects
            for want_verbs, want_resources, cluster_only, why, severity in ESCALATIONS:
                if cluster_only and doc["kind"] != "ClusterRole":
                    continue
                if (want_verbs is None or verbs & want_verbs) and (want_resources is None or resources & want_resources):
                    needle = sorted(resources & want_resources)[0] if want_resources else sorted(verbs & want_verbs)[0]
                    yield make(info, path, find_line(lines, re.compile(rf"\b{re.escape(needle)}\b"), start),
                               f"{doc['kind']} '{name}': {why}.", severity)


@rule("ACR-K8S-021", "Container keeps its default capabilities or may escalate privileges", Severity.LOW, "kubernetes",
      ["kubernetes"],
      fix="Under every container's securityContext set `allowPrivilegeEscalation: false` and `capabilities: {drop: [ALL]}`, "
          "adding back only the capabilities it needs. Pod Security's restricted profile requires both; without them a "
          "process that gets code execution starts with setuid binaries and a dozen capabilities to work with.",
      references=[PSS])
def restricted_profile_gaps(path, text, lines):
    info = restricted_profile_gaps.info
    for doc in _workloads(text):
        spec = _pod_spec(doc)
        for c in (spec.get("containers") or []) + (spec.get("initContainers") or []):
            sc = c.get("securityContext") or {}
            drops = [str(x).upper() for x in ((sc.get("capabilities") or {}).get("drop") or [])]
            missing = []
            if sc.get("allowPrivilegeEscalation") is not False:
                missing.append("allowPrivilegeEscalation: false")
            if "ALL" not in drops:
                missing.append("capabilities.drop: [ALL]")
            if missing:
                yield make(info, path, _container_line(lines, c.get("name")),
                           f"Container '{c.get('name')}' lacks {' and '.join(missing)}.")


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


# Services that ship without authentication by default; reachable from outside, anyone can use them.
UNAUTHENTICATED_PORTS = {11434: "Ollama API", 8265: "Ray dashboard/jobs API", 10001: "Ray client", 8888: "Jupyter",
                         6379: "Redis", 9200: "Elasticsearch", 27017: "MongoDB", 2375: "Docker API"}


@rule("ACR-K8S-017", "Unauthenticated service exposed outside the cluster", Severity.HIGH, "kubernetes", ["kubernetes"],
      fix="Keep it a ClusterIP Service and reach it through an authenticating proxy or VPN; if it must be public, restrict "
          "loadBalancerSourceRanges and turn on the service's own authentication.",
      references=["https://kubernetes.io/docs/concepts/services-networking/service/#publishing-services-service-types"])
def exposed_service(path, text, lines):
    info = exposed_service.info
    for doc in _docs(text, {"Service"}):
        spec = doc.get("spec") or {}
        if spec.get("type") not in ("LoadBalancer", "NodePort") or spec.get("loadBalancerSourceRanges"):
            continue
        for port in spec.get("ports") or []:
            nums = {p for p in (port.get("port"), port.get("targetPort")) if isinstance(p, int)}
            hit = sorted(nums & set(UNAUTHENTICATED_PORTS))
            if hit:
                name = (doc.get("metadata") or {}).get("name", "")
                yield make(info, path, find_line(lines, re.compile(rf"^\s*-?\s*(port|targetPort)\s*:\s*{hit[0]}\b")),
                           f"{spec['type']} Service '{name}' exposes {UNAUTHENTICATED_PORTS[hit[0]]} (port {hit[0]}).")


CREDENTIAL_KEY = re.compile(r"(?i)(password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credentials?)$")
CREDENTIAL_URL = re.compile(r"://[^/\s:@]+:[^/\s@]{3,}@")  # scheme://user:password@host


@rule("ACR-K8S-018", "Credential stored in a ConfigMap", Severity.HIGH, "secrets", ["kubernetes"],
      fix="Move it to a Secret (ideally an ExternalSecret or SealedSecret) and reference it with secretKeyRef. ConfigMaps "
          "are readable by anyone with get on configmaps and are never encrypted at rest.",
      references=["https://kubernetes.io/docs/concepts/configuration/configmap/"])
def configmap_credentials(path, text, lines):
    info = configmap_credentials.info
    for doc in _docs(text, {"ConfigMap"}):
        for key, value in (doc.get("data") or {}).items():
            v = str(value or "")
            if re.search(r"\{\{|\$\{|<|CHANGE|REPLACE", v, re.I):
                continue
            if (CREDENTIAL_KEY.search(str(key)) and len(v) >= 8) or CREDENTIAL_URL.search(v):
                yield make(info, path, find_line(lines, re.compile(rf"^\s*['\"]?{re.escape(str(key))}['\"]?\s*:")),
                           f"ConfigMap '{(doc.get('metadata') or {}).get('name', '')}' key '{key}' holds a credential (not shown).")


@rule("ACR-K8S-019", "NetworkPolicy allows all ingress traffic", Severity.MEDIUM, "kubernetes", ["kubernetes"],
      fix="Replace the empty ingress rule ({}) with from: selectors (podSelector / namespaceSelector) and ports for the "
          "callers that actually need access.",
      references=["https://kubernetes.io/docs/concepts/services-networking/network-policies/"])
def allow_all_ingress(path, text, lines):
    info = allow_all_ingress.info
    for doc in _docs(text, {"NetworkPolicy"}):
        rules = (doc.get("spec") or {}).get("ingress") or []
        if any(r == {} or r is None for r in rules):
            start = find_line(lines, re.compile(r"^\s*ingress\s*:"))
            yield make(info, path, find_line(lines, re.compile(r"^\s*-\s*\{\s*\}\s*(#.*)?$"), start),
                       f"NetworkPolicy '{(doc.get('metadata') or {}).get('name', '')}' admits traffic from every pod and namespace.")
