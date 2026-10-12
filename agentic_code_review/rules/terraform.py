"""Terraform rules for AWS, Azure and GCP: exposure, public data, encryption, IAM and cluster endpoints.

A light block splitter is enough here: each check reports the exact line that sets the risky value.
"""
from __future__ import annotations

import re

from ..models import Severity
from .base import line_matches, make, rule

TF = ["terraform"]
SENSITIVE_PORTS = {22, 3389, 3306, 5432, 1433, 27017, 6379, 9200, 5601, 2375, 2376, 6443, 10250}
OPEN_CIDR = re.compile(r"""(cidr_blocks|ipv6_cidr_blocks|source_ranges|source_address_prefix(es)?|cidr_ipv4)\s*=\s*\[?\s*["'](0\.0\.0\.0/0|::/0|\*|Internet)["']""")


def _blocks(lines: list[str]):
    """Yield (start_line, end_line, header) for each top-level block."""
    depth, start, header = 0, None, ""
    for i, line in enumerate(lines, start=1):
        if depth == 0 and re.match(r'^\s*(resource|module|data)\s+"', line):
            start, header = i, line.strip()
        depth += line.count("{") - line.count("}")
        if start is not None and depth == 0:
            yield start, i, header
            start = None


def _ports(block: str) -> set[int]:
    ports: set[int] = set()
    for a, b in re.findall(r"from_port\s*=\s*(\d+)[\s\S]*?to_port\s*=\s*(\d+)", block):
        lo, hi = int(a), int(b)
        ports.update(range(lo, min(hi, 65535) + 1) if hi - lo < 70000 else [])
    for spec in re.findall(r'destination_port_ranges?\s*=\s*\[?([^\]\n]+)', block):
        for part in re.findall(r'"([\d*\-]+)"', spec):
            if part == "*":
                ports.update(range(0, 65536))
            elif "-" in part:
                lo, hi = map(int, part.split("-"))
                ports.update(range(lo, hi + 1))
            elif part.isdigit():
                ports.add(int(part))
    for p in re.findall(r'ports\s*=\s*\[([^\]]+)\]', block):
        ports.update(int(x) for x in re.findall(r'"(\d+)"', p))
    return ports


ALL_PORTS = re.compile(r'\b(ip_)?protocol\s*=\s*"(-1|all)"', re.I)  # AWS "-1" / GCP "all": every port, every protocol


def _nested(lines: list[str], start: int, end: int, name: str):
    """(start, end) of each `name { ... }` block nested inside lines start..end."""
    i = start
    while i <= end:
        if re.match(rf"^\s*{name}\s*\{{", lines[i - 1]):
            depth = 0
            for j in range(i, end + 1):
                depth += lines[j - 1].count("{") - lines[j - 1].count("}")
                if depth <= 0:
                    yield i, j
                    i = j
                    break
        i += 1


@rule("ACR-TF-001", "Sensitive port open to the whole internet", Severity.CRITICAL, "iac", TF,
      fix="Restrict the source to known CIDRs, a bastion, or a private endpoint/VPN. Never expose SSH, RDP, databases or the Kubernetes API to 0.0.0.0/0.")
def open_ingress(path, text, lines):
    info = open_ingress.info
    for start, end, header in _blocks(lines):
        if not re.search(r"security_group|firewall|network_security|nsg|security_rule", header, re.I):
            continue
        block = "\n".join(lines[start - 1:end])
        if re.search(r'(type|direction)\s*=\s*"(egress|Outbound)"', block, re.I) or "egress_rule" in header:
            continue
        # Inline ingress blocks are judged one by one, so an open egress block never counts against them.
        units = list(_nested(lines, start, end, "ingress")) or [(start, end)]
        for s, e in units:
            unit = "\n".join(lines[s - 1:e])
            exposed = SENSITIVE_PORTS if ALL_PORTS.search(unit) else _ports(unit) & SENSITIVE_PORTS
            if not exposed:
                continue
            what = "Every port is" if ALL_PORTS.search(unit) else f"Ports {sorted(exposed)[:6]} are"
            for i in range(s, e + 1):
                if OPEN_CIDR.search(lines[i - 1]) and not (units == [(start, end)] and _in_egress(lines, start, end, i)):
                    yield make(info, path, i, f"{what} reachable from anywhere.")


def _in_egress(lines: list[str], start: int, end: int, line: int) -> bool:
    return any(s <= line <= e for s, e in _nested(lines, start, end, "egress"))


@rule("ACR-TF-002", "Storage or data service exposed publicly", Severity.HIGH, "iac", TF,
      fix="Keep buckets/accounts private, block public access, and reach data services through private endpoints.")
def public_data(path, text, lines):
    pat = re.compile(r'acl\s*=\s*"public-read(-write)?"|allow_nested_items_to_be_public\s*=\s*true|allow_blob_public_access\s*=\s*true'
                     r'|public_network_access_enabled\s*=\s*true|"all(Authenticated)?Users"|publicly_accessible\s*=\s*true'
                     r'|block_public_(acls|policy)\s*=\s*false')
    yield from line_matches(public_data.info, path, lines, pat)


@rule("ACR-TF-003", "Encryption or TLS weakened", Severity.HIGH, "iac", TF,
      fix="Enable encryption at rest, require HTTPS, and set the minimum TLS version to 1.2.")
def encryption(path, text, lines):
    pat = re.compile(r'\b(encrypted|storage_encrypted|enable_https_traffic_only|https_traffic_only_enabled|encryption_at_host_enabled)\s*=\s*false'
                     r'|min(imum)?_tls_version\s*=\s*"(TLS1_0|TLS1_1|1\.0|1\.1|TLSv1|TLSv1\.1)"')
    yield from line_matches(encryption.info, path, lines, pat)


@rule("ACR-TF-004", "Wildcard or owner-level IAM permission", Severity.HIGH, "iac", TF,
      fix="Grant specific actions on specific resources; avoid Owner/Contributor and '*' at subscription or account scope.")
def iam_wildcard(path, text, lines):
    pat = re.compile(r'"Action"\s*:\s*"\*"|\bactions\s*=\s*\[\s*"\*"\s*\]|role_definition_name\s*=\s*"Owner"|role\s*=\s*"roles/(owner|editor)"')
    yield from line_matches(iam_wildcard.info, path, lines, pat)


@rule("ACR-TF-005", "Kubernetes control plane reachable from the internet or legacy auth on", Severity.MEDIUM, "iac", TF,
      fix="Use a private cluster (or restrict authorised IP ranges), disable local/legacy accounts and use cloud IAM for access.")
def cluster_endpoint(path, text, lines):
    pat = re.compile(r'endpoint_public_access\s*=\s*true|private_cluster_enabled\s*=\s*false|enable_legacy_abac\s*=\s*true'
                     r'|local_account_disabled\s*=\s*false')
    yield from line_matches(cluster_endpoint.info, path, lines, pat)


@rule("ACR-TF-006", "Module source not pinned to a version", Severity.LOW, "iac", TF,
      fix="Pin git modules with ?ref=<tag-or-sha> and registry modules with version = \"x.y.z\".")
def module_pin(path, text, lines):
    info = module_pin.info
    for start, end, header in _blocks(lines):
        if not header.startswith("module"):
            continue
        block = "\n".join(lines[start - 1:end])
        src = re.search(r'source\s*=\s*"([^"]+)"', block)
        if not src or src.group(1).startswith(("./", "../")):
            continue
        s = src.group(1)
        pinned = "?ref=" in s if s.startswith(("git::", "github.com", "git@")) else bool(re.search(r"^\s*version\s*=", block, re.M))
        if not pinned:
            yield make(info, path, start, f"Module source '{s}' is not pinned.")


@rule("ACR-TF-007", "Database can be destroyed without protection or a final backup", Severity.MEDIUM, "iac", TF,
      fix="Set deletion_protection = true and keep a final snapshot (skip_final_snapshot = false) on stateful data stores.")
def db_protection(path, text, lines):
    pat = re.compile(r"\bdeletion_protection(_enabled)?\s*=\s*false|\bskip_final_snapshot\s*=\s*true|\bprevent_destroy\s*=\s*false")
    yield from line_matches(db_protection.info, path, lines, pat)


@rule("ACR-TF-008", "Instance metadata reachable without session tokens (credential theft via SSRF)", Severity.MEDIUM, "iac", TF,
      fix="Require IMDSv2 (metadata_options { http_tokens = \"required\" }) on AWS, and use GKE Workload Identity "
          "(workload_metadata_config { mode = \"GKE_METADATA\" }) so pods cannot read node credentials.",
      references=["https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html",
                  "https://cloud.google.com/kubernetes-engine/docs/how-to/protecting-cluster-metadata"])
def instance_metadata(path, text, lines):
    pat = re.compile(r'\bhttp_tokens\s*=\s*"optional"|\bmode\s*=\s*"GCE_METADATA"|"?disable-legacy-endpoints"?\s*=\s*"?false"?'
                     r'|\bnode_metadata\s*=\s*"(EXPOSE|UNSPECIFIED)"')
    yield from line_matches(instance_metadata.info, path, lines, pat)
