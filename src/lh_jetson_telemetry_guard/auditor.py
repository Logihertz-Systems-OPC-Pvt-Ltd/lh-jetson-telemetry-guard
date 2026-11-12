# ==============================================================================
# Product:       Logihertz Jetson Telemetry Guard (lh-jetson-telemetry-guard)
# Module:        auditor.py
# Role:          10-Rule Deterministic BSP Telemetry Posture Auditor & Scoring
# Organization:  Logihertz Systems (OPC) Private Limited
# Developer:     Sameer Tawade (Creator, Founder, Director & Sole Developer)
# Contact:       ops@logihertz.com / security@logihertz.com
# License:       Apache-2.0
# ==============================================================================

"""10-Rule deterministic sovereign air-gap telemetry auditor and posture scoring engine."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

PUBLIC_DNS_RESOLVERS: frozenset[str] = frozenset({
    "8.8.8.8",
    "8.8.4.4",
    "1.1.1.1",
    "1.0.0.1",
    "9.9.9.9",
    "149.112.112.112",
    "208.67.222.222",
    "208.67.220.220",
})


@dataclass(frozen=True)
class RuleDefinition:
    """Normative security rule definition."""

    id: str
    name: str
    severity: str
    cwe: str
    weight: int
    description: str
    remediation: str


RULE_REGISTRY: tuple[RuleDefinition, ...] = (
    RuleDefinition(
        id="LH-JTG-001",
        name="Active Vendor Telemetry or Crash-Reporting Daemons",
        severity="CRITICAL",
        cwe="CWE-200",
        weight=25,
        description="Active vendor telemetry, crash collection, or metrics daemons running (e.g. whoopsie, apport, nv-telemetry).",
        remediation="Stop, disable, and mask all telemetry daemons using `systemctl mask whoopsie apport ubuntu-report nv-telemetry`.",
    ),
    RuleDefinition(
        id="LH-JTG-002",
        name="Permissive Outbound WAN Firewall Policy",
        severity="CRITICAL",
        cwe="CWE-284",
        weight=25,
        description="Egress default firewall policy is not set to DROP or eBPF socket connect guard is disabled.",
        remediation="Configure nftables chain output with policy drop and deploy eBPF cgroup/connect4 socket filter.",
    ),
    RuleDefinition(
        id="LH-JTG-003",
        name="Vendor Telemetry Domains Unsinkholed",
        severity="CRITICAL",
        cwe="CWE-359",
        weight=25,
        description="Known vendor phone-home and telemetry domains are not sinkholed in /etc/hosts (fewer than 10 blocked entries).",
        remediation="Populate /etc/hosts with 0.0.0.0 and :: sinkhole entries for all NVIDIA and Canonical telemetry endpoints.",
    ),
    RuleDefinition(
        id="LH-JTG-004",
        name="Uncontrolled Background Auto-Update Timers",
        severity="HIGH",
        cwe="CWE-300",
        weight=10,
        description="Background periodic auto-update or MOTD phone-home timers are enabled on embedded appliance.",
        remediation="Mask apt-daily.timer, apt-daily-upgrade.timer, and motd-news.timer to enforce deterministic manual updates.",
    ),
    RuleDefinition(
        id="LH-JTG-005",
        name="HTTP Captive-Portal Connectivity Checks Enabled",
        severity="HIGH",
        cwe="CWE-200",
        weight=10,
        description="NetworkManager or systemd connectivity probe is enabled, sending periodic unencrypted HTTP requests to public endpoints.",
        remediation="Set [connectivity] enabled=false in NetworkManager.conf or systemd network configuration.",
    ),
    RuleDefinition(
        id="LH-JTG-006",
        name="Unauthorized External Public DNS Resolvers Configured",
        severity="HIGH",
        cwe="CWE-319",
        weight=10,
        description="External public DNS resolvers (e.g. 8.8.8.8, 1.1.1.1) configured or external DNS allowed, leaking internal queries.",
        remediation="Pin DNS resolution exclusively to local sovereign, authenticated internal nameservers.",
    ),
    RuleDefinition(
        id="LH-JTG-007",
        name="Active Snapd or Cloud-Init Phone-Home Services",
        severity="HIGH",
        cwe="CWE-400",
        weight=10,
        description="Canonical snapd or cloud-init phone-home services active on sovereign embedded appliance.",
        remediation="Mask or purge snapd.service and cloud-init to eliminate non-deterministic cloud metadata telemetry.",
    ),
    RuleDefinition(
        id="LH-JTG-008",
        name="Unsanitized Container Runtime or CUDA/TensorRT Telemetry",
        severity="MEDIUM",
        cwe="CWE-200",
        weight=4,
        description="Docker telemetry is not disabled or CUDA/TensorRT developer telemetry opt-out flag is not set.",
        remediation="Configure docker daemon.json with telemetry: false and export NVIDIA_VISIBLE_DEVICES / CUDA opt-out flags.",
    ),
    RuleDefinition(
        id="LH-JTG-009",
        name="External Core Dump Transmission or Insecure Dumpability",
        severity="MEDIUM",
        cwe="CWE-215",
        weight=4,
        description="System core dumps configured for external upload or fs.suid_dumpable is not set to 0.",
        remediation="Disable crash uploads in systemd-coredump and set sysctl fs.suid_dumpable = 0.",
    ),
    RuleDefinition(
        id="LH-JTG-010",
        name="Missing Egress Drop Audit Logging or Public NTP Pool",
        severity="LOW",
        cwe="CWE-778",
        weight=1,
        description="Firewall egress drops are not logged to kernel telemetry or unauthenticated public NTP pool is used.",
        remediation="Enable nftables drop logging with prefix [LH-EGRESS-DROP] and pin NTP to an internal sovereign timeserver.",
    ),
)


@dataclass
class Finding:
    """An individual security finding detected during BSP posture evaluation."""

    rule_id: str
    rule_name: str
    severity: str
    weight: int
    cwe: str
    message: str
    remediation: str


@dataclass
class AuditReport:
    """Comprehensive posture audit evaluation report."""

    manifest_path: str
    score: int
    status: str
    total_rules: int
    passed_rules: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    findings: list[Finding] = field(default_factory=list)


def audit_bsp_policy(policy_data: dict[str, Any], manifest_path: str = "") -> AuditReport:
    """Evaluate an NVIDIA Jetson / Embedded BSP policy manifest against all 10 security rules.

    Args:
        policy_data: Parsed dictionary from BSP policy JSON manifest.
        manifest_path: Optional path string of the policy file.

    Returns:
        AuditReport instance with computed score and detailed findings.
    """
    findings: list[Finding] = []

    # Rule 1: LH-JTG-001 (CRITICAL, 25)
    active_services = policy_data.get("active_telemetry_services", [])
    if active_services:
        services_str = ", ".join(str(s) for s in active_services)
        findings.append(Finding(
            rule_id="LH-JTG-001",
            rule_name=RULE_REGISTRY[0].name,
            severity="CRITICAL",
            weight=25,
            cwe="CWE-200",
            message=f"Active telemetry or crash-reporting services detected: [{services_str}].",
            remediation=RULE_REGISTRY[0].remediation,
        ))

    # Rule 2: LH-JTG-002 (CRITICAL, 25)
    egress_policy = str(policy_data.get("egress_default_policy", "")).upper()
    ebpf_enabled = bool(policy_data.get("ebpf_socket_guard_enabled", False))
    if egress_policy != "DROP" or not ebpf_enabled:
        findings.append(Finding(
            rule_id="LH-JTG-002",
            rule_name=RULE_REGISTRY[1].name,
            severity="CRITICAL",
            weight=25,
            cwe="CWE-284",
            message=f"egress_default_policy is '{egress_policy}' and ebpf_socket_guard_enabled={ebpf_enabled}. Must be DROP with eBPF guard enabled.",
            remediation=RULE_REGISTRY[1].remediation,
        ))

    # Rule 3: LH-JTG-003 (CRITICAL, 25)
    domains_sinkholed = bool(policy_data.get("telemetry_domains_sinkholed", False))
    blocked_count = int(policy_data.get("blocked_hosts_count", 0))
    if not domains_sinkholed or blocked_count < 10:
        findings.append(Finding(
            rule_id="LH-JTG-003",
            rule_name=RULE_REGISTRY[2].name,
            severity="CRITICAL",
            weight=25,
            cwe="CWE-359",
            message=f"telemetry_domains_sinkholed={domains_sinkholed} and blocked_hosts_count={blocked_count} (minimum 10 required).",
            remediation=RULE_REGISTRY[2].remediation,
        ))

    # Rule 4: LH-JTG-004 (HIGH, 10)
    unattended = bool(policy_data.get("unattended_upgrades_enabled", False))
    apt_daily = bool(policy_data.get("apt_daily_timer_enabled", False))
    motd_news = bool(policy_data.get("motd_news_enabled", False))
    if unattended or apt_daily or motd_news:
        findings.append(Finding(
            rule_id="LH-JTG-004",
            rule_name=RULE_REGISTRY[3].name,
            severity="HIGH",
            weight=10,
            cwe="CWE-300",
            message=f"Background auto-timers enabled: unattended_upgrades={unattended}, apt_daily={apt_daily}, motd_news={motd_news}.",
            remediation=RULE_REGISTRY[3].remediation,
        ))

    # Rule 5: LH-JTG-005 (HIGH, 10)
    connectivity = bool(policy_data.get("connectivity_check_enabled", False))
    if connectivity:
        findings.append(Finding(
            rule_id="LH-JTG-005",
            rule_name=RULE_REGISTRY[4].name,
            severity="HIGH",
            weight=10,
            cwe="CWE-200",
            message="HTTP captive-portal connectivity check is enabled, triggering periodic unencrypted outbound probes.",
            remediation=RULE_REGISTRY[4].remediation,
        ))

    # Rule 6: LH-JTG-006 (HIGH, 10)
    external_dns = bool(policy_data.get("external_dns_allowed", False))
    dns_servers = [str(s).strip() for s in policy_data.get("dns_servers", [])]
    has_public_resolver = any(s in PUBLIC_DNS_RESOLVERS for s in dns_servers)
    if external_dns or has_public_resolver:
        servers_str = ", ".join(dns_servers)
        findings.append(Finding(
            rule_id="LH-JTG-006",
            rule_name=RULE_REGISTRY[5].name,
            severity="HIGH",
            weight=10,
            cwe="CWE-319",
            message=f"external_dns_allowed={external_dns} or public resolvers configured: [{servers_str}].",
            remediation=RULE_REGISTRY[5].remediation,
        ))

    # Rule 7: LH-JTG-007 (HIGH, 10)
    snapd = bool(policy_data.get("snapd_enabled", False))
    cloud_init = bool(policy_data.get("cloud_init_phone_home_enabled", False))
    if snapd or cloud_init:
        findings.append(Finding(
            rule_id="LH-JTG-007",
            rule_name=RULE_REGISTRY[6].name,
            severity="HIGH",
            weight=10,
            cwe="CWE-400",
            message=f"Active cloud services: snapd_enabled={snapd}, cloud_init_phone_home={cloud_init}.",
            remediation=RULE_REGISTRY[6].remediation,
        ))

    # Rule 8: LH-JTG-008 (MEDIUM, 4)
    docker_opt_out = bool(policy_data.get("docker_telemetry_disabled", False))
    cuda_opt_out = bool(policy_data.get("cuda_telemetry_opt_out", False))
    if not docker_opt_out or not cuda_opt_out:
        findings.append(Finding(
            rule_id="LH-JTG-008",
            rule_name=RULE_REGISTRY[7].name,
            severity="MEDIUM",
            weight=4,
            cwe="CWE-200",
            message=f"docker_telemetry_disabled={docker_opt_out} and cuda_telemetry_opt_out={cuda_opt_out}.",
            remediation=RULE_REGISTRY[7].remediation,
        ))

    # Rule 9: LH-JTG-009 (MEDIUM, 4)
    coredump_upload = bool(policy_data.get("coredump_external_upload", False))
    suid_dumpable = int(policy_data.get("fs_suid_dumpable", 0))
    if coredump_upload or suid_dumpable != 0:
        findings.append(Finding(
            rule_id="LH-JTG-009",
            rule_name=RULE_REGISTRY[8].name,
            severity="MEDIUM",
            weight=4,
            cwe="CWE-215",
            message=f"coredump_external_upload={coredump_upload} and fs_suid_dumpable={suid_dumpable} (must be 0).",
            remediation=RULE_REGISTRY[8].remediation,
        ))

    # Rule 10: LH-JTG-010 (LOW, 1)
    drop_logging = bool(policy_data.get("egress_drop_logging_enabled", False))
    public_ntp = bool(policy_data.get("public_ntp_pool_used", False))
    if not drop_logging or public_ntp:
        findings.append(Finding(
            rule_id="LH-JTG-010",
            rule_name=RULE_REGISTRY[9].name,
            severity="LOW",
            weight=1,
            cwe="CWE-778",
            message=f"egress_drop_logging_enabled={drop_logging} and public_ntp_pool_used={public_ntp}.",
            remediation=RULE_REGISTRY[9].remediation,
        ))

    # Count findings and compute penalty
    critical_count = sum(1 for f in findings if f.severity == "CRITICAL")
    high_count = sum(1 for f in findings if f.severity == "HIGH")
    medium_count = sum(1 for f in findings if f.severity == "MEDIUM")
    low_count = sum(1 for f in findings if f.severity == "LOW")

    penalty = (25 * critical_count) + (10 * high_count) + (4 * medium_count) + (1 * low_count)
    score = max(0, 100 - penalty)
    status = "PASSED" if score == 100 else "FAILED"
    passed_rules = len(RULE_REGISTRY) - len(findings)

    return AuditReport(
        manifest_path=manifest_path,
        score=score,
        status=status,
        total_rules=len(RULE_REGISTRY),
        passed_rules=passed_rules,
        critical_count=critical_count,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,
        findings=findings,
    )
