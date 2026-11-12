# ==============================================================================
# Product:       Logihertz Jetson Telemetry Guard (lh-jetson-telemetry-guard)
# Module:        __init__.py
# Role:          Package Entry & Public Symbol Exports
# Organization:  Logihertz Systems (OPC) Private Limited
# Developer:     Sameer Tawade (Creator, Founder, Director & Sole Developer)
# Contact:       ops@logihertz.com / security@logihertz.com
# License:       Apache-2.0
# ==============================================================================

"""Logihertz Jetson Telemetry Guard (`lh-jetson-telemetry-guard`).

NVIDIA Jetson L4T / Embedded BSP Outbound Telemetry Blocker,
eBPF & nftables Egress Filter Generator, DNS Sinkhole Builder,
and 10-Rule Sovereign Air-Gap Posture Auditor.
"""

from __future__ import annotations

from lh_jetson_telemetry_guard.domain_sinkhole import (
    CURATED_TELEMETRY_DOMAINS,
    compute_coefficient_of_variation,
    compute_shannon_entropy,
    detect_periodic_beacon,
    generate_hosts_sinkhole,
    is_high_entropy_dns,
    is_telemetry_domain,
)
from lh_jetson_telemetry_guard.ebpf_nft_generator import (
    generate_ebpf_cgroup_filter,
    generate_nftables_ruleset,
)
from lh_jetson_telemetry_guard.systemd_sanitizer import (
    MANDATORY_MASKED_UNITS,
    audit_active_units,
    generate_systemd_mask_commands,
)
from lh_jetson_telemetry_guard.auditor import (
    Finding,
    AuditReport,
    RuleDefinition,
    RULE_REGISTRY,
    audit_bsp_policy,
)
from lh_jetson_telemetry_guard.exporters import (
    format_table,
    format_json,
    format_sarif,
)

__version__ = "0.1.0"
__author__ = "Sameer Tawade"
__email__ = "ops@logihertz.com"
__all__ = [
    "__version__",
    "__author__",
    "__email__",
    "CURATED_TELEMETRY_DOMAINS",
    "compute_coefficient_of_variation",
    "compute_shannon_entropy",
    "detect_periodic_beacon",
    "generate_hosts_sinkhole",
    "is_high_entropy_dns",
    "is_telemetry_domain",
    "generate_ebpf_cgroup_filter",
    "generate_nftables_ruleset",
    "MANDATORY_MASKED_UNITS",
    "audit_active_units",
    "generate_systemd_mask_commands",
    "Finding",
    "AuditReport",
    "RuleDefinition",
    "RULE_REGISTRY",
    "audit_bsp_policy",
    "format_table",
    "format_json",
    "format_sarif",
]
