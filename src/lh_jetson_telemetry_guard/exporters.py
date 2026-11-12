# ==============================================================================
# Product:       Logihertz Jetson Telemetry Guard (lh-jetson-telemetry-guard)
# Module:        exporters.py
# Role:          ANSI Terminal Table, Canonical JSON, and OASIS SARIF v2.1.0 Exporters
# Organization:  Logihertz Systems (OPC) Private Limited
# Developer:     Sameer Tawade (Creator, Founder, Director & Sole Developer)
# Contact:       ops@logihertz.com / security@logihertz.com
# License:       Apache-2.0
# ==============================================================================

"""Multi-format report exporters: ANSI Table, Canonical JSON, and OASIS SARIF v2.1.0."""

from __future__ import annotations

import json
from typing import Any

from lh_jetson_telemetry_guard.auditor import AuditReport, RULE_REGISTRY


def format_table(report: AuditReport) -> str:
    """Format audit report into an ANSI terminal table with score banner."""
    lines: list[str] = [
        "",
        "=" * 80,
        "   Logihertz Jetson Telemetry Guard (lh-telemetry-guard)",
        f"   Policy Manifest: {report.manifest_path or 'In-Memory / Direct Input'}",
        f"   Posture Score:   {report.score}/100   [{report.status}]",
        f"   Summary:         {report.passed_rules} passed, {len(report.findings)} violations "
        f"(CRIT: {report.critical_count}, HIGH: {report.high_count}, MED: {report.medium_count}, LOW: {report.low_count})",
        "=" * 80,
        "",
    ]

    if not report.findings:
        lines.extend([
            " [OK] All 10 sovereign air-gap telemetry controls are satisfied.",
            "      The evaluated BSP configuration strictly enforces outbound isolation.",
            "",
        ])
        return "\n".join(lines)

    lines.extend([
        "+----------------+----------+--------+----------+--------------------------------------+",
        "| Rule ID        | Severity | Weight | CWE      | Rule Title                           |",
        "+----------------+----------+--------+----------+--------------------------------------+",
    ])

    for f in report.findings:
        short_name = f.rule_name[:36] if len(f.rule_name) <= 36 else f.rule_name[:33] + "..."
        lines.append(
            f"| {f.rule_id:<14} | {f.severity:<8} | {f.weight:<6} | {f.cwe:<8} | {short_name:<36} |"
        )
        msg_preview = f.message[:66] if len(f.message) <= 66 else f.message[:63] + "..."
        rem_preview = f.remediation[:66] if len(f.remediation) <= 66 else f.remediation[:63] + "..."
        lines.append(f"| Detail:        {msg_preview:<66} |")
        lines.append(f"| Remediation:   {rem_preview:<66} |")
        lines.append("+----------------+----------+--------+----------+--------------------------------------+")

    lines.append("")
    return "\n".join(lines)


def format_json(report: AuditReport) -> str:
    """Format audit report into structured canonical JSON."""
    data: dict[str, Any] = {
        "manifest_path": report.manifest_path,
        "score": report.score,
        "status": report.status,
        "total_rules": report.total_rules,
        "passed_rules": report.passed_rules,
        "violations_count": len(report.findings),
        "critical_count": report.critical_count,
        "high_count": report.high_count,
        "medium_count": report.medium_count,
        "low_count": report.low_count,
        "findings": [
            {
                "rule_id": f.rule_id,
                "rule_name": f.rule_name,
                "severity": f.severity,
                "weight": f.weight,
                "cwe": f.cwe,
                "message": f.message,
                "remediation": f.remediation,
            }
            for f in report.findings
        ],
    }
    return json.dumps(data, indent=2, sort_keys=False)


def format_sarif(report: AuditReport) -> str:
    """Format audit report into an OASIS SARIF v2.1.0 document."""
    rules_obj = []
    for r in RULE_REGISTRY:
        rules_obj.append({
            "id": r.id,
            "name": r.name,
            "fullDescription": {"text": r.description},
            "help": {"text": r.remediation},
            "properties": {
                "cwe": r.cwe,
                "severity": r.severity,
                "weight": r.weight,
            },
        })

    results_obj = []
    for f in report.findings:
        level_str = "error" if f.severity in ("CRITICAL", "HIGH") else ("warning" if f.severity == "MEDIUM" else "note")
        results_obj.append({
            "ruleId": f.rule_id,
            "level": level_str,
            "message": {"text": f.message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": report.manifest_path or "manifest.json"}
                    }
                }
            ],
        })

    sarif_doc = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "lh-telemetry-guard",
                        "version": "0.1.0",
                        "informationUri": "https://logihertz.com",
                        "rules": rules_obj,
                    }
                },
                "results": results_obj,
            }
        ],
    }

    return json.dumps(sarif_doc, indent=2)
