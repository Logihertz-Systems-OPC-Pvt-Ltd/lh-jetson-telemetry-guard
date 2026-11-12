# ==============================================================================
# Product:       Logihertz Jetson Telemetry Guard (lh-jetson-telemetry-guard)
# Module:        cli.py
# Role:          CLI Entry Point & Subcommand Router
# Organization:  Logihertz Systems (OPC) Private Limited
# Developer:     Sameer Tawade (Creator, Founder, Director & Sole Developer)
# Contact:       ops@logihertz.com / security@logihertz.com
# License:       Apache-2.0
# ==============================================================================

"""Command-line interface and subcommand router for lh-telemetry-guard."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from lh_jetson_telemetry_guard import __version__
from lh_jetson_telemetry_guard.auditor import audit_bsp_policy
from lh_jetson_telemetry_guard.domain_sinkhole import (
    detect_periodic_beacon,
    generate_hosts_sinkhole,
    is_high_entropy_dns,
    is_telemetry_domain,
)
from lh_jetson_telemetry_guard.ebpf_nft_generator import (
    generate_ebpf_cgroup_filter,
    generate_nftables_ruleset,
)
from lh_jetson_telemetry_guard.exporters import (
    format_json,
    format_sarif,
    format_table,
)


def build_parser() -> argparse.ArgumentParser:
    """Construct the top-level argument parser with subcommands."""
    parser = argparse.ArgumentParser(
        prog="lh-telemetry-guard",
        description=(
            f"lh-telemetry-guard {__version__} - NVIDIA Jetson L4T / Embedded BSP Outbound Telemetry Blocker\n"
            "Logihertz Systems (OPC) Private Limited\n"
            "Creator & Developer: Sameer Tawade <ops@logihertz.com>"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"lh-telemetry-guard {__version__} (Logihertz Systems - Sameer Tawade)",
    )

    subparsers = parser.add_subparsers(dest="subcommand", help="Operational Subcommands")

    # 1. scan
    scan_parser = subparsers.add_parser("scan", help="Audit BSP security policy manifest against 10 rules")
    scan_parser.add_argument("manifest", help="Path to BSP policy JSON manifest")
    scan_parser.add_argument(
        "--format",
        choices=["table", "json", "sarif"],
        default="table",
        help="Report presentation format (default: table)",
    )
    scan_parser.add_argument("--output", help="Optional output file destination")

    # 2. gen-firewall
    fw_parser = subparsers.add_parser("gen-firewall", help="Generate atomic nftables air-gap ruleset")
    fw_parser.add_argument(
        "--allow-cidr",
        action="append",
        default=[],
        help="Allowlisted CIDR network (repeatable, e.g. --allow-cidr 192.168.10.0/24)",
    )
    fw_parser.add_argument(
        "--allow-ntp",
        action="store_true",
        help="Permit outbound NTP synchronization (UDP port 123)",
    )
    fw_parser.add_argument("--output", help="Optional output file destination")

    # 3. gen-ebpf
    ebpf_parser = subparsers.add_parser("gen-ebpf", help="Generate compilable Linux kernel cgroup eBPF C filter")
    ebpf_parser.add_argument(
        "--allow-cidr",
        action="append",
        default=[],
        help="Allowlisted CIDR network (repeatable, e.g. --allow-cidr 192.168.10.0/24)",
    )
    ebpf_parser.add_argument("--output", help="Optional output file destination")

    # 4. gen-sinkhole
    sink_parser = subparsers.add_parser("gen-sinkhole", help="Generate /etc/hosts telemetry sinkhole configuration")
    sink_parser.add_argument("--output", help="Optional output file destination")

    # 5. analyze-egress
    egress_parser = subparsers.add_parser(
        "analyze-egress",
        help="Analyze outbound socket/DNS telemetry flow for high-entropy exfiltration or beacons",
    )
    egress_parser.add_argument("flow", help="Path to egress flow telemetry JSON file")
    egress_parser.add_argument("--output", help="Optional output file destination")

    return parser


def handle_scan(args: argparse.Namespace) -> int:
    """Execute policy audit scan against BSP manifest."""
    manifest_path = Path(args.manifest)
    if not manifest_path.exists():
        sys.stderr.write(f"[ERROR] Manifest file not found: '{args.manifest}'\n")
        return 2

    try:
        content = manifest_path.read_text(encoding="utf-8")
        policy_data = json.loads(content)
    except Exception as exc:
        sys.stderr.write(f"[ERROR] Failed to read or parse JSON manifest: {exc}\n")
        return 2

    report = audit_bsp_policy(policy_data, str(manifest_path))

    if args.format == "json":
        rendered = format_json(report)
    elif args.format == "sarif":
        rendered = format_sarif(report)
    else:
        rendered = format_table(report)

    if args.output:
        try:
            Path(args.output).write_text(rendered, encoding="utf-8")
            print(f"[OK] Audit report written to '{args.output}'")
        except Exception as exc:
            sys.stderr.write(f"[ERROR] Failed to write output file: {exc}\n")
            return 2
    else:
        print(rendered)

    return 0 if report.score == 100 else 1


def handle_gen_firewall(args: argparse.Namespace) -> int:
    """Generate nftables ruleset."""
    try:
        ruleset = generate_nftables_ruleset(args.allow_cidr, allow_ntp=args.allow_ntp)
    except ValueError as exc:
        sys.stderr.write(f"[ERROR] Firewall generation error: {exc}\n")
        return 2

    if args.output:
        try:
            Path(args.output).write_text(ruleset, encoding="utf-8")
            print(f"[OK] nftables air-gap ruleset written to '{args.output}'")
        except Exception as exc:
            sys.stderr.write(f"[ERROR] Failed to write output file: {exc}\n")
            return 2
    else:
        print(ruleset)

    return 0


def handle_gen_ebpf(args: argparse.Namespace) -> int:
    """Generate eBPF cgroup socket filter C program."""
    try:
        ebpf_c = generate_ebpf_cgroup_filter(args.allow_cidr)
    except ValueError as exc:
        sys.stderr.write(f"[ERROR] eBPF generation error: {exc}\n")
        return 2

    if args.output:
        try:
            Path(args.output).write_text(ebpf_c, encoding="utf-8")
            print(f"[OK] eBPF cgroup filter source written to '{args.output}'")
        except Exception as exc:
            sys.stderr.write(f"[ERROR] Failed to write output file: {exc}\n")
            return 2
    else:
        print(ebpf_c)

    return 0


def handle_gen_sinkhole(args: argparse.Namespace) -> int:
    """Generate /etc/hosts sinkhole."""
    sinkhole_content = generate_hosts_sinkhole()
    if args.output:
        try:
            Path(args.output).write_text(sinkhole_content, encoding="utf-8")
            print(f"[OK] /etc/hosts sinkhole written to '{args.output}'")
        except Exception as exc:
            sys.stderr.write(f"[ERROR] Failed to write output file: {exc}\n")
            return 2
    else:
        print(sinkhole_content)

    return 0


def handle_analyze_egress(args: argparse.Namespace) -> int:
    """Analyze outbound telemetry flow for covert exfiltration and beacons."""
    flow_path = Path(args.flow)
    if not flow_path.exists():
        sys.stderr.write(f"[ERROR] Egress flow file not found: '{args.flow}'\n")
        return 2

    try:
        content = flow_path.read_text(encoding="utf-8")
        flow_data = json.loads(content)
    except Exception as exc:
        sys.stderr.write(f"[ERROR] Failed to parse flow JSON: {exc}\n")
        return 2

    dns_queries = flow_data.get("dns_queries", [])
    socket_flows = flow_data.get("socket_flows", [])

    violations: list[dict[str, str]] = []

    # 1. Inspect DNS queries
    for q in dns_queries:
        fqdn = q.get("fqdn", "")
        if is_telemetry_domain(fqdn):
            violations.append({
                "type": "VENDOR_TELEMETRY_DOMAIN",
                "target": fqdn,
                "detail": "Known NVIDIA or Ubuntu embedded telemetry endpoint queried.",
            })

        is_flagged, entropy, label = is_high_entropy_dns(fqdn)
        if is_flagged:
            violations.append({
                "type": "HIGH_ENTROPY_DNS_EXFILTRATION",
                "target": fqdn,
                "detail": f"Subdomain label '{label}' exhibits high Shannon entropy: {entropy} bits/char (>= 3.8).",
            })

    # 2. Inspect socket flow periodicity
    for flow in socket_flows:
        timestamps = flow.get("timestamps", [])
        dst = f"{flow.get('dst_ip')}:{flow.get('dst_port')}"
        is_beacon, cv, interval = detect_periodic_beacon(timestamps)
        if is_beacon:
            violations.append({
                "type": "PERIODIC_TELEMETRY_BEACON",
                "target": dst,
                "detail": f"Socket connections exhibit tight periodicity (CV={cv} < 0.05, mean interval={interval}s).",
            })

    lines: list[str] = [
        "",
        "=" * 80,
        " Logihertz Jetson Telemetry Guard - Egress Flow Analysis",
        f" Flow Data Source: {args.flow}",
        f" Analyzed DNS Queries: {len(dns_queries)}",
        f" Analyzed Socket Flows: {len(socket_flows)}",
        f" Detected Violations:  {len(violations)}",
        "=" * 80,
        "",
    ]

    if not violations:
        lines.append(" [OK] Clean Egress: No vendor telemetry, DNS exfiltration, or beacons detected.\n")
        exit_code = 0
    else:
        lines.append(" [ALERT] Outbound Telemetry Violations Detected:\n")
        for v in violations:
            lines.append(f"  - [{v['type']}] Target: {v['target']}")
            lines.append(f"    Detail: {v['detail']}")
        lines.append("")
        exit_code = 1

    report_str = "\n".join(lines)
    if args.output:
        try:
            Path(args.output).write_text(report_str, encoding="utf-8")
            print(f"[OK] Egress analysis written to '{args.output}'")
        except Exception as exc:
            sys.stderr.write(f"[ERROR] Failed to write output file: {exc}\n")
            return 2
    else:
        print(report_str)

    return exit_code


def main(argv: Sequence[str] | None = None) -> int:
    """CLI main entry point."""
    parser = build_parser()
    if argv is None:
        argv = sys.argv[1:]

    if not argv:
        parser.print_help()
        return 2

    args = parser.parse_args(argv)

    if args.subcommand == "scan":
        return handle_scan(args)
    if args.subcommand == "gen-firewall":
        return handle_gen_firewall(args)
    if args.subcommand == "gen-ebpf":
        return handle_gen_ebpf(args)
    if args.subcommand == "gen-sinkhole":
        return handle_gen_sinkhole(args)
    if args.subcommand == "analyze-egress":
        return handle_analyze_egress(args)

    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
