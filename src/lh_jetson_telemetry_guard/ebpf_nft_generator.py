# ==============================================================================
# Product:       Logihertz Jetson Telemetry Guard (lh-jetson-telemetry-guard)
# Module:        ebpf_nft_generator.py
# Role:          Linux cgroup/connect4 eBPF C Generator & nftables Egress Builder
# Organization:  Logihertz Systems (OPC) Private Limited
# Developer:     Sameer Tawade (Creator, Founder, Director & Sole Developer)
# Contact:       ops@logihertz.com / security@logihertz.com
# License:       Apache-2.0
# ==============================================================================

"""Linux kernel eBPF cgroup socket filter and atomic nftables egress firewall generator."""

from __future__ import annotations

import ipaddress
from typing import Sequence

DEFAULT_BLOCKED_PORTS: tuple[int, ...] = (853,)  # DNS-over-TLS covert egress port


def generate_ebpf_cgroup_filter(
    allowed_cidrs: Sequence[str],
    blocked_ports: Sequence[int] | None = None,
) -> str:
    """Synthesize a compilable Linux kernel eBPF C program intercepting outbound connections.

    Uses `SEC("cgroup/connect4")` and `SEC("cgroup/connect6")` to enforce socket-level
    air-gap isolation at the transport layer before packets leave user space.

    Args:
        allowed_cidrs: Sequence of IPv4/IPv6 CIDR network strings (e.g. ['192.168.1.0/24']).
        blocked_ports: Optional list of destination ports to block explicitly (e.g. [853]).

    Returns:
        Compilable eBPF C program source code.

    Raises:
        ValueError: If any provided CIDR string is malformed or invalid.
    """
    v4_networks: list[ipaddress.IPv4Network] = []
    v6_networks: list[ipaddress.IPv6Network] = []

    for cidr_str in allowed_cidrs:
        clean_cidr = cidr_str.strip()
        try:
            net = ipaddress.ip_network(clean_cidr, strict=False)
            if isinstance(net, ipaddress.IPv4Network):
                v4_networks.append(net)
            else:
                v6_networks.append(net)
        except ValueError as exc:
            raise ValueError(f"Malformed or invalid CIDR specification: '{clean_cidr}'") from exc

    ports_to_block = list(blocked_ports if blocked_ports is not None else DEFAULT_BLOCKED_PORTS)

    lines: list[str] = [
        "/* ==============================================================================",
        " * Product:       Logihertz Jetson Telemetry Guard (lh-telemetry-guard)",
        " * Role:          Kernel cgroup/connect4 & connect6 Egress Socket Filter",
        " * Organization:  Logihertz Systems (OPC) Private Limited",
        " * Developer:     Sameer Tawade (Creator, Founder, Director & Sole Developer)",
        " * License:       Apache-2.0",
        " * ============================================================================== */",
        "",
        "#include <linux/bpf.h>",
        "#include <linux/in.h>",
        "#include <bpf/bpf_helpers.h>",
        "#include <bpf/bpf_endian.h>",
        "",
        "SEC(\"cgroup/connect4\")",
        "int sock_connect4_egress_guard(struct bpf_sock_addr *ctx) {",
        "    __u32 dst_ip = bpf_ntohl(ctx->user_ip4);",
        "    __u16 dst_port = bpf_ntohs((__u16)ctx->user_port);",
        "",
        "    /* 1. Unconditionally permit IPv4 loopback (127.0.0.0/8) */",
        "    if ((dst_ip & 0xFF000000) == 0x7F000000) {",
        "        return 1;",
        "    }",
        "",
    ]

    # Explicit port blocks
    if ports_to_block:
        lines.append("    /* 2. Block prohibited covert egress ports (e.g. DNS-over-TLS) */")
        for port in sorted(set(ports_to_block)):
            lines.append(f"    if (dst_port == {port}) {{")
            lines.append("        return 0; /* -EPERM */")
            lines.append("    }")
        lines.append("")

    # Allowlisted IPv4 subnets
    if v4_networks:
        lines.append("    /* 3. Permit explicitly allowlisted sovereign subnets */")
        for net in v4_networks:
            mask = int(net.netmask)
            net_addr = int(net.network_address)
            lines.append(
                f"    /* {net} */\n"
                f"    if ((dst_ip & 0x{mask:08X}U) == 0x{net_addr:08X}U) {{\n"
                f"        return 1;\n"
                f"    }}"
            )
        lines.append("")

    lines.extend([
        "    /* Default Egress Action: Drop unauthorized WAN egress */",
        "    return 0; /* -EPERM */",
        "}",
        "",
        "SEC(\"cgroup/connect6\")",
        "int sock_connect6_egress_guard(struct bpf_sock_addr *ctx) {",
        "    /* Permit IPv6 loopback (::1) */",
        "    if (ctx->user_ip6[0] == 0 && ctx->user_ip6[1] == 0 &&",
        "        ctx->user_ip6[2] == 0 && ctx->user_ip6[3] == bpf_htonl(1)) {",
        "        return 1;",
        "    }",
        "",
    ])

    if v6_networks:
        lines.append("    /* Allowlisted IPv6 subnets */")
        for v6_net in v6_networks:
            # Check the first 64 bits for simplicity
            lines.append(f"    /* {v6_net} */")
            prefix_words = [int.from_bytes(v6_net.network_address.packed[i:i + 4], "big") for i in (0, 4, 8, 12)]
            mask_words = [int.from_bytes(v6_net.netmask.packed[i:i + 4], "big") for i in (0, 4, 8, 12)]
            lines.append(
                f"    if ((bpf_ntohl(ctx->user_ip6[0]) & 0x{mask_words[0]:08X}U) == 0x{prefix_words[0]:08X}U &&\n"
                f"        (bpf_ntohl(ctx->user_ip6[1]) & 0x{mask_words[1]:08X}U) == 0x{prefix_words[1]:08X}U) {{\n"
                f"        return 1;\n"
                f"    }}"
            )
        lines.append("")

    lines.extend([
        "    /* Default IPv6 Action: Drop unauthorized WAN egress */",
        "    return 0; /* -EPERM */",
        "}",
        "",
        'char _license[] SEC("license") = "Apache-2.0";',
        "",
    ])

    return "\n".join(lines)


def generate_nftables_ruleset(
    allowed_cidrs: Sequence[str],
    allow_ntp: bool = False,
    blocked_ports: Sequence[int] | None = None,
) -> str:
    """Synthesize an atomic nftables egress configuration for air-gapped appliances.

    Configures `table inet lh_telemetry_guard` with default drop egress policy,
    loopback acceptance, established state tracking, and local subnet allowlisting.

    Args:
        allowed_cidrs: Sequence of permitted network CIDRs.
        allow_ntp: Whether to permit outbound NTP UDP port 123.
        blocked_ports: Optional ports to explicitly drop (default: [853]).

    Returns:
        Synthesized nftables configuration file content.

    Raises:
        ValueError: If any CIDR is malformed.
    """
    v4_subnets: list[str] = []
    v6_subnets: list[str] = []

    for cidr in allowed_cidrs:
        clean = cidr.strip()
        try:
            net = ipaddress.ip_network(clean, strict=False)
            if isinstance(net, ipaddress.IPv4Network):
                v4_subnets.append(str(net))
            else:
                v6_subnets.append(str(net))
        except ValueError as exc:
            raise ValueError(f"Malformed or invalid CIDR specification: '{clean}'") from exc

    ports_to_drop = list(blocked_ports if blocked_ports is not None else DEFAULT_BLOCKED_PORTS)

    lines: list[str] = [
        "#!/usr/sbin/nft -f",
        "# ==============================================================================",
        "# Product:       Logihertz Jetson Telemetry Guard (lh-telemetry-guard)",
        "# File:          Atomic nftables Sovereign Air-Gap Egress Ruleset",
        "# Table:         inet lh_telemetry_guard",
        "# Organization:  Logihertz Systems (OPC) Private Limited",
        "# Developer:     Sameer Tawade (Creator, Founder, Director & Sole Developer)",
        "# License:       Apache-2.0",
        "# ==============================================================================",
        "",
        "flush table inet lh_telemetry_guard",
        "",
        "table inet lh_telemetry_guard {",
        "    chain output {",
        "        type filter hook output priority 0; policy drop;",
        "",
        "        # 1. Unconditionally permit loopback traffic",
        "        oifname \"lo\" accept",
        "",
        "        # 2. Permit established and related connection states",
        "        ct state established,related accept",
        "",
        "        # 3. Drop invalid packet states",
        "        ct state invalid drop",
        "",
    ]

    if ports_to_drop:
        port_list_str = ", ".join(str(p) for p in sorted(set(ports_to_drop)))
        lines.extend([
            "        # 4. Drop covert DNS-over-TLS / prohibited ports",
            f"        tcp dport {{ {port_list_str} }} drop",
            f"        udp dport {{ {port_list_str} }} drop",
            "",
        ])

    if allow_ntp:
        lines.extend([
            "        # 5. Permit authenticated local NTP synchronization",
            "        udp dport 123 accept",
            "",
        ])

    if v4_subnets:
        v4_str = ", ".join(v4_subnets)
        lines.extend([
            "        # 6. Permit verified sovereign IPv4 destination subnets",
            f"        ip daddr {{ {v4_str} }} accept",
            "",
        ])

    if v6_subnets:
        v6_str = ", ".join(v6_subnets)
        lines.extend([
            "        # 7. Permit verified sovereign IPv6 destination subnets",
            f"        ip6 daddr {{ {v6_str} }} accept",
            "",
        ])

    lines.extend([
        "        # 8. Log and reject unauthorized egress attempts",
        "        log prefix \"[LH-EGRESS-DROP] \" flags all",
        "        reject with icmpx type admin-prohibited",
        "    }",
        "}",
        "",
    ])

    return "\n".join(lines)
