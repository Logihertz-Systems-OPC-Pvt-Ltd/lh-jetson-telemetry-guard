# Logihertz Jetson Telemetry Guard (`lh-jetson-telemetry-guard`)

[![Organization](https://img.shields.io/badge/Organization-Logihertz%20Systems-000000.svg)](https://logihertz.com/)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python: 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue.svg?logo=python&logoColor=white)](https://www.python.org/)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-0%20External%20Packages-success.svg)](#architecture)
[![OASIS SARIF v2.1.0](https://img.shields.io/badge/OASIS-SARIF%20v2.1.0-green.svg)](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
[![CI Matrix](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-jetson-telemetry-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-jetson-telemetry-guard/actions/workflows/ci.yml)

**Production-grade, zero-dependency Python 3.11+ NVIDIA Jetson L4T / Embedded BSP Outbound Telemetry Blocker, eBPF & `nftables` Egress Filter Generator, DNS Sinkhole Builder, and 10-Rule Sovereign Air-Gap Posture Auditor.**

---

## Executive Summary

Mission-critical edge AI appliances, defense robotics, and industrial autonomous systems powered by **NVIDIA Jetson (Orin, Xavier, Nano)** and embedded Linux Board Support Packages (BSPs) operate in sensitive environments where data exfiltration, vendor tracking, and unauthenticated network beacons violate sovereign security policies.

Stock Linux for Tegra (L4T) and Ubuntu embedded roots ship with numerous active phone-home services, diagnostic reporters (`whoopsie`, `apport`, `ubuntu-report`, `popularity-contest`), automatic MOTD queries, cloud-init beacons, and NVIDIA developer telemetry. In air-gapped or high-assurance deployments, these background processes create covert communication channels and beaconing telemetry.

**`lh-jetson-telemetry-guard`** (`lh-telemetry-guard`) provides an end-to-end telemetry neutralization and auditing suite:
- **100% Zero External Runtime Dependencies**: Standard Library only (`json`, `ipaddress`, `math`, `hashlib`, `re`, `argparse`, `pathlib`, `dataclasses`, `typing`).
- **Shannon Entropy DNS Exfiltration Detector**: Identifies covert data tunneling and domain-fluxing beacons via character-level information theory ($H(L) \ge 3.8\text{ bits/char}$) and periodic beaconing ($CV < 0.05$).
- **Curated Vendor Telemetry Sinkhole**: Curated registry of NVIDIA L4T and Canonical embedded phone-home domains mapped to `0.0.0.0` / `::`.
- **eBPF C Program Generator**: Synthesizes clean Linux `cgroup/connect4` and `cgroup/connect6` kernel probes that intercept socket connections at the transport layer and enforce strict CIDR allowlists.
- **Atomic `nftables` Air-Gap Ruleset**: Generates production-ready `nftables` configurations with default `drop` egress, loopback allowance, local subnet pin, and DNS port `53`/`853` leakage prevention.
- **Systemd Telemetry Sanitizer**: Detects and masks default L4T / Ubuntu phone-home services and periodic timers.
- **10-Rule Sovereign Air-Gap Posture Auditor**: Evaluates BSP configurations against 10 deterministic security controls with ANSI table, JSON, and OASIS SARIF v2.1.0 output.

---

## Mathematical Architecture: Shannon Entropy & Periodic Beacons

Covert telemetry and data exfiltration channels frequently leverage DNS tunneling (encoding stolen payloads inside high-entropy subdomain labels) or scheduled heartbeats (calling back on regular timer ticks).

### 1. Normalized Shannon Subdomain Character Entropy

For any requested FQDN $d$, the leftmost subdomain label $L_{\text{sub}}$ is isolated. Given an alphabet $\Sigma$ of characters present in $L_{\text{sub}}$, the character probability $P(c)$ and Shannon information entropy $H(L_{\text{sub}})$ in bits per character are computed as:

$$P(c) = \frac{\text{count}(c)}{|L_{\text{sub}}|}, \quad c \in \Sigma$$

$$H(L_{\text{sub}}) = -\sum_{c \in \Sigma} P(c) \log_2 P(c)$$

- **Normal Subdomain Labels** (e.g. `api`, `metrics`, `internal-node`): Character entropy is low to moderate ($H < 3.8\text{ bits/char}$).
- **Covert Exfiltration & Base32/Hex Tunneling** (e.g. `a9f4b2c8d1e7f09a8b7c6d5e4f3a2b1c`): Highly uniform character distributions yield high entropy ($H \ge 3.8\text{ bits/char}$ for $|L_{\text{sub}}| \ge 16$).

### 2. Beacon Timing Regularity (Coefficient of Variation)

Automated telemetry agents and heartbeat beacons transmit outbound pings at fixed periodic intervals. For a sequence of observed socket connection inter-arrival deltas $\Delta t_1, \Delta t_2, \dots, \Delta t_k$, the mean $\mu_{\Delta t}$ and standard deviation $\sigma_{\Delta t}$ determine the Coefficient of Variation ($CV$):

$$CV = \frac{\sigma_{\Delta t}}{\mu_{\Delta t}}$$

Where $CV < 0.05$ indicates an automated, machine-driven telemetry heartbeat timer rather than stochastic human or dynamic process activity.

---

## eBPF & `nftables` Kernel Egress Filtering

`lh-telemetry-guard` generates two complementary defense-in-depth enforcement mechanisms:

### 1. eBPF C Program (`cgroup/connect4` / `cgroup/connect6`)
Attaches directly to the socket connection hook inside the Linux kernel network stack:
- Intercepts `connect(2)` syscalls before IP packets are formed.
- Permissive for loopback (`127.0.0.0/8`, `::1`) and explicitly allowlisted private RFC 1918 or industrial subnets.
- Immediately aborts unauthorized egress with `-EPERM` (`0`), preventing packet generation and socket leaks.

### 2. Atomic `nftables` Egress Ruleset (`table inet lh_telemetry_guard`)
Configures a hardware/kernel packet filter:
- `chain output { type filter hook output priority 0; policy drop; }`
- Allows established and related traffic (`ct state established,related accept`).
- Restricts outbound UDP/TCP DNS queries to verified local nameservers and drops unauthorized public DNS (`8.8.8.8`, `1.1.1.1`, DoT `853`).

---

## Core Detection Rules (`LH-JTG-001` .. `LH-JTG-010`)

| Rule ID | Severity | Weight ($W_r$) | CWE | Trigger Condition & Description |
|:---|:---:|:---:|:---:|:---|
| **`LH-JTG-001`** | `CRITICAL` | 25 | CWE-200 | Active vendor telemetry or crash-reporting daemons running (`whoopsie`, `apport`, `ubuntu-report`, `nv-telemetry`, `popularity-contest`) |
| **`LH-JTG-002`** | `CRITICAL` | 25 | CWE-284 | Unrestricted default outbound WAN egress firewall (`egress_default_policy != "DROP"` or `ebpf_socket_guard_enabled: false`) |
| **`LH-JTG-003`** | `CRITICAL` | 25 | CWE-359 | Vendor telemetry domains unsinkholed (`telemetry_domains_sinkholed: false` or `< 10` blocked entries in `/etc/hosts`) |
| **`LH-JTG-004`** | `HIGH` | 10 | CWE-300 | Uncontrolled background auto-update or phone-home timers enabled (`unattended_upgrades_enabled: true`, `apt_daily_timer_enabled: true`, or `motd_news_enabled: true`) |
| **`LH-JTG-005`** | `HIGH` | 10 | CWE-200 | NetworkManager / Ubuntu HTTP captive portal connectivity checks enabled (`connectivity_check_enabled: true`) |
| **`LH-JTG-006`** | `HIGH` | 10 | CWE-319 | Unauthorized external public DNS resolvers configured (`external_dns_allowed: true` or `8.8.8.8`/`1.1.1.1` configured) |
| **`LH-JTG-007`** | `HIGH` | 10 | CWE-400 | Snapd or cloud-init phone-home services active on embedded appliance (`snapd_enabled: true` or `cloud_init_phone_home_enabled: true`) |
| **`LH-JTG-008`** | `MEDIUM` | 4 | CWE-200 | Unsanitized container runtime or CUDA/TensorRT usage telemetry (`docker_telemetry_disabled: false` or `cuda_telemetry_opt_out: false`) |
| **`LH-JTG-009`** | `MEDIUM` | 4 | CWE-215 | Core dumps or kernel crash kdump configured to transmit externally (`coredump_external_upload: true` or `fs_suid_dumpable != 0`) |
| **`LH-JTG-010`** | `LOW` | 1 | CWE-778 | Missing egress drop audit logging or unpinned public NTP pool (`egress_drop_logging_enabled: false` or `public_ntp_pool_used: true`) |

### Standardized Security Posture Score:

$$S_{\text{posture}} = \max\left(0, 100 - \sum_{r \in \text{Violations}} W_r\right) = \max\left(0, 100 - (25 \cdot c_{\text{CRIT}} + 10 \cdot c_{\text{HIGH}} + 4 \cdot c_{\text{MED}} + 1 \cdot c_{\text{LOW}})\right)$$

- **Hardened Policy (`hardened_jetson_bsp.json`)**: $S_{\text{posture}} = 100/100$ (Exit code `0`).
- **Vulnerable Policy (`vulnerable_jetson_bsp.json`)**: $S_{\text{posture}} = \max(0, 100 - 124) = 0/100$ (Exit code `1`).

---

## CLI Reference (`lh-telemetry-guard`)

```bash
# 1. Audit Jetson BSP policy manifest
bin/lh-telemetry-guard scan fixtures/hardened_jetson_bsp.json --format table
bin/lh-telemetry-guard scan fixtures/hardened_jetson_bsp.json --format sarif --output report.sarif

# 2. Generate nftables atomic egress air-gap ruleset
bin/lh-telemetry-guard gen-firewall --allow-cidr 192.168.10.0/24 --allow-cidr 10.0.0.0/8 --output /tmp/egress.nft

# 3. Generate compilable Linux kernel eBPF C program
bin/lh-telemetry-guard gen-ebpf --allow-cidr 192.168.10.0/24 --output /tmp/egress_filter.bpf.c

# 4. Generate /etc/hosts sinkhole configuration
bin/lh-telemetry-guard gen-sinkhole --output /tmp/telemetry_hosts

# 5. Analyze outbound DNS & socket telemetry flow for covert exfiltration
bin/lh-telemetry-guard analyze-egress fixtures/sample_egress_flow.json

# 6. Version & Help
bin/lh-telemetry-guard --version
bin/lh-telemetry-guard --help
```

---

## Exit Codes

| Exit Code | Semantic Meaning |
|:---:|:---|
| **`0`** | Clean scan (Score: 100, zero violations) or clean egress flow analysis |
| **`1`** | Air-gap policy violation detected, high-entropy DNS exfiltration found, or beacon detected |
| **`2`** | Invalid CLI usage, missing file, or malformed JSON syntax |

---

## Corporate Attribution & Governance

- **Organization**: [Logihertz Systems (OPC) Private Limited](https://logihertz.com/)
- **GitHub Organization**: [`Logihertz-Systems-OPC-Pvt-Ltd`](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd)
- **Creator, Founder, Director & Sole Developer**: **Sameer Tawade** ([`ops@logihertz.com`](mailto:ops@logihertz.com) / [`security@logihertz.com`](mailto:security@logihertz.com))
- **Git Commit Author**: `logihertzsystems <ops@logihertz.com>`
- **License**: Released under the [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0).

Copyright &copy; 2026 Logihertz Systems (OPC) Private Limited. All Rights Reserved.
