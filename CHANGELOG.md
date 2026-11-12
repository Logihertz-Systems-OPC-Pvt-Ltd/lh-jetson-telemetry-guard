# Changelog

All notable changes to `lh-jetson-telemetry-guard` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-11-12

### Added
- **Clean-Room Core Architecture**: Initial production-grade release of `lh-jetson-telemetry-guard` (`lh-telemetry-guard`) for NVIDIA Jetson L4T and embedded Linux BSPs with zero external runtime dependencies.
- **Domain Sinkhole & Shannon Entropy Analyzer** (`domain_sinkhole.py`):
  - Curated vendor telemetry domain registry for NVIDIA JetPack/L4T (`telemetry.nvidia.com`, `events.gfe.nvidia.com`, `ota.nvidia.com`, etc.) and Ubuntu embedded BSP (`metrics.ubuntu.com`, `popcon.ubuntu.com`, `daisy.ubuntu.com`, etc.).
  - Normalized character Shannon entropy calculation $H(L_{\text{sub}})$ for DNS exfiltration detection ($\ge 3.8\text{ bits/char}$ threshold for labels $|L| \ge 16$).
  - Periodic heartbeat telemetry beacon detector using inter-arrival Coefficient of Variation ($CV < 0.05$).
  - Deterministic `/etc/hosts` sinkhole block generator mapping domains to `0.0.0.0` and `::`.
- **eBPF & `nftables` Air-Gap Generator** (`ebpf_nft_generator.py`):
  - Compilable Linux kernel eBPF C program generator (`SEC("cgroup/connect4")` & `SEC("cgroup/connect6")`) with loopback allowlisting, subnet CIDR bitwise checks, and `-EPERM` enforcement.
  - Complete `nftables` air-gap ruleset generator (`table inet lh_telemetry_guard`) with drop policy, local subnet allowlisting, and external DNS/DoT port blocking.
- **Systemd Telemetry Unit & Timer Sanitizer** (`systemd_sanitizer.py`):
  - Detection and masking generator for Ubuntu and NVIDIA L4T phone-home daemons and timers (`whoopsie`, `apport`, `ubuntu-report`, `popularity-contest`, `motd-news`, `apt-daily`, `snapd`, `nv-telemetry`).
- **10-Rule Sovereign Air-Gap Posture Auditor** (`auditor.py`):
  - Normative evaluation of rules `LH-JTG-001` through `LH-JTG-010` mapping to CWEs.
  - Standardized Logihertz Security Posture Score calculation: $S_{\text{posture}} = \max(0, 100 - (25 c_{\text{CRIT}} + 10 c_{\text{HIGH}} + 4 c_{\text{MED}} + 1 c_{\text{LOW}}))$.
- **Multi-Format Reporting** (`exporters.py`):
  - ANSI Box table with posture score banner.
  - Canonical JSON exporter.
  - OASIS SARIF v2.1.0 compliant security report with CWE and rule definitions.
- **Unified CLI Tool** (`cli.py` & `bin/lh-telemetry-guard`):
  - Subcommands: `scan`, `gen-firewall`, `gen-ebpf`, `gen-sinkhole`, `analyze-egress`, `--version`, and `--help`.
- **Deterministic Test Suite** (`tests/test_telemetry_guard.py`):
  - 85+ test assertions covering domain classification, entropy math, eBPF synthesis, systemd sanitizer, auditor rules, and subprocess CLI exit codes.
