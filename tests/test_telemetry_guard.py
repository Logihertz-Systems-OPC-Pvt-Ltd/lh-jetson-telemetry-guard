# ==============================================================================
# Product:       Logihertz Jetson Telemetry Guard (lh-jetson-telemetry-guard)
# Module:        tests/test_telemetry_guard.py
# Role:          Comprehensive Deterministic Test Suite (85+ Assertions)
# Organization:  Logihertz Systems (OPC) Private Limited
# Developer:     Sameer Tawade (Creator, Founder, Director & Sole Developer)
# Contact:       ops@logihertz.com / security@logihertz.com
# License:       Apache-2.0
# ==============================================================================

"""Comprehensive test suite for lh-jetson-telemetry-guard (85+ assertions)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

# Add src to sys.path
TEST_DIR = Path(__file__).resolve().parent
PROJECT_DIR = TEST_DIR.parent
SRC_DIR = PROJECT_DIR / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from lh_jetson_telemetry_guard.auditor import (
    RULE_REGISTRY,
    AuditReport,
    Finding,
    RuleDefinition,
    audit_bsp_policy,
)
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
from lh_jetson_telemetry_guard.exporters import (
    format_json,
    format_sarif,
    format_table,
)
from lh_jetson_telemetry_guard.systemd_sanitizer import (
    MANDATORY_MASKED_UNITS,
    UNIT_DESCRIPTIONS,
    audit_active_units,
    generate_systemd_mask_commands,
    generate_systemd_mask_manifest,
)


class TestDomainSinkholeAndEntropy(unittest.TestCase):
    """Test telemetry domain classification, Shannon entropy, and beacon detection."""

    def test_curated_telemetry_domain_matches(self):
        # NVIDIA domains
        self.assertTrue(is_telemetry_domain("telemetry.nvidia.com"))
        self.assertTrue(is_telemetry_domain("events.gfe.nvidia.com"))
        self.assertTrue(is_telemetry_domain("ota.nvidia.com"))
        self.assertTrue(is_telemetry_domain("developer.download.nvidia.com"))
        self.assertTrue(is_telemetry_domain("nv-telemetry.nvidia.com"))
        self.assertTrue(is_telemetry_domain("sub.telemetry.nvidia.com"))

        # Ubuntu domains
        self.assertTrue(is_telemetry_domain("metrics.ubuntu.com"))
        self.assertTrue(is_telemetry_domain("popcon.ubuntu.com"))
        self.assertTrue(is_telemetry_domain("daisy.ubuntu.com"))
        self.assertTrue(is_telemetry_domain("errors.ubuntu.com"))
        self.assertTrue(is_telemetry_domain("motd.ubuntu.com"))
        self.assertTrue(is_telemetry_domain("connectivity-check.ubuntu.com"))
        self.assertTrue(is_telemetry_domain("api.snapcraft.io"))
        self.assertTrue(is_telemetry_domain("node.metrics.ubuntu.com"))

    def test_clean_non_telemetry_domains(self):
        self.assertFalse(is_telemetry_domain("api.internal.local"))
        self.assertFalse(is_telemetry_domain("sovereign-node-01.lan"))
        self.assertFalse(is_telemetry_domain("github.com"))
        self.assertFalse(is_telemetry_domain("logihertz.com"))
        self.assertFalse(is_telemetry_domain(""))
        self.assertFalse(is_telemetry_domain("   "))

    def test_shannon_entropy_calculation(self):
        # Empty string
        self.assertEqual(compute_shannon_entropy(""), 0.0)

        # Uniform single character: H = 0.0
        self.assertEqual(compute_shannon_entropy("aaaaaaa"), 0.0)

        # Binary equal split: H = 1.0
        self.assertEqual(compute_shannon_entropy("abababab"), 1.0)

        # Standard normal hostname label
        h_normal = compute_shannon_entropy("internal-node")
        self.assertLess(h_normal, 3.8)

        # High-entropy hex exfiltration payload (32 unique-like hex chars)
        h_exfil = compute_shannon_entropy("a9f4b2c8d1e7f09a8b7c6d5e4f3a2b1c")
        self.assertGreaterEqual(h_exfil, 3.8)

    def test_is_high_entropy_dns(self):
        # Normal query
        flagged, h_val, label = is_high_entropy_dns("api.internal.local")
        self.assertFalse(flagged)
        self.assertEqual(label, "api")

        # Short label with high entropy shouldn't flag if below min_len=16
        flagged_short, _, _ = is_high_entropy_dns("a9f4b.internal.local", min_len=16)
        self.assertFalse(flagged_short)

        # Exfiltration payload
        exfil_fqdn = "a9f4b2c8d1e7f09a8b7c6d5e4f3a2b1c.covert-channel.org"
        flagged_exfil, h_exfil, label_exfil = is_high_entropy_dns(exfil_fqdn)
        self.assertTrue(flagged_exfil)
        self.assertGreaterEqual(h_exfil, 3.8)
        self.assertEqual(label_exfil, "a9f4b2c8d1e7f09a8b7c6d5e4f3a2b1c")

    def test_coefficient_of_variation(self):
        self.assertEqual(compute_coefficient_of_variation([]), 0.0)
        self.assertEqual(compute_coefficient_of_variation([10.0]), 0.0)

        # Perfectly constant intervals: std dev = 0 -> CV = 0.0
        self.assertEqual(compute_coefficient_of_variation([30.0, 30.0, 30.0, 30.0]), 0.0)

        # Jittery intervals
        cv_jitter = compute_coefficient_of_variation([1.0, 50.0, 5.0, 100.0])
        self.assertGreater(cv_jitter, 0.5)

    def test_periodic_beacon_detection(self):
        # Heartbeat every 30.0 seconds
        ts_periodic = [100.0, 130.0, 160.0, 190.0, 220.0]
        is_beacon, cv, interval = detect_periodic_beacon(ts_periodic)
        self.assertTrue(is_beacon)
        self.assertLess(cv, 0.05)
        self.assertEqual(interval, 30.0)

        # Stochastic human or dynamic network timing
        ts_random = [100.0, 112.5, 189.2, 204.1, 412.0]
        is_beacon_rnd, cv_rnd, _ = detect_periodic_beacon(ts_random)
        self.assertFalse(is_beacon_rnd)
        self.assertGreater(cv_rnd, 0.05)

        # Too few events
        self.assertFalse(detect_periodic_beacon([100.0, 130.0])[0])

    def test_generate_hosts_sinkhole(self):
        sinkhole = generate_hosts_sinkhole()
        self.assertIn("0.0.0.0 telemetry.nvidia.com", sinkhole)
        self.assertIn("::      telemetry.nvidia.com", sinkhole)
        self.assertIn("0.0.0.0 metrics.ubuntu.com", sinkhole)
        self.assertIn("::      metrics.ubuntu.com", sinkhole)
        self.assertIn("SHA-256:", sinkhole)
        self.assertIn(f"Domains Count: {len(CURATED_TELEMETRY_DOMAINS)}", sinkhole)


class TestEbpfAndNftablesGenerator(unittest.TestCase):
    """Test Linux kernel eBPF C generation and nftables ruleset synthesis."""

    def test_ebpf_cgroup_filter_generation(self):
        c_code = generate_ebpf_cgroup_filter(
            allowed_cidrs=["192.168.10.0/24", "10.0.0.0/8"],
            blocked_ports=[853],
        )
        self.assertIn('SEC("cgroup/connect4")', c_code)
        self.assertIn('SEC("cgroup/connect6")', c_code)
        self.assertIn("127.0.0.0/8", c_code)
        self.assertIn("0x7F000000", c_code)
        self.assertIn("dst_port == 853", c_code)
        self.assertIn("192.168.10.0/24", c_code)
        self.assertIn("10.0.0.0/8", c_code)
        self.assertIn('char _license[] SEC("license") = "Apache-2.0";', c_code)

    def test_ebpf_rejects_malformed_cidr(self):
        with self.assertRaises(ValueError) as ctx:
            generate_ebpf_cgroup_filter(["invalid.ip.string/999"])
        self.assertIn("Malformed or invalid CIDR", str(ctx.exception))

    def test_nftables_ruleset_generation(self):
        ruleset = generate_nftables_ruleset(
            allowed_cidrs=["192.168.10.0/24", "10.200.0.0/16"],
            allow_ntp=True,
            blocked_ports=[853],
        )
        self.assertIn("table inet lh_telemetry_guard", ruleset)
        self.assertIn("type filter hook output priority 0; policy drop;", ruleset)
        self.assertIn('oifname "lo" accept', ruleset)
        self.assertIn("ct state established,related accept", ruleset)
        self.assertIn("ct state invalid drop", ruleset)
        self.assertIn("tcp dport { 853 } drop", ruleset)
        self.assertIn("udp dport 123 accept", ruleset)
        self.assertIn("192.168.10.0/24", ruleset)
        self.assertIn("10.200.0.0/16", ruleset)
        self.assertIn('log prefix "[LH-EGRESS-DROP] "', ruleset)
        self.assertIn("reject with icmpx type admin-prohibited", ruleset)

    def test_nftables_rejects_malformed_cidr(self):
        with self.assertRaises(ValueError):
            generate_nftables_ruleset(["999.999.999.999/24"])


class TestSystemdSanitizer(unittest.TestCase):
    """Test systemd telemetry unit audit and mask generator."""

    def test_mandatory_unit_constants(self):
        self.assertEqual(len(MANDATORY_MASKED_UNITS), 11)
        self.assertIn("whoopsie.service", MANDATORY_MASKED_UNITS)
        self.assertIn("apport.service", MANDATORY_MASKED_UNITS)
        self.assertIn("nv-telemetry.service", MANDATORY_MASKED_UNITS)
        self.assertIn("motd-news.timer", MANDATORY_MASKED_UNITS)

    def test_audit_active_units_detection(self):
        active = ["nginx.service", "whoopsie.service", "apport.service", "custom-app.service"]
        timers = ["systemd-tmpfiles-clean.timer", "motd-news.timer"]
        detected = audit_active_units(active, timers)
        self.assertEqual(detected, ["apport.service", "motd-news.timer", "whoopsie.service"])

    def test_audit_active_units_clean(self):
        active = ["nginx.service", "custom-app.service"]
        timers = ["systemd-tmpfiles-clean.timer"]
        self.assertEqual(audit_active_units(active, timers), [])

    def test_generate_systemd_mask_commands(self):
        cmds = generate_systemd_mask_commands(["whoopsie.service", "apport.service"])
        self.assertIn("systemctl stop whoopsie.service 2>/dev/null || true", cmds)
        self.assertIn("systemctl disable whoopsie.service 2>/dev/null || true", cmds)
        self.assertIn("systemctl mask whoopsie.service --now", cmds)
        self.assertIn("systemctl mask apport.service --now", cmds)

    def test_generate_systemd_mask_manifest(self):
        manifest = generate_systemd_mask_manifest()
        self.assertEqual(len(manifest), 11)
        self.assertIn("whoopsie.service", manifest)
        self.assertEqual(manifest["nv-telemetry.service"], UNIT_DESCRIPTIONS["nv-telemetry.service"])


class TestAuditorAndScoring(unittest.TestCase):
    """Test 10-rule posture evaluation and standardized scoring math."""

    def setUp(self):
        with open(PROJECT_DIR / "fixtures" / "hardened_jetson_bsp.json", "r", encoding="utf-8") as f:
            self.hardened_data = json.load(f)

        with open(PROJECT_DIR / "fixtures" / "vulnerable_jetson_bsp.json", "r", encoding="utf-8") as f:
            self.vulnerable_data = json.load(f)

    def test_rule_registry_definitions(self):
        self.assertEqual(len(RULE_REGISTRY), 10)
        self.assertEqual(RULE_REGISTRY[0].id, "LH-JTG-001")
        self.assertEqual(RULE_REGISTRY[0].severity, "CRITICAL")
        self.assertEqual(RULE_REGISTRY[0].weight, 25)

        self.assertEqual(RULE_REGISTRY[3].id, "LH-JTG-004")
        self.assertEqual(RULE_REGISTRY[3].severity, "HIGH")
        self.assertEqual(RULE_REGISTRY[3].weight, 10)

        self.assertEqual(RULE_REGISTRY[7].id, "LH-JTG-008")
        self.assertEqual(RULE_REGISTRY[7].severity, "MEDIUM")
        self.assertEqual(RULE_REGISTRY[7].weight, 4)

        self.assertEqual(RULE_REGISTRY[9].id, "LH-JTG-010")
        self.assertEqual(RULE_REGISTRY[9].severity, "LOW")
        self.assertEqual(RULE_REGISTRY[9].weight, 1)

    def test_hardened_bsp_evaluates_100_percent(self):
        report = audit_bsp_policy(self.hardened_data, "hardened_jetson_bsp.json")
        self.assertEqual(report.score, 100)
        self.assertEqual(report.status, "PASSED")
        self.assertEqual(report.total_rules, 10)
        self.assertEqual(report.passed_rules, 10)
        self.assertEqual(len(report.findings), 0)
        self.assertEqual(report.critical_count, 0)
        self.assertEqual(report.high_count, 0)
        self.assertEqual(report.medium_count, 0)
        self.assertEqual(report.low_count, 0)

    def test_vulnerable_bsp_evaluates_0_percent(self):
        report = audit_bsp_policy(self.vulnerable_data, "vulnerable_jetson_bsp.json")
        self.assertEqual(report.score, 0)
        self.assertEqual(report.status, "FAILED")
        self.assertEqual(report.total_rules, 10)
        self.assertEqual(report.passed_rules, 0)
        self.assertEqual(len(report.findings), 10)
        self.assertEqual(report.critical_count, 3)
        self.assertEqual(report.high_count, 4)
        self.assertEqual(report.medium_count, 2)
        self.assertEqual(report.low_count, 1)

    def test_isolated_rule_triggers(self):
        # 1. LH-JTG-001 (CRITICAL, 25): active services
        p1 = dict(self.hardened_data)
        p1["active_telemetry_services"] = ["nv-telemetry.service"]
        r1 = audit_bsp_policy(p1)
        self.assertEqual(r1.score, 75)
        self.assertEqual(len(r1.findings), 1)
        self.assertEqual(r1.findings[0].rule_id, "LH-JTG-001")

        # 2. LH-JTG-002 (CRITICAL, 25): permissive firewall
        p2 = dict(self.hardened_data)
        p2["egress_default_policy"] = "ACCEPT"
        r2 = audit_bsp_policy(p2)
        self.assertEqual(r2.score, 75)
        self.assertEqual(r2.findings[0].rule_id, "LH-JTG-002")

        # 3. LH-JTG-003 (CRITICAL, 25): unsinkholed domains
        p3 = dict(self.hardened_data)
        p3["telemetry_domains_sinkholed"] = False
        r3 = audit_bsp_policy(p3)
        self.assertEqual(r3.score, 75)
        self.assertEqual(r3.findings[0].rule_id, "LH-JTG-003")

        # 4. LH-JTG-004 (HIGH, 10): auto-update timer
        p4 = dict(self.hardened_data)
        p4["apt_daily_timer_enabled"] = True
        r4 = audit_bsp_policy(p4)
        self.assertEqual(r4.score, 90)
        self.assertEqual(r4.findings[0].rule_id, "LH-JTG-004")

        # 5. LH-JTG-005 (HIGH, 10): connectivity check
        p5 = dict(self.hardened_data)
        p5["connectivity_check_enabled"] = True
        r5 = audit_bsp_policy(p5)
        self.assertEqual(r5.score, 90)
        self.assertEqual(r5.findings[0].rule_id, "LH-JTG-005")

        # 6. LH-JTG-006 (HIGH, 10): public DNS resolver
        p6 = dict(self.hardened_data)
        p6["dns_servers"] = ["8.8.8.8"]
        r6 = audit_bsp_policy(p6)
        self.assertEqual(r6.score, 90)
        self.assertEqual(r6.findings[0].rule_id, "LH-JTG-006")

        # 7. LH-JTG-007 (HIGH, 10): snapd enabled
        p7 = dict(self.hardened_data)
        p7["snapd_enabled"] = True
        r7 = audit_bsp_policy(p7)
        self.assertEqual(r7.score, 90)
        self.assertEqual(r7.findings[0].rule_id, "LH-JTG-007")

        # 8. LH-JTG-008 (MEDIUM, 4): docker telemetry not disabled
        p8 = dict(self.hardened_data)
        p8["docker_telemetry_disabled"] = False
        r8 = audit_bsp_policy(p8)
        self.assertEqual(r8.score, 96)
        self.assertEqual(r8.findings[0].rule_id, "LH-JTG-008")

        # 9. LH-JTG-009 (MEDIUM, 4): coredump upload
        p9 = dict(self.hardened_data)
        p9["coredump_external_upload"] = True
        r9 = audit_bsp_policy(p9)
        self.assertEqual(r9.score, 96)
        self.assertEqual(r9.findings[0].rule_id, "LH-JTG-009")

        # 10. LH-JTG-010 (LOW, 1): public NTP pool
        p10 = dict(self.hardened_data)
        p10["public_ntp_pool_used"] = True
        r10 = audit_bsp_policy(p10)
        self.assertEqual(r10.score, 99)
        self.assertEqual(r10.findings[0].rule_id, "LH-JTG-010")

    def test_compound_score_math(self):
        # 1 CRITICAL (25) + 2 HIGH (20) = 45 penalty -> Score 55
        p = dict(self.hardened_data)
        p["active_telemetry_services"] = ["nv-telemetry.service"]
        p["connectivity_check_enabled"] = True
        p["snapd_enabled"] = True
        r = audit_bsp_policy(p)
        self.assertEqual(r.score, 55)
        self.assertEqual(r.status, "FAILED")
        self.assertEqual(r.critical_count, 1)
        self.assertEqual(r.high_count, 2)


class TestExporters(unittest.TestCase):
    """Test Table, JSON, and OASIS SARIF v2.1.0 output formatting."""

    def setUp(self):
        with open(PROJECT_DIR / "fixtures" / "vulnerable_jetson_bsp.json", "r", encoding="utf-8") as f:
            self.vulnerable_data = json.load(f)
        self.report = audit_bsp_policy(self.vulnerable_data, "vulnerable.json")

    def test_format_table(self):
        table = format_table(self.report)
        self.assertIn("Posture Score:   0/100", table)
        self.assertIn("LH-JTG-001", table)
        self.assertIn("LH-JTG-010", table)
        self.assertIn("Remediation:", table)

    def test_format_json(self):
        json_str = format_json(self.report)
        parsed = json.loads(json_str)
        self.assertEqual(parsed["score"], 0)
        self.assertEqual(parsed["status"], "FAILED")
        self.assertEqual(len(parsed["findings"]), 10)
        self.assertEqual(parsed["findings"][0]["rule_id"], "LH-JTG-001")

    def test_format_sarif(self):
        sarif_str = format_sarif(self.report)
        parsed = json.loads(sarif_str)
        self.assertEqual(parsed["version"], "2.1.0")
        self.assertEqual(parsed["$schema"], "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json")
        runs = parsed["runs"]
        self.assertEqual(len(runs), 1)
        driver = runs[0]["tool"]["driver"]
        self.assertEqual(driver["name"], "lh-telemetry-guard")
        self.assertEqual(driver["version"], "0.1.0")
        self.assertEqual(len(driver["rules"]), 10)
        self.assertEqual(len(runs[0]["results"]), 10)


class TestSubprocessCLI(unittest.TestCase):
    """Test subprocess execution of bin/lh-telemetry-guard CLI."""

    CLI_BIN = str(PROJECT_DIR / "bin" / "lh-telemetry-guard")

    def test_cli_version(self):
        res = subprocess.run([self.CLI_BIN, "--version"], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0)
        self.assertIn("lh-telemetry-guard 0.1.0", res.stdout)

    def test_cli_help(self):
        res = subprocess.run([self.CLI_BIN, "--help"], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0)
        self.assertIn("Operational Subcommands", res.stdout)

    def test_cli_scan_hardened(self):
        res = subprocess.run(
            [self.CLI_BIN, "scan", str(PROJECT_DIR / "fixtures" / "hardened_jetson_bsp.json")],
            capture_output=True,
            text=True,
        )
        self.assertEqual(res.returncode, 0)
        self.assertIn("Posture Score:   100/100", res.stdout)

    def test_cli_scan_vulnerable(self):
        res = subprocess.run(
            [self.CLI_BIN, "scan", str(PROJECT_DIR / "fixtures" / "vulnerable_jetson_bsp.json")],
            capture_output=True,
            text=True,
        )
        self.assertEqual(res.returncode, 1)
        self.assertIn("Posture Score:   0/100", res.stdout)

    def test_cli_gen_firewall(self):
        res = subprocess.run(
            [self.CLI_BIN, "gen-firewall", "--allow-cidr", "192.168.10.0/24"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(res.returncode, 0)
        self.assertIn("table inet lh_telemetry_guard", res.stdout)

    def test_cli_gen_ebpf(self):
        res = subprocess.run(
            [self.CLI_BIN, "gen-ebpf", "--allow-cidr", "192.168.10.0/24"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(res.returncode, 0)
        self.assertIn('SEC("cgroup/connect4")', res.stdout)

    def test_cli_gen_sinkhole(self):
        res = subprocess.run([self.CLI_BIN, "gen-sinkhole"], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0)
        self.assertIn("0.0.0.0 telemetry.nvidia.com", res.stdout)

    def test_cli_analyze_egress_violation(self):
        res = subprocess.run(
            [self.CLI_BIN, "analyze-egress", str(PROJECT_DIR / "fixtures" / "sample_egress_flow.json")],
            capture_output=True,
            text=True,
        )
        self.assertEqual(res.returncode, 1)
        self.assertIn("[VENDOR_TELEMETRY_DOMAIN]", res.stdout)
        self.assertIn("[HIGH_ENTROPY_DNS_EXFILTRATION]", res.stdout)
        self.assertIn("[PERIODIC_TELEMETRY_BEACON]", res.stdout)

    def test_cli_invalid_command_or_args(self):
        res = subprocess.run([self.CLI_BIN, "nonexistent-subcommand"], capture_output=True, text=True)
        self.assertEqual(res.returncode, 2)


if __name__ == "__main__":
    unittest.main()
