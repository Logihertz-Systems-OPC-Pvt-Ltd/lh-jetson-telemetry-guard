# ==============================================================================
# Product:       Logihertz Jetson Telemetry Guard (lh-jetson-telemetry-guard)
# Module:        domain_sinkhole.py
# Role:          Telemetry Domain Matcher, DNS Entropy Analyzer & Hosts Sinkhole
# Organization:  Logihertz Systems (OPC) Private Limited
# Developer:     Sameer Tawade (Creator, Founder, Director & Sole Developer)
# Contact:       ops@logihertz.com / security@logihertz.com
# License:       Apache-2.0
# ==============================================================================

"""Vendor telemetry domain matcher, Shannon entropy DNS exfiltration detector,
and /etc/hosts sinkhole configuration synthesizer.
"""

from __future__ import annotations

import hashlib
import math
from typing import Sequence

# Curated registry of known phone-home and telemetry domains for NVIDIA L4T and Ubuntu
CURATED_TELEMETRY_DOMAINS: tuple[str, ...] = (
    # NVIDIA JetPack / Tegra L4T Telemetry & Diagnostics
    "telemetry.nvidia.com",
    "events.gfe.nvidia.com",
    "ota.nvidia.com",
    "developer.download.nvidia.com",
    "nv-telemetry.nvidia.com",
    "api.developer.nvidia.com",
    "services.gfe.nvidia.com",
    "telemetry.gfe.nvidia.com",
    "telemetry-in.nvidia.com",
    "prod.telemetry.nvidia.com",
    # Canonical / Ubuntu Embedded BSP Telemetry & Reporting
    "metrics.ubuntu.com",
    "popcon.ubuntu.com",
    "daisy.ubuntu.com",
    "errors.ubuntu.com",
    "motd.ubuntu.com",
    "connectivity-check.ubuntu.com",
    "api.snapcraft.io",
    "geoip.ubuntu.com",
    "telemetry.ubuntu.com",
    "upload.ubuntu.com",
)


def is_telemetry_domain(fqdn: str, curated_list: Sequence[str] | None = None) -> bool:
    """Check whether a given FQDN matches or is a subdomain of a known telemetry endpoint.

    Args:
        fqdn: Fully qualified domain name to check.
        curated_list: Optional custom domain list; defaults to CURATED_TELEMETRY_DOMAINS.

    Returns:
        True if the domain is a known vendor telemetry endpoint, False otherwise.
    """
    clean_fqdn = fqdn.strip().rstrip(".").lower()
    if not clean_fqdn:
        return False

    domains_to_check = curated_list if curated_list is not None else CURATED_TELEMETRY_DOMAINS

    for target in domains_to_check:
        clean_target = target.strip().rstrip(".").lower()
        if clean_fqdn == clean_target or clean_fqdn.endswith("." + clean_target):
            return True

    return False


def compute_shannon_entropy(label: str) -> float:
    """Compute the normalized character-level Shannon information entropy in bits/char.

    Formula:
        H(L) = - sum_{c in Sigma} P(c) * log2(P(c))
        where P(c) = count(c) / |L|

    Args:
        label: Text string (e.g. subdomain label).

    Returns:
        Calculated entropy in bits per character (rounded to 4 decimal places).
    """
    if not label:
        return 0.0

    length = len(label)
    char_counts: dict[str, int] = {}
    for char in label:
        char_counts[char] = char_counts.get(char, 0) + 1

    entropy = 0.0
    for count in char_counts.values():
        prob = count / length
        entropy -= prob * math.log2(prob)

    return round(entropy, 4)


def is_high_entropy_dns(
    fqdn: str,
    min_len: int = 16,
    threshold: float = 3.8,
) -> tuple[bool, float, str]:
    """Analyze the leftmost subdomain label of an FQDN for covert DNS exfiltration/tunneling.

    High-entropy labels often indicate base32/base64/hex encoded data exfiltration
    or algorithmic domain generation (DGA) beacons.

    Args:
        fqdn: Fully qualified domain name query string.
        min_len: Minimum length of leftmost label to consider for exfiltration.
        threshold: Shannon entropy threshold in bits/character (standard 3.8).

    Returns:
        Tuple of (is_flagged, computed_entropy, leftmost_label).
    """
    clean = fqdn.strip().rstrip(".")
    if not clean:
        return False, 0.0, ""

    labels = clean.split(".")
    leftmost = labels[0]

    entropy = compute_shannon_entropy(leftmost)
    is_flagged = len(leftmost) >= min_len and entropy >= threshold

    return is_flagged, entropy, leftmost


def compute_coefficient_of_variation(intervals: Sequence[float]) -> float:
    """Calculate the Coefficient of Variation (CV = sigma / mu) for a series of intervals.

    Args:
        intervals: Sequence of time deltas between successive socket/DNS events.

    Returns:
        Coefficient of variation (standard deviation divided by mean).
    """
    if len(intervals) < 2:
        return 0.0

    mean_val = sum(intervals) / len(intervals)
    if mean_val <= 0.0:
        return 0.0

    variance = sum((x - mean_val) ** 2 for x in intervals) / len(intervals)
    std_dev = math.sqrt(variance)

    return round(std_dev / mean_val, 4)


def detect_periodic_beacon(
    timestamps: Sequence[float],
    max_cv: float = 0.05,
    min_events: int = 4,
) -> tuple[bool, float, float]:
    """Detect whether a sequence of connection timestamps represents an automated telemetry heartbeat.

    Automated timer-driven phone-home beacons exhibit tight periodicity with CV < 0.05.

    Args:
        timestamps: Chronological or unsorted timestamp sequence in seconds.
        max_cv: Maximum Coefficient of Variation threshold to flag as periodic.
        min_events: Minimum number of timestamp events required for statistical confidence.

    Returns:
        Tuple of (is_periodic_beacon, calculated_cv, mean_interval_seconds).
    """
    if len(timestamps) < min_events:
        return False, 1.0, 0.0

    sorted_ts = sorted(timestamps)
    deltas = [sorted_ts[i + 1] - sorted_ts[i] for i in range(len(sorted_ts) - 1)]

    # Filter out zero or negative deltas
    valid_deltas = [d for d in deltas if d > 0.0]
    if len(valid_deltas) < min_events - 1:
        return False, 1.0, 0.0

    cv = compute_coefficient_of_variation(valid_deltas)
    mean_interval = round(sum(valid_deltas) / len(valid_deltas), 2)
    is_beacon = cv < max_cv and mean_interval > 0.0

    return is_beacon, cv, mean_interval


def generate_hosts_sinkhole(custom_domains: Sequence[str] | None = None) -> str:
    """Generate a deterministic /etc/hosts sinkhole block mapping telemetry domains to 0.0.0.0 and ::.

    Args:
        custom_domains: Optional domain list; defaults to CURATED_TELEMETRY_DOMAINS.

    Returns:
        Formatted /etc/hosts configuration text including SHA-256 integrity digest.
    """
    domains = sorted(set(custom_domains if custom_domains is not None else CURATED_TELEMETRY_DOMAINS))

    content_for_hash = "\n".join(domains).encode("utf-8")
    sha256_digest = hashlib.sha256(content_for_hash).hexdigest()

    lines = [
        "# ==============================================================================",
        "# Logihertz Jetson Telemetry Guard (lh-telemetry-guard)",
        "# File:          /etc/hosts (Telemetry & Diagnostics Sinkhole)",
        f"# Integrity:     SHA-256: {sha256_digest}",
        f"# Domains Count: {len(domains)}",
        "# ==============================================================================",
        "",
    ]

    for domain in domains:
        lines.append(f"0.0.0.0 {domain}")
        lines.append(f"::      {domain}")

    lines.append("")
    return "\n".join(lines)
