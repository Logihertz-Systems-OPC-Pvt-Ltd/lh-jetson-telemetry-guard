# ==============================================================================
# Product:       Logihertz Jetson Telemetry Guard (lh-jetson-telemetry-guard)
# Module:        systemd_sanitizer.py
# Role:          L4T / Ubuntu BSP Telemetry Daemon & Timer Mask Generator
# Organization:  Logihertz Systems (OPC) Private Limited
# Developer:     Sameer Tawade (Creator, Founder, Director & Sole Developer)
# Contact:       ops@logihertz.com / security@logihertz.com
# License:       Apache-2.0
# ==============================================================================

"""Systemd background telemetry unit, crash reporter, and timer mask synthesizer."""

from __future__ import annotations

from typing import Sequence

# Canonical mandatory units and timers that must be masked on sovereign embedded appliances
MANDATORY_MASKED_UNITS: tuple[str, ...] = (
    "whoopsie.service",
    "apport.service",
    "ubuntu-report.service",
    "popularity-contest.service",
    "motd-news.service",
    "motd-news.timer",
    "apt-daily.timer",
    "apt-daily-upgrade.timer",
    "fwupd-refresh.timer",
    "snapd.service",
    "nv-telemetry.service",
)

UNIT_DESCRIPTIONS: dict[str, str] = {
    "whoopsie.service": "Ubuntu crash database submitter daemon",
    "apport.service": "Automatic crash reporting and core dump collection daemon",
    "ubuntu-report.service": "Hardware metrics and telemetry survey reporter",
    "popularity-contest.service": "Debian/Ubuntu package installation survey telemetry",
    "motd-news.service": "Dynamic MOTD outbound WAN news fetch service",
    "motd-news.timer": "Dynamic MOTD periodic fetch timer",
    "apt-daily.timer": "Unattended background package metadata sync timer",
    "apt-daily-upgrade.timer": "Unattended background package installation timer",
    "fwupd-refresh.timer": "LVFS firmware update metadata phone-home timer",
    "snapd.service": "Canonical Snap store daemon and telemetry client",
    "nv-telemetry.service": "NVIDIA developer telemetry and diagnostics collector",
}


def audit_active_units(
    active_units: Sequence[str],
    enabled_timers: Sequence[str] | None = None,
) -> list[str]:
    """Audit active services and timers against the mandatory telemetry mask list.

    Args:
        active_units: Sequence of running systemd service unit names.
        enabled_timers: Optional sequence of active systemd timer unit names.

    Returns:
        List of detected offending unit names.
    """
    detected: list[str] = []
    combined = set(u.strip().lower() for u in active_units)
    if enabled_timers is not None:
        combined.update(t.strip().lower() for t in enabled_timers)

    for target in MANDATORY_MASKED_UNITS:
        if target.lower() in combined:
            detected.append(target)

    return sorted(detected)


def generate_systemd_mask_manifest() -> dict[str, str]:
    """Generate a dictionary mapping each mandatory unit to its security risk description."""
    return dict(UNIT_DESCRIPTIONS)


def generate_systemd_mask_commands(units: Sequence[str] | None = None) -> list[str]:
    """Generate shell commands to permanently stop, disable, and mask telemetry units.

    Args:
        units: Optional list of units to mask; defaults to MANDATORY_MASKED_UNITS.

    Returns:
        List of idempotent shell execution strings.
    """
    targets = sorted(set(units if units is not None else MANDATORY_MASKED_UNITS))
    commands: list[str] = []

    for unit in targets:
        commands.append(f"systemctl stop {unit} 2>/dev/null || true")
        commands.append(f"systemctl disable {unit} 2>/dev/null || true")
        commands.append(f"systemctl mask {unit} --now")

    return commands
