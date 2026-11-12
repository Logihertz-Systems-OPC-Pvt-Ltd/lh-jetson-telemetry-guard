# Contributing to `lh-jetson-telemetry-guard`

Thank you for your interest in contributing to **`lh-jetson-telemetry-guard`** (`lh-telemetry-guard`), part of the Logihertz 60-Tool Open-Source Ecosystem.

## Core Architectural Mandates

1. **Zero External Dependencies**:
   - Runtime dependencies must strictly be `0`.
   - Use only the Python 3.11+ Standard Library (`json`, `ipaddress`, `math`, `hashlib`, `re`, `argparse`, `pathlib`, `dataclasses`, `typing`).
   - Do NOT introduce third-party runtime dependencies (e.g. `requests`, `pydantic`, `dnspython`, `scapy`).
2. **Determinism & Performance**:
   - All Shannon entropy calculations, eBPF C generation, `nftables` synthesis, and posture scoring must be 100% deterministic.
   - Code must execute with sub-50ms CLI startup latency.
3. **Compatibility**:
   - Must execute cleanly and without deprecation warnings on Python 3.11, 3.12, and 3.13.

## Development Setup

```bash
# Clone the repository
git clone https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-jetson-telemetry-guard.git
cd lh-jetson-telemetry-guard

# Run syntax verification
python3 -m py_compile src/lh_jetson_telemetry_guard/*.py tests/*.py

# Execute the test suite
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

## Adding Rules or Curated Domains

- **Domain Sinkhole**: Telemetry domain entries in `domain_sinkhole.py` must represent documented vendor phone-home or diagnostics endpoints for NVIDIA L4T, JetPack, Tegra BSPs, or Ubuntu embedded systems.
- **Posture Rules (`LH-JTG-001` .. `LH-JTG-010`)**: Rule definitions in `auditor.py` must be documented with an official CWE identifier, severity weight, and concrete remediation instructions.

## Code Standards

- Follow PEP 8 style conventions.
- Include complete type annotations on all public functions and methods.
- Every commit must be signed and attributed cleanly.
