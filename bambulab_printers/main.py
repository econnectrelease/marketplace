# Copyright (c) 2026 Đinh Trung Kiên. All rights reserved.
"""
# [INPUT]: depends on driver (validate_command, execute_command, probe_state, discover_devices, detect_chamber_camera_support), json, os, sys
# [OUTPUT]: exports entrypoint hooks for E-Connect runtime (validate_command, execute_command, probe_state, discover_devices, detect_chamber_camera_support)
# [POS]: Extension entrypoint module for econnect_extensions/bambulab_printers
# [PROTOCOL]: Update this header on change
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any

from driver import (
    discover_devices as driver_discover_devices,
    execute_command as driver_execute_command,
    probe_state as driver_probe_state,
    validate_command as driver_validate_command,
)


def validate_command(device: dict[str, Any], command: dict[str, Any]) -> None:
    """Validate printer or camera command payload."""
    driver_validate_command(device, command)


def execute_command(device: dict[str, Any], command: dict[str, Any]) -> dict[str, Any]:
    """Execute action on Bambu Lab printer or camera."""
    return driver_execute_command(device, command)


def probe_state(device: dict[str, Any]) -> dict[str, Any]:
    """Probe telemetry state for printer or chamber camera."""
    return driver_probe_state(device)


def discover_devices() -> list[dict[str, Any]]:
    """Scan local network via SSDP (with mDNS fallback) for Bambu Lab 3D printers."""
    return driver_discover_devices()


def detect_chamber_camera_support(serial_number: str, model: str | None = None) -> dict[str, Any]:
    """Detect chamber camera support from serial number or model."""
    from driver import detect_chamber_camera_support as _detect
    return _detect(serial_number, model)


def main() -> int:
    """Entrypoint CLI execution for testing and local diagnostics."""
    print("=== Bambu Lab 3D Printers Extension for E-Connect ===")
    ip = os.getenv("BAMBU_IP", "127.0.0.1")
    code = os.getenv("BAMBU_ACCESS_CODE", "test_code")
    serial = os.getenv("BAMBU_SERIAL", "").strip()

    config: dict[str, Any] = {
        "ip_address": ip,
        "access_code": code,
    }
    if serial:
        config["serial_number"] = serial

    mock_device = {
        "device_schema_id": "bambu_printer",
        "name": "Bambu Lab Printer",
        "config": config,
    }

    target_label = serial or "auto-resolve"
    print(f"Probing printer state for {target_label} at {ip}...")
    state = probe_state(mock_device)
    print("Resulting State:")
    print(json.dumps(state, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
