# Copyright (c) 2026 Đinh Trung Kiên. All rights reserved.
"""
# [INPUT]: depends on bambu_mqtt, bambu_ftps, bambu_camera, os, socket, io, threading, time, urllib.parse, logging, typing
# [OUTPUT]: exports BambuDriver, resolve_printer_identity, get_or_create_mqtt_client, get_or_create_camera_adapter, validate_command, execute_command, probe_state, discover_devices, detect_chamber_camera_support, ExtensionRuntimeError
# [POS]: Main hardware orchestration driver for Bambu Lab 3D printers and chamber cameras
# [PROTOCOL]: Update this header on change
"""

from __future__ import annotations

import io
import logging
import os
import socket
import threading
import time
from typing import Any
from urllib.parse import urlsplit

try:
    from app.services.extension_runtime_api import ExtensionRuntimeError
except Exception:
    class ExtensionRuntimeError(RuntimeError):
        def __init__(
            self,
            message: str,
            *,
            mark_offline: bool = False,
            connection_failed: bool = False,
        ) -> None:
            super().__init__(message)
            self.mark_offline = mark_offline
            self.connection_failed = connection_failed

from bambu_camera import BambuCameraAdapter
from bambu_ftps import stream_3mf_to_printer
from bambu_mqtt import (
    BambuMQTTClient,
    detect_bambu_model,
    detect_chamber_camera_support,
    get_bambu_model_capabilities,
    is_valid_bambu_serial,
    resolve_serial_from_tls,
)

logger = logging.getLogger("econnect.bambulab.driver")

_BAMBU_SSDP_ST = "urn:bambulab-com:device:3dprinter:1"
_BAMBU_SSDP_GROUP = "239.255.255.250"
_BAMBU_SSDP_PORTS = (2021, 1900)
_BAMBU_SSDP_MODEL_CODES = {
    "BL-P001": "X1C",
    "BL-P002": "X1E",
    "C11": "P1P",
    "C12": "P1S",
    "N1": "A1_mini",
    "N2S": "A1",
}

# Registry of active printer MQTT/Camera clients and resolved identity cache
_PRINTER_CLIENTS: dict[str, BambuMQTTClient] = {}
_CAMERA_ADAPTERS: dict[str, BambuCameraAdapter] = {}
_RESOLVED_SERIAL_CACHE: dict[str, tuple[str, str | None]] = {}
_REGISTRY_LOCK = threading.Lock()


def _extract_serial_from_usn(raw_usn: str) -> str:
    """Extract Bambu serial token from SSDP USN header."""
    cleaned = (raw_usn or "").strip()
    if not cleaned:
        return ""
    for part in cleaned.replace("::", ":").split(":"):
        candidate = part.strip()
        if is_valid_bambu_serial(candidate):
            return candidate
    return cleaned if is_valid_bambu_serial(cleaned) else ""


def _parse_ssdp_packet(data: bytes) -> dict[str, str] | None:
    """Parse a Bambu Lab SSDP NOTIFY or M-SEARCH response packet."""
    text = data.decode("utf-8", errors="ignore")
    lower_text = text.lower()
    if (
        _BAMBU_SSDP_ST not in lower_text
        and "devmodel.bambu.com" not in lower_text
        and "bambulab" not in lower_text
    ):
        return None

    headers: dict[str, str] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, val = line.split(":", 1)
        k = key.strip().lower()
        if k and k not in headers:
            headers[k] = val.strip()

    serial = _extract_serial_from_usn(headers.get("usn", ""))
    if not serial:
        return None

    raw_model = headers.get("devmodel.bambu.com", "").strip()
    dev_name = headers.get("devname.bambu.com", "").strip()
    model = _BAMBU_SSDP_MODEL_CODES.get(raw_model.upper())
    if not model:
        hint = " ".join(part for part in (raw_model, dev_name) if part)
        model = detect_bambu_model(serial, {"dev_product_name": hint} if hint else None)

    return {
        "serial": serial,
        "model": model,
        "dev_name": dev_name,
        "location": headers.get("location", "").strip(),
    }


def _scan_bambu_ssdp(target_ip: str | None = None, timeout: float = 2.0) -> list[dict[str, Any]]:
    """Actively query and passively listen for Bambu Lab printers over SSDP UDP 2021/1900."""
    msearch = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 1\r\n"
        f"ST: {_BAMBU_SSDP_ST}\r\n"
        "\r\n"
    ).encode("utf-8")

    results: list[dict[str, Any]] = []
    seen_ips: set[str] = set()
    seen_raw: dict[tuple[str, bytes], int] = {}
    sock: socket.socket | None = None

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except OSError:
                pass
        try:
            sock.bind(("", _BAMBU_SSDP_PORTS[0]))
            mreq = socket.inet_aton(_BAMBU_SSDP_GROUP) + socket.inet_aton("0.0.0.0")
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        except OSError:
            pass

        targets: list[tuple[str, int]] = []
        if target_ip:
            for port in _BAMBU_SSDP_PORTS:
                targets.append((target_ip, port))
        for port in _BAMBU_SSDP_PORTS:
            targets.append((_BAMBU_SSDP_GROUP, port))

        for addr in targets:
            try:
                sock.sendto(msearch, addr)
            except OSError:
                pass

        deadline = time.monotonic() + timeout
        fast_timeouts = 0
        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            slice_timeout = min(0.5, remaining)
            sock.settimeout(slice_timeout)
            poll_start = time.monotonic()
            try:
                data, (src_ip, _) = sock.recvfrom(4096)
            except (socket.timeout, TimeoutError):
                if time.monotonic() - poll_start < slice_timeout * 0.25:
                    fast_timeouts += 1
                    if fast_timeouts >= 4:
                        break
                continue
            except OSError:
                break
            fast_timeouts = 0

            raw_key = (src_ip, data)
            seen_raw[raw_key] = seen_raw.get(raw_key, 0) + 1
            if seen_raw[raw_key] >= 5:
                break

            parsed = _parse_ssdp_packet(data)
            if parsed is None:
                continue

            effective_ip = src_ip or parsed.get("location", "")
            if not effective_ip:
                continue
            if target_ip and effective_ip != target_ip:
                continue
            if effective_ip in seen_ips:
                continue
            seen_ips.add(effective_ip)

            results.append({
                "ip": effective_ip,
                "serial": parsed["serial"],
                "model": parsed["model"],
                "dev_name": parsed["dev_name"],
            })
            if target_ip:
                break
    except Exception as exc:
        logger.debug("SSDP discovery notice: %s", exc)
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass

    return results


def _discover_bambu_mdns(timeout: float = 1.5) -> list[dict[str, Any]]:
    """Fallback mDNS PTR probe for '_bambulab._tcp.local'."""
    discovered: list[dict[str, Any]] = []
    mdns_group = ("224.0.0.251", 5353)
    query = (
        b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\t_bambulab\x04_tcp\x05local\x00\x00\x0c\x00\x01"
    )
    sock: socket.socket | None = None
    seen_ips: set[str] = set()
    seen_raw: dict[tuple[str, bytes], int] = {}

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(timeout)
        sock.sendto(query, mdns_group)

        deadline = time.monotonic() + timeout
        fast_timeouts = 0
        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            slice_timeout = min(0.5, remaining)
            sock.settimeout(slice_timeout)
            poll_start = time.monotonic()
            try:
                data, (src_ip, _) = sock.recvfrom(4096)
            except (socket.timeout, TimeoutError):
                if time.monotonic() - poll_start < slice_timeout * 0.25:
                    fast_timeouts += 1
                    if fast_timeouts >= 4:
                        break
                continue
            except OSError:
                break
            fast_timeouts = 0

            raw_key = (src_ip, data)
            seen_raw[raw_key] = seen_raw.get(raw_key, 0) + 1
            if seen_raw[raw_key] >= 5:
                break

            if src_ip in seen_ips:
                continue
            seen_ips.add(src_ip)

            serial = ""
            data_str = data.decode("utf-8", errors="ignore")
            for token in data_str.split():
                clean_tok = "".join(c for c in token if c.isalnum())
                if len(clean_tok) >= 14 and clean_tok[:3].upper() in {
                    "01S", "01P", "00M", "030", "039", "00W", "03W", "01E",
                }:
                    serial = clean_tok
                    break

            if not serial:
                continue

            model = detect_bambu_model(serial)
            discovered.append({
                "ip": src_ip,
                "serial": serial,
                "model": model,
                "dev_name": "",
            })
    except Exception as exc:
        logger.debug("mDNS discovery notice: %s", exc)
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass

    return discovered


def resolve_printer_identity(
    ip: str,
    access_code: str = "",
    config_serial: str = "",
) -> tuple[str, str | None]:
    """Resolve printer serial number and optional model from explicit config, cache, TLS cert, or SSDP."""
    del access_code
    clean_ip = (ip or "").strip()
    clean_serial = (config_serial or "").strip()
    if clean_serial:
        return clean_serial, None

    with _REGISTRY_LOCK:
        cached = _RESOLVED_SERIAL_CACHE.get(clean_ip)
    if cached is not None:
        return cached

    mqtt_port = int(os.getenv("BAMBU_MQTT_PORT", "8883"))
    tls_serial = resolve_serial_from_tls(clean_ip, port=mqtt_port)
    if tls_serial:
        model = detect_bambu_model(tls_serial)
        with _REGISTRY_LOCK:
            _RESOLVED_SERIAL_CACHE[clean_ip] = (tls_serial, model)
        return tls_serial, model

    ssdp_hits = _scan_bambu_ssdp(target_ip=clean_ip, timeout=1.5)
    if ssdp_hits:
        hit = ssdp_hits[0]
        serial = str(hit["serial"])
        model = str(hit.get("model") or detect_bambu_model(serial))
        with _REGISTRY_LOCK:
            _RESOLVED_SERIAL_CACHE[clean_ip] = (serial, model)
        return serial, model

    raise ExtensionRuntimeError(
        f"Could not connect or resolve Bambu Lab printer serial number at {clean_ip}. "
        "Ensure the printer is powered on and LAN Only / Developer Mode is enabled.",
        mark_offline=True,
        connection_failed=True,
    )


def _extract_url_host(url: Any) -> str:
    """Return normalized hostname from a stream URL, or empty string if invalid."""
    if not isinstance(url, str) or not url.strip():
        return ""
    try:
        return (urlsplit(url.strip()).hostname or "").strip().lower()
    except ValueError:
        return ""


def _build_effective_config(device: dict[str, Any]) -> dict[str, Any]:
    """Return a shallow config dict reusing last_state serial only when IP matches stream host."""
    raw_config = device.get("config")
    effective = dict(raw_config) if isinstance(raw_config, dict) else {}
    if str(effective.get("serial_number") or "").strip():
        return effective

    ip = str(effective.get("ip_address") or "").strip()
    last_state = device.get("last_state")
    if not ip or not isinstance(last_state, dict):
        return effective

    state_serial = str(last_state.get("serial_number") or "").strip()
    if not is_valid_bambu_serial(state_serial):
        return effective

    hosts = [
        h
        for h in (
            _extract_url_host(last_state.get("stream_url")),
            _extract_url_host(last_state.get("video_stream")),
        )
        if h
    ]
    if not hosts or any(h != ip.strip("[]").lower() for h in hosts):
        return effective

    effective["serial_number"] = state_serial
    state_model = str(last_state.get("model") or "").strip()
    if state_model and not str(effective.get("model") or "").strip():
        effective["model"] = state_model
    return effective


def get_or_create_mqtt_client(config: dict[str, Any]) -> BambuMQTTClient:
    """Retrieve existing MQTT connection or establish a new client for a printer."""
    ip = str(config.get("ip_address", "")).strip()
    access_code = str(config.get("access_code", "")).strip()
    config_serial = str(config.get("serial_number", "")).strip()

    if not ip or not access_code:
        raise ValueError("Printer configuration must contain ip_address and access_code.")

    serial, resolved_model = resolve_printer_identity(ip, access_code, config_serial)
    model_hint = str(config.get("model") or resolved_model or "").strip() or None

    old_client: BambuMQTTClient | None = None
    needs_connect = False
    with _REGISTRY_LOCK:
        client = _PRINTER_CLIENTS.get(serial)
        if client is None or client.ip != ip or client.access_code != access_code:
            old_client = client
            client = BambuMQTTClient(
                ip=ip,
                access_code=access_code,
                serial_number=serial,
                model=model_hint,
            )
            _PRINTER_CLIENTS[serial] = client
            needs_connect = True
        elif not client.is_connected:
            needs_connect = True

    if old_client is not None:
        old_client.disconnect()
    if needs_connect:
        client.connect()
    return client


def get_or_create_camera_adapter(config: dict[str, Any]) -> BambuCameraAdapter:
    """Retrieve or create the camera feed adapter for a printer."""
    ip = str(config.get("ip_address", "")).strip()
    access_code = str(config.get("access_code", "")).strip()
    config_serial = str(config.get("serial_number", "")).strip()

    if not ip or not access_code:
        raise ValueError("Printer configuration must contain ip_address and access_code.")

    serial, resolved_model = resolve_printer_identity(ip, access_code, config_serial)
    model = str(config.get("model") or resolved_model or detect_bambu_model(serial)).strip()

    with _REGISTRY_LOCK:
        adapter = _CAMERA_ADAPTERS.get(serial)
        if (
            adapter is None
            or adapter.ip != ip
            or adapter.access_code != access_code
            or adapter.model != model.upper()
        ):
            adapter = BambuCameraAdapter(ip=ip, access_code=access_code, serial_number=serial, model=model)
            _CAMERA_ADAPTERS[serial] = adapter
        return adapter


class BambuDriver:
    """Universal controller for Bambu Lab 3D printers and companion chamber cameras."""

    @staticmethod
    def validate_command(device: dict[str, Any], command: dict[str, Any]) -> None:
        """Validate an incoming command before execution.

        Permitted commands:
        - pause: Pause current print job
        - resume: Resume paused print job
        - stop: Cancel current print job
        - set_power / chamber_light / power / E-Connect automation toggle: Turn chamber light on or off
        - upload_3mf: Stream sliced .3mf file from memory
        """
        if not isinstance(command, dict):
            raise ValueError("Command payload must be a JSON object.")

        if "kind" in command and command.get("kind") is not None:
            cmd_kind = str(command.get("kind")).strip().lower()
            if cmd_kind != "action":
                raise ValueError(f"Unsupported command kind '{cmd_kind}'. Only 'action' is supported.")
            if "value" in command:
                raw_val = command["value"]
                if not (isinstance(raw_val, bool) or (isinstance(raw_val, int) and raw_val in (0, 1))):
                    raise ValueError("Automation toggle field 'value' must be a boolean or integer 0/1.")
                if not command.get("action") and not command.get("command") and "power" not in command:
                    return

        action = str(command.get("action") or command.get("command") or "").strip().lower()

        # Check boolean power toggle
        if "power" in command:
            if not isinstance(command["power"], bool):
                raise ValueError("Command field 'power' must be a boolean.")
            return

        if not action:
            raise ValueError("Command must specify 'action', 'command', 'power', or automation toggle 'value'.")

        valid_actions = {
            "pause",
            "resume",
            "stop",
            "set_power",
            "chamber_light",
            "upload_3mf",
            "request_status",
            "snapshot",
            "clear_error",
            "set_nozzle_temp",
            "set_bed_temp",
            "set_fan_speed",
            "set_cooling_fan",
            "set_aux_fan",
            "set_chamber_fan",
            "gcode",
        }
        if action not in valid_actions:
            raise ValueError(f"Unsupported Bambu command action '{action}'. Valid: {sorted(valid_actions)}")

        if action == "set_nozzle_temp":
            val = (
                command.get("temperature")
                if command.get("temperature") is not None
                else command.get("temp")
                if command.get("temp") is not None
                else command.get("target_temp")
                if command.get("target_temp") is not None
                else command.get("value")
            )
            if val is None:
                raise ValueError("Action 'set_nozzle_temp' requires 'temperature', 'temp', 'target_temp', or 'value'.")
            try:
                t = float(val)
                if t < 0 or t > 350:
                    raise ValueError(f"Nozzle temperature {t}°C is out of allowable range (0-350°C).")
            except (ValueError, TypeError) as exc:
                raise ValueError(f"Invalid nozzle temperature parameter: {exc}")

        elif action == "set_bed_temp":
            val = (
                command.get("temperature")
                if command.get("temperature") is not None
                else command.get("temp")
                if command.get("temp") is not None
                else command.get("target_temp")
                if command.get("target_temp") is not None
                else command.get("value")
            )
            if val is None:
                raise ValueError("Action 'set_bed_temp' requires 'temperature', 'temp', 'target_temp', or 'value'.")
            try:
                t = float(val)
                if t < 0 or t > 150:
                    raise ValueError(f"Bed temperature {t}°C is out of allowable range (0-150°C).")
            except (ValueError, TypeError) as exc:
                raise ValueError(f"Invalid bed temperature parameter: {exc}")

        elif action in {"set_fan_speed", "set_cooling_fan", "set_aux_fan", "set_chamber_fan"}:
            val = (
                command.get("speed")
                if command.get("speed") is not None
                else command.get("speed_pct")
                if command.get("speed_pct") is not None
                else command.get("value")
            )
            if val is None:
                raise ValueError(f"Action '{action}' requires 'speed' or 'value'.")
            try:
                s = float(val)
                if s < 0 or s > 100:
                    raise ValueError(f"Fan speed {s}% is out of allowable range (0-100%).")
            except (ValueError, TypeError) as exc:
                raise ValueError(f"Invalid fan speed parameter: {exc}")

        elif action == "gcode":
            gcode_str = command.get("gcode") or command.get("param") or command.get("value")
            if not gcode_str or not isinstance(gcode_str, str):
                raise ValueError("Action 'gcode' requires a non-empty string in 'gcode', 'param', or 'value'.")

        elif action == "upload_3mf":
            filename = command.get("filename")
            if not filename or not isinstance(filename, str):
                raise ValueError("Action 'upload_3mf' requires a non-empty string 'filename'.")
            if not (filename.endswith(".3mf") or filename.endswith(".gcode")):
                raise ValueError("Action 'upload_3mf' filename must end with .3mf or .gcode.")
            raw_parts = filename.replace("\\", "/").split("/")
            if ".." in raw_parts or "/" in filename or "\\" in filename:
                raise ValueError(f"Path traversal detected in upload_3mf filename '{filename}'.")
            if "file_data" not in command and "file_stream" not in command:
                raise ValueError("Action 'upload_3mf' requires in-memory 'file_data' or 'file_stream'.")

    @staticmethod
    def execute_command(device: dict[str, Any], command: dict[str, Any]) -> dict[str, Any]:
        """Execute a validated command on the target Bambu Lab device."""
        BambuDriver.validate_command(device, command)
        effective_config = _build_effective_config(device)
        schema_id = device.get("device_schema_id") or device.get("schema_id", "bambu_printer")

        action = str(command.get("action") or command.get("command") or "").strip().lower()

        # Handle Snapshot command (applies to both bambu_printer and legacy bambu_camera)
        if action == "snapshot":
            camera = get_or_create_camera_adapter(effective_config)
            snapshot_bytes = camera.get_snapshot()
            return {
                "conn_status": "online",
                "state": {
                    "snapshot_length": len(snapshot_bytes),
                    "stream_url": camera.get_stream_url(),
                    "power": True,
                    "has_camera": True,
                    "chamber_camera_supported": True,
                },
            }

        # Handle Camera Schema Commands (legacy)
        if schema_id == "bambu_camera":
            camera = get_or_create_camera_adapter(effective_config)
            return {
                "conn_status": "online",
                "state": {
                    "stream_url": camera.get_stream_url(),
                    "video_stream": camera.get_stream_url(),
                    "power": True,
                    "has_camera": True,
                    "chamber_camera_supported": True,
                },
            }

        # Handle Printer Schema Commands
        client = get_or_create_mqtt_client(effective_config)

        # Check if printer client is currently blocked by Developer Mode or Access Control System
        if client.last_error and action != "clear_error":
            if "BAMBU_DEV_MODE_REQUIRED" in client.last_error or "84033543" in client.last_error:
                raise ExtensionRuntimeError(
                    "Máy in Bambu Lab từ chối lệnh (err_code: 84033543). Vui lòng vào Cài đặt màn hình máy in -> Mạng (WLAN) -> Bật 'Chế độ nhà phát triển' (Developer Mode) và khởi động lại máy in để cho phép điều khiển qua mạng LAN.",
                    mark_offline=False,
                )
            if "ACS" in client.last_error:
                raise ExtensionRuntimeError(
                    f"Bambu Lab printer command '{action or 'toggle'}' blocked by Access Control System (firmware 01.05.00.00+): {client.last_error}",
                    mark_offline=False,
                )

        is_automation_toggle = str(command.get("kind") or "").strip().lower() == "action" and "value" in command

        cmd_ok = True
        if action == "clear_error":
            client.clear_error()
            return BambuDriver.probe_state(device)
        elif is_automation_toggle:
            cmd_ok = client.set_chamber_light(bool(command["value"]))
        elif "power" in command:
            power_val = bool(command["power"])
            cmd_ok = client.set_chamber_light(power_val)
        elif action in {"set_power", "chamber_light"}:
            state_val = str(command.get("state", "on")).strip().lower() in {"on", "true", "1"}
            cmd_ok = client.set_chamber_light(state_val)
        elif action == "pause":
            cmd_ok = client.pause_print()
        elif action == "resume":
            cmd_ok = client.resume_print()
        elif action == "stop":
            cmd_ok = client.stop_print()
        elif action == "request_status":
            cmd_ok = client.request_full_status()
        elif action == "set_nozzle_temp":
            val = (
                command.get("temperature")
                if command.get("temperature") is not None
                else command.get("temp")
                if command.get("temp") is not None
                else command.get("target_temp")
                if command.get("target_temp") is not None
                else command.get("value", 0)
            )
            cmd_ok = client.set_nozzle_temperature(float(val))
        elif action == "set_bed_temp":
            val = (
                command.get("temperature")
                if command.get("temperature") is not None
                else command.get("temp")
                if command.get("temp") is not None
                else command.get("target_temp")
                if command.get("target_temp") is not None
                else command.get("value", 0)
            )
            cmd_ok = client.set_bed_temperature(float(val))
        elif action == "set_fan_speed":
            fan = str(command.get("fan") or command.get("fan_type") or "cooling")
            val = (
                command.get("speed")
                if command.get("speed") is not None
                else command.get("speed_pct")
                if command.get("speed_pct") is not None
                else command.get("value", 0)
            )
            cmd_ok = client.set_fan_speed(fan, float(val))
        elif action == "set_cooling_fan":
            val = (
                command.get("speed")
                if command.get("speed") is not None
                else command.get("speed_pct")
                if command.get("speed_pct") is not None
                else command.get("value", 0)
            )
            cmd_ok = client.set_fan_speed("cooling", float(val))
        elif action == "set_aux_fan":
            val = (
                command.get("speed")
                if command.get("speed") is not None
                else command.get("speed_pct")
                if command.get("speed_pct") is not None
                else command.get("value", 0)
            )
            cmd_ok = client.set_fan_speed("aux", float(val))
        elif action == "set_chamber_fan":
            val = (
                command.get("speed")
                if command.get("speed") is not None
                else command.get("speed_pct")
                if command.get("speed_pct") is not None
                else command.get("value", 0)
            )
            cmd_ok = client.set_fan_speed("chamber", float(val))
        elif action == "gcode":
            gcode_line = str(command.get("gcode") or command.get("param") or command.get("value") or "")
            cmd_ok = client.send_gcode(gcode_line)
        elif action == "upload_3mf":
            filename = str(command["filename"])
            raw_data = command.get("file_data")
            file_stream_obj = command.get("file_stream")
            if file_stream_obj is not None and hasattr(file_stream_obj, "read"):
                stream = file_stream_obj
            elif isinstance(raw_data, (bytes, bytearray)):
                stream = io.BytesIO(raw_data)
            else:
                stream = io.BytesIO(str(raw_data or "").encode("utf-8"))

            ip = str(effective_config.get("ip_address"))
            code = str(effective_config.get("access_code"))
            stream_3mf_to_printer(ip, code, stream, filename)

        if not cmd_ok:
            if client.last_error and ("BAMBU_DEV_MODE_REQUIRED" in client.last_error or "84033543" in client.last_error):
                raise ExtensionRuntimeError(
                    "Máy in Bambu Lab từ chối lệnh (err_code: 84033543). Vui lòng vào Cài đặt màn hình máy in -> Mạng (WLAN) -> Bật 'Chế độ nhà phát triển' (Developer Mode) và khởi động lại máy in để cho phép điều khiển qua mạng LAN.",
                    mark_offline=False,
                )
            if client.last_error and "ACS" in client.last_error:
                raise ExtensionRuntimeError(
                    f"Bambu Lab printer command '{action or 'toggle'}' blocked by Access Control System: {client.last_error}",
                    mark_offline=False,
                )
            raise ExtensionRuntimeError(
                "Printer is offline or failed to receive MQTT command.",
                mark_offline=True,
                connection_failed=True,
            )

        if client.last_error and ("BAMBU_DEV_MODE_REQUIRED" in client.last_error or "84033543" in client.last_error):
            raise ExtensionRuntimeError(
                "Máy in Bambu Lab từ chối lệnh (err_code: 84033543). Vui lòng vào Cài đặt màn hình máy in -> Mạng (WLAN) -> Bật 'Chế độ nhà phát triển' (Developer Mode) và khởi động lại máy in để cho phép điều khiển qua mạng LAN.",
                mark_offline=False,
            )

        return BambuDriver.probe_state(device)

    @staticmethod
    def probe_state(device: dict[str, Any]) -> dict[str, Any]:
        """Query live telemetry state from the printer or camera.

        Returns state conforming to E-Connect v2 generic metric slots:
        - value: Status string (IDLE, RUNNING, PAUSE, FINISH, FAILED)
        - value1: Progress percentage (0 - 100 %)
        - value2: Remaining time (minutes)
        - value3: Print subtask name
        - value4: Nozzle temperature (°C)
        - value5: Bed temperature (°C)
        """
        effective_config = _build_effective_config(device)
        schema_id = device.get("device_schema_id") or device.get("schema_id", "bambu_printer")

        if schema_id == "bambu_camera":
            camera = get_or_create_camera_adapter(effective_config)
            return {
                "conn_status": "online",
                "state": {
                    "serial_number": camera.serial_number,
                    "video_stream": camera.get_stream_url(),
                    "stream_url": camera.get_stream_url(),
                    "power": True,
                    "model": camera.model,
                },
            }

        client = get_or_create_mqtt_client(effective_config)
        if client.auth_error:
            raise ExtensionRuntimeError(
                f"Bambu Lab authentication failed (verify LAN Access Code): {client.auth_error}",
                mark_offline=True,
                connection_failed=True,
            )

        cached = client.get_latest_state()
        serial = client.serial_number
        model = cached.get("model") or detect_bambu_model(serial)
        camera = get_or_create_camera_adapter({**effective_config, "serial_number": serial, "model": model})
        stream_url = camera.get_stream_url()

        caps = get_bambu_model_capabilities(model)
        has_chamber = bool(cached.get("has_chamber", caps["has_chamber"]))
        has_chamber_fan = bool(cached.get("has_chamber_fan", caps["has_chamber_fan"]))
        has_aux_fan = bool(cached.get("has_aux_fan", caps["has_aux_fan"]))
        has_cooling_fan = bool(cached.get("has_cooling_fan", caps.get("has_cooling_fan", True)))

        state_payload = {
            "serial_number": serial,
            "value": cached["status"],
            "value1": cached["progress"],
            "value2": cached["remaining_time"],
            "value3": cached["subtask_name"],
            "value4": cached["nozzle_temp"],
            "value5": cached["bed_temp"],
            "status": cached["status"],
            "progress": cached["progress"],
            "remaining_time": cached["remaining_time"],
            "subtask_name": cached["subtask_name"],
            "nozzle_temp": cached["nozzle_temp"],
            "target_nozzle_temp": cached.get("target_nozzle_temp", 0),
            "bed_temp": cached["bed_temp"],
            "target_bed_temp": cached.get("target_bed_temp", 0),
            "cooling_fan_speed": cached.get("cooling_fan_speed", 0),
            "aux_fan_speed": cached.get("aux_fan_speed", 0) if has_aux_fan else 0,
            "chamber_fan_speed": cached.get("chamber_fan_speed", 0) if has_chamber_fan else 0,
            "has_chamber": has_chamber,
            "has_chamber_fan": has_chamber_fan,
            "has_aux_fan": has_aux_fan,
            "has_cooling_fan": has_cooling_fan,
            "chamber_light": cached.get("chamber_light", "off"),
            "power": cached.get("chamber_light") == "on",
            "model": model,
            "has_camera": True,
            "chamber_camera_supported": True,
            "video_stream": stream_url,
            "stream_url": stream_url,
        }

        if has_chamber:
            state_payload["chamber_temp"] = cached.get("chamber_temp", 0.0)

        return {
            "conn_status": "online" if client.is_connected else "offline",
            "state": state_payload,
        }

    @staticmethod
    def discover_devices() -> list[dict[str, Any]]:
        """Discover Bambu Lab printers on the local LAN via SSDP (UDP 2021/1900) with mDNS fallback."""
        hits = _scan_bambu_ssdp(target_ip=None, timeout=2.0)
        if not hits:
            hits = _discover_bambu_mdns(timeout=1.5)

        discovered: list[dict[str, Any]] = []
        for hit in hits:
            src_ip = str(hit["ip"])
            serial = str(hit["serial"])
            model = str(hit["model"])
            dev_name = str(hit.get("dev_name") or "").strip()

            if is_valid_bambu_serial(serial):
                with _REGISTRY_LOCK:
                    _RESOLVED_SERIAL_CACHE[src_ip] = (serial, model)

            display_name = dev_name or f"Bambu Lab {model} ({serial[-6:]})"
            discovered.append({
                "device_schema_id": "bambu_printer",
                "name": display_name,
                "default_name": dev_name or f"Bambu Lab {model}",
                "config": {
                    "ip_address": src_ip,
                    "serial_number": serial,
                    "access_code": "",
                },
                "display": {
                    "card_type": "sensor",
                },
                "extra": {
                    "model": model,
                    "serial_number": serial,
                    "dev_name": dev_name or f"Bambu Lab {model}",
                    "has_camera": True,
                    "chamber_camera_supported": True,
                },
            })

        return discovered


# Top-level functional hooks bound to BambuDriver
def validate_command(device: dict[str, Any], command: dict[str, Any]) -> None:
    BambuDriver.validate_command(device, command)


def execute_command(device: dict[str, Any], command: dict[str, Any]) -> dict[str, Any]:
    return BambuDriver.execute_command(device, command)


def probe_state(device: dict[str, Any]) -> dict[str, Any]:
    return BambuDriver.probe_state(device)


def discover_devices() -> list[dict[str, Any]]:
    return BambuDriver.discover_devices()


def detect_chamber_camera_support(serial_number: str, model: str | None = None) -> dict[str, Any]:
    from bambu_mqtt import detect_chamber_camera_support as _detect
    return _detect(serial_number, model)
