# Copyright (c) 2026 Đinh Trung Kiên. All rights reserved.
"""
# [INPUT]: depends on ipaddress, socket, ssl, json, os, time, threading, logging, typing (and optional cryptography, paho.mqtt.client)
# [OUTPUT]: exports BambuMQTTClient, NotificationService, detect_bambu_model, detect_chamber_camera_support, resolve_serial_from_tls, is_valid_bambu_serial
# [POS]: MQTT telemetry, TLS serial resolution, and command transport client for Bambu Lab 3D printers
# [PROTOCOL]: Update this header on change
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import socket
import ssl
import threading
import time
from typing import Any, Callable

logger = logging.getLogger("econnect.bambulab.mqtt")

try:
    import paho.mqtt.client as mqtt
except ImportError:
    mqtt = None


class NotificationService:
    """Central event notification service for Bambu Lab state transitions and alerts.

    Dispatches notifications when 3D print jobs finish, pause, or fail.
    """

    _listeners: list[Callable[[dict[str, Any]], None]] = []
    _history: list[dict[str, Any]] = []
    _lock = threading.Lock()

    @classmethod
    def register_listener(cls, callback: Callable[[dict[str, Any]], None]) -> None:
        """Register a callback listener function for notifications."""
        with cls._lock:
            cls._listeners.append(callback)

    @classmethod
    def notify(
        cls,
        title: str,
        message: str,
        level: str = "info",
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Dispatch a notification event to E-Connect and logged history."""
        event = {
            "title": title,
            "message": message,
            "level": level,
            "timestamp": time.time(),
            "metadata": metadata or {},
        }
        with cls._lock:
            cls._history.append(event)
            if len(cls._history) > 100:
                cls._history.pop(0)

        logger.info("[NOTIFICATION][%s] %s: %s | %s", level.upper(), title, message, metadata)

        for listener in cls._listeners:
            try:
                listener(event)
            except Exception as exc:
                logger.warning("Notification listener error: %s", exc)

        # Bridge to central E-Connect NotificationService if available in host environment
        try:
            from app.services.notification_service import NotificationService as CentralNotificationService
            CentralNotificationService.notify(
                title=title,
                message=message,
                severity=level,
                category="health" if level in ("warning", "error", "critical") else "lifecycle",
                details=metadata,
            )
        except Exception:
            pass

        return event

    @classmethod
    def get_recent_notifications(cls) -> list[dict[str, Any]]:
        """Return the latest dispatched notifications."""
        with cls._lock:
            return list(cls._history)


def detect_bambu_model(serial: str, telemetry: dict[str, Any] | None = None) -> str:
    """Identify the exact Bambu Lab model: A1, A1_mini, P1P, P1S, X1C, or X1E.

    Uses telemetry product identifiers if available, falling back to hardware
    serial number prefix heuristics.
    """
    if telemetry:
        print_data = telemetry.get("print", {}) if isinstance(telemetry.get("print"), dict) else telemetry
        dev_name = str(
            print_data.get("dev_product_name")
            or telemetry.get("dev_product_name")
            or telemetry.get("model")
            or ""
        ).upper()

        if "X1E" in dev_name:
            return "X1E"
        if "X1" in dev_name or "CARBON" in dev_name:
            return "X1C"
        if "P1S" in dev_name:
            return "P1S"
        if "P1P" in dev_name:
            return "P1P"
        if "MINI" in dev_name:
            return "A1_mini"
        if "A1" in dev_name:
            return "A1"

    s = (serial or "").strip().upper()
    if s.startswith("01E"):
        return "X1E"
    if s.startswith("01S"):
        return "X1C"
    if s.startswith("00M"):
        return "P1S"
    if s.startswith("01P"):
        return "P1P"
    if s.startswith("00W") or s.startswith("03W"):
        return "A1_mini"
    if s.startswith("030") or s.startswith("039"):
        return "A1"

    return "P1S"


def detect_chamber_camera_support(serial_number: str, model: str | None = None) -> dict[str, Any]:
    """Identify chamber camera support and transport protocol for Bambu Lab printers.

    Hardware serial prefix mapping:
    - 01E: X1E (Port 322 RTSPS)
    - 01S: X1C (Port 322 RTSPS)
    - 00M: P1S (Port 6000 MJPEG)
    - 01P: P1P (Port 6000 MJPEG)
    - 00W / 03W: A1 mini (Port 6000 MJPEG)
    - 030 / 039: A1 (Port 6000 MJPEG)
    All of these models feature chamber camera support.
    """
    resolved_model = model or detect_bambu_model(serial_number)
    s = (serial_number or "").strip().upper()

    supported_prefixes = ("01E", "01S", "00M", "01P", "00W", "03W", "030", "039")
    supported_models = {"X1E", "X1C", "P1S", "P1P", "A1_MINI", "A1"}

    is_supported = (
        any(s.startswith(p) for p in supported_prefixes)
        or resolved_model.upper() in supported_models
    )
    if not is_supported and resolved_model:
        is_supported = True

    is_x1 = "X1" in resolved_model.upper()
    return {
        "supported": is_supported,
        "model": resolved_model,
        "stream_type": "rtsps" if is_x1 else "mjpeg",
        "default_port": 322 if is_x1 else 6000,
    }


def _is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _parse_fan_speed(raw: Any, fallback: int = 0) -> int:
    """Convert fan speed representation (0-15 level or 0-100 percentage) to integer percentage 0-100."""
    if raw is None:
        return fallback
    try:
        val = float(raw)
        if val <= 0:
            return 0
        if val <= 15:
            return int(round(val * 100.0 / 15.0))
        return int(round(min(100.0, max(0.0, val))))
    except (ValueError, TypeError):
        return fallback


def is_valid_bambu_serial(candidate: str | None) -> bool:
    """Return True if candidate matches Bambu Lab serial constraints (alnum, len>=10, not IP)."""
    if not isinstance(candidate, str):
        return False
    cleaned = candidate.strip()
    if len(cleaned) < 10 or _is_ip_address(cleaned):
        return False
    return cleaned.isascii() and cleaned.isalnum()


def _read_der_tlv(data: bytes, offset: int) -> tuple[int, bytes, int]:
    """Read a single ASN.1 DER Tag-Length-Value tuple with strict bounds checks."""
    if offset >= len(data):
        raise ValueError("Truncated DER structure")
    tag = data[offset]
    idx = offset + 1
    if (tag & 0x1F) == 0x1F:
        while idx < len(data) and (data[idx] & 0x80):
            idx += 1
        idx += 1
    if idx >= len(data):
        raise ValueError("Truncated DER length")

    len_byte = data[idx]
    idx += 1
    if len_byte < 0x80:
        length = len_byte
    else:
        num_octets = len_byte & 0x7F
        if num_octets == 0 or idx + num_octets > len(data):
            raise ValueError("Invalid DER length encoding")
        length = int.from_bytes(data[idx : idx + num_octets], "big")
        idx += num_octets

    end = idx + length
    if end > len(data):
        raise ValueError("DER element exceeds buffer length")
    return tag, data[idx:end], end


def _extract_cn_from_der_asn1(der_bytes: bytes) -> str | None:
    """Pure-stdlib ASN.1/DER X.509 parser extracting Subject commonName (OID 2.5.4.3)."""
    try:
        cert_tag, cert_body, _ = _read_der_tlv(der_bytes, 0)
        if cert_tag != 0x30:
            return None
        tbs_tag, tbs_body, _ = _read_der_tlv(cert_body, 0)
        if tbs_tag != 0x30:
            return None

        pos = 0
        tag, _, pos = _read_der_tlv(tbs_body, pos)
        # Optional explicit version [0]
        if tag == 0xA0:
            tag, _, pos = _read_der_tlv(tbs_body, pos)
        # serialNumber (INTEGER 0x02) already consumed; skip signature, issuer, validity
        if tag != 0x02:
            return None
        for expected_tag in (0x30, 0x30, 0x30):
            tag, _, pos = _read_der_tlv(tbs_body, pos)
            if tag != expected_tag:
                return None

        subj_tag, subj_body, _ = _read_der_tlv(tbs_body, pos)
        if subj_tag != 0x30:
            return None

        cns: list[str] = []
        s_pos = 0
        while s_pos < len(subj_body):
            rdn_tag, rdn_body, s_pos = _read_der_tlv(subj_body, s_pos)
            if rdn_tag != 0x31:
                continue
            r_pos = 0
            while r_pos < len(rdn_body):
                atv_tag, atv_body, r_pos = _read_der_tlv(rdn_body, r_pos)
                if atv_tag != 0x30:
                    continue
                oid_tag, oid_val, a_pos = _read_der_tlv(atv_body, 0)
                if oid_tag == 0x06 and oid_val == b"\x55\x04\x03" and a_pos < len(atv_body):
                    val_tag, val_bytes, _ = _read_der_tlv(atv_body, a_pos)
                    if val_tag == 0x1E:
                        decoded = val_bytes.decode("utf-16-be", errors="ignore").strip()
                    else:
                        decoded = val_bytes.decode("utf-8", errors="ignore").strip()
                    if decoded:
                        cns.append(decoded)
        for cn in cns:
            if is_valid_bambu_serial(cn):
                return cn
        return cns[0] if cns else None
    except Exception:
        return None


def _extract_cns_from_der(der_bytes: bytes) -> list[str]:
    """Extract Subject CommonName(s) from DER X.509 bytes using cryptography with stdlib fallback."""
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
    except ImportError:
        cn = _extract_cn_from_der_asn1(der_bytes)
        return [cn] if cn else []

    try:
        cert = x509.load_der_x509_certificate(der_bytes)
        attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        return [str(attr.value).strip() for attr in attrs if getattr(attr, "value", None)]
    except Exception:
        return []


def resolve_serial_from_tls(ip: str, port: int = 8883, timeout: float | None = None) -> str | None:
    """Connect over TCP+TLS to a Bambu printer and extract its serial number from cert Subject CN."""
    clean_ip = (ip or "").strip()
    if not clean_ip:
        return None

    if timeout is None:
        timeout = float(os.getenv("BAMBU_TLS_PROBE_TIMEOUT", "4.0"))

    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE

    raw_sock: socket.socket | None = None
    tls_sock: ssl.SSLSocket | None = None
    deadline = time.monotonic() + max(0.2, timeout)
    try:
        raw_sock = socket.create_connection((clean_ip, port), timeout=timeout)
        raw_sock.settimeout(max(0.2, deadline - time.monotonic()))
        tls_sock = ssl_ctx.wrap_socket(raw_sock, server_hostname=clean_ip)
        tls_sock.settimeout(max(0.2, deadline - time.monotonic()))
        der_cert = tls_sock.getpeercert(binary_form=True)
        if not der_cert:
            return None
        for cn in _extract_cns_from_der(der_cert):
            if is_valid_bambu_serial(cn):
                return cn.strip()
        return None
    except Exception as exc:
        logger.debug("TLS serial resolution failed for %s:%d: %s", clean_ip, port, exc)
        return None
    finally:
        if tls_sock is not None:
            try:
                tls_sock.close()
            except Exception:
                pass
        elif raw_sock is not None:
            try:
                raw_sock.close()
            except Exception:
                pass


class BambuMQTTClient:
    """MQTT client for Bambu Lab printers over TLS Port 8883.

    Handles continuous telemetry reception, command dispatch, and state transition alerts.
    """

    def __init__(
        self,
        ip: str,
        access_code: str,
        serial_number: str,
        model: str | None = None,
    ) -> None:
        self.ip = ip
        self.access_code = access_code
        self.serial_number = serial_number
        self.model = model or detect_bambu_model(serial_number)

        self._client: Any = None
        self._connected = False
        self._lock = threading.Lock()
        self._connect_event = threading.Event()
        self._telemetry_event = threading.Event()
        self._last_state: dict[str, Any] = {
            "status": "IDLE",
            "progress": 0,
            "remaining_time": 0,
            "subtask_name": "",
            "nozzle_temp": 0.0,
            "target_nozzle_temp": 0.0,
            "bed_temp": 0.0,
            "target_bed_temp": 0.0,
            "chamber_temp": 0.0,
            "chamber_light": "off",
            "cooling_fan_speed": 0,
            "aux_fan_speed": 0,
            "chamber_fan_speed": 0,
            "has_chamber_fan": ("X1" in (self.model or "").upper() or "P1S" in (self.model or "").upper()),
            "model": self.model,
            "last_updated": 0,
        }
        self._previous_gcode_state: str = "IDLE"
        self._last_error: str | None = None
        self._auth_error: str | None = None

    @property
    def auth_error(self) -> str | None:
        """Return MQTT authentication rejection message if any."""
        with self._lock:
            return self._auth_error

    @property
    def last_error(self) -> str | None:
        """Return the latest error or ACS restriction message if any."""
        with self._lock:
            return self._last_error

    def clear_error(self) -> None:
        """Clear recorded error state."""
        with self._lock:
            self._last_error = None
            self._auth_error = None

    @property
    def is_connected(self) -> bool:
        with self._lock:
            return self._connected

    def get_latest_state(self) -> dict[str, Any]:
        with self._lock:
            return dict(self._last_state)

    @staticmethod
    def _cleanup_paho_client(client: Any) -> None:
        if client is None:
            return
        try:
            client.loop_stop()
        except Exception:
            pass
        try:
            client.disconnect()
        except Exception:
            pass

    def connect(self, timeout: float | None = None, telemetry_wait: float | None = None) -> bool:
        """Connect to the printer's local MQTT broker over TLS port 8883."""
        if timeout is None:
            timeout = float(os.getenv("BAMBU_MQTT_TIMEOUT", "5.0"))
        if telemetry_wait is None:
            telemetry_wait = float(os.getenv("BAMBU_TELEMETRY_WAIT", "1.8"))

        if mqtt is None:
            logger.warning("paho-mqtt is not installed; MQTT client running in simulation/fallback mode.")
            with self._lock:
                self._connected = True
                self._auth_error = None
            return True

        old_client: Any = None
        with self._lock:
            if self._connected and self._client is not None:
                return True
            if self._client is not None:
                old_client = self._client
                self._client = None
            self._connected = False
            self._auth_error = None
            self._connect_event.clear()
            self._telemetry_event.clear()

        if old_client is not None:
            self._cleanup_paho_client(old_client)

        try:
            client = mqtt.Client(
                callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
                client_id=f"econnect_bambu_{self.serial_number[-6:]}",
                protocol=mqtt.MQTTv311,
            )
        except AttributeError:
            client = mqtt.Client(
                client_id=f"econnect_bambu_{self.serial_number[-6:]}",
                protocol=mqtt.MQTTv311,
            )

        if hasattr(client, "connect_timeout"):
            try:
                client.connect_timeout = timeout
            except Exception:
                pass

        client.username_pw_set("bblp", self.access_code)

        # Configure TLS with self-signed certificate acceptance
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
        client.tls_set_context(ssl_ctx)

        client.on_connect = self._on_connect
        client.on_disconnect = self._on_disconnect
        client.on_message = self._on_message

        try:
            mqtt_port = int(os.getenv("BAMBU_MQTT_PORT", "8883"))
            with self._lock:
                self._client = client
            client.connect(self.ip, mqtt_port, keepalive=60)
            client.loop_start()
        except Exception as exc:
            logger.error("Failed to connect MQTT to Bambu printer %s: %s", self.ip, exc)
            with self._lock:
                if self._client is client:
                    self._client = None
                self._connected = False
                if not self._auth_error:
                    self._last_error = f"MQTT connection failed: {exc}"
            self._cleanup_paho_client(client)
            return False

        # Wait outside self._lock so MQTT callbacks cannot deadlock
        self._connect_event.wait(timeout=timeout)

        with self._lock:
            auth_err = self._auth_error
            connected = self._connected

        if auth_err or not connected:
            self.disconnect()
            return False

        if telemetry_wait > 0:
            self._telemetry_event.wait(timeout=telemetry_wait)

        return True

    def disconnect(self) -> None:
        """Gracefully disconnect MQTT client."""
        with self._lock:
            client = self._client
            self._client = None
            self._connected = False
        self._cleanup_paho_client(client)

    def _on_connect(self, client: Any, userdata: Any, flags: Any, rc: Any, properties: Any = None) -> None:
        is_fail = (
            bool(getattr(rc, "is_failure", False))
            or (isinstance(rc, int) and rc != 0)
            or (hasattr(rc, "value") and rc.value != 0)
        )
        if is_fail:
            err_msg = f"MQTT connection rejected (code={rc})"
            logger.warning("MQTT auth/connect rejected for Bambu Lab printer %s: %s", self.ip, err_msg)
            with self._lock:
                if self._client is not None and client is not self._client:
                    return
                self._connected = False
                self._auth_error = err_msg
                self._last_error = err_msg
            self._connect_event.set()
            return

        logger.info("Connected to Bambu Lab printer %s via MQTT", self.ip)
        with self._lock:
            if self._client is not None and client is not self._client:
                return
            self._auth_error = None
            if self._last_error and not str(self._last_error).startswith("ACS_DENIED"):
                self._last_error = None
            self._connected = True

        topic = f"device/{self.serial_number}/report"
        client.subscribe(topic)
        self._connect_event.set()
        self.request_full_status()

    def _on_disconnect(self, client: Any, userdata: Any, flags: Any = None, rc: Any = None, properties: Any = None) -> None:
        logger.warning("Disconnected from Bambu Lab printer %s MQTT", self.ip)
        with self._lock:
            if self._client is not None and client is not self._client:
                return
            self._connected = False
        self._connect_event.set()

    def _on_message(self, client: Any, userdata: Any, msg: Any) -> None:
        """Handle incoming telemetry reports from the printer."""
        try:
            payload = json.loads(msg.payload.decode("utf-8", errors="ignore"))
            self.update_telemetry(payload)
        except Exception as exc:
            logger.debug("Telemetry parse error: %s", exc)

    def update_telemetry(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Parse raw telemetry payload and update state cache, triggering alerts on transitions."""
        print_data = payload.get("print", {}) if isinstance(payload.get("print"), dict) else payload

        # Detect printer model from telemetry if not already locked
        detected_model = detect_bambu_model(self.serial_number, payload)
        self.model = detected_model

        with self._lock:
            self._connected = True
            # Gcode execution state: IDLE, PREPARE, RUNNING, PAUSE, FINISH, FAILED
            raw_state = print_data.get("gcode_state", self._last_state["status"])
            current_state = str(raw_state).upper()

            progress = int(print_data.get("mc_percent", self._last_state["progress"]) or 0)
            remaining_time = int(print_data.get("mc_remaining_time", self._last_state["remaining_time"]) or 0)
            subtask_name = str(print_data.get("subtask_name", self._last_state["subtask_name"]) or "")

            try:
                nozzle_temp = float(print_data.get("nozzle_temper", self._last_state["nozzle_temp"]) or 0.0)
            except (ValueError, TypeError):
                nozzle_temp = 0.0

            try:
                bed_temp = float(print_data.get("bed_temper", self._last_state["bed_temp"]) or 0.0)
            except (ValueError, TypeError):
                bed_temp = 0.0

            try:
                chamber_temp = float(print_data.get("chamber_temper", self._last_state.get("chamber_temp", 0.0)) or 0.0)
            except (ValueError, TypeError):
                chamber_temp = 0.0

            try:
                raw_target_nozzle = print_data.get("nozzle_target_temper")
                if raw_target_nozzle is not None:
                    target_nozzle_temp = float(raw_target_nozzle)
                else:
                    target_nozzle_temp = float(self._last_state.get("target_nozzle_temp", 0.0))
            except (ValueError, TypeError):
                target_nozzle_temp = float(self._last_state.get("target_nozzle_temp", 0.0))

            try:
                raw_target_bed = print_data.get("bed_target_temper")
                if raw_target_bed is not None:
                    target_bed_temp = float(raw_target_bed)
                else:
                    target_bed_temp = float(self._last_state.get("target_bed_temp", 0.0))
            except (ValueError, TypeError):
                target_bed_temp = float(self._last_state.get("target_bed_temp", 0.0))

            # Fan speeds: cooling_fan_speed, big_fan1_speed (aux), big_fan2_speed (chamber)
            raw_cooling = print_data.get("cooling_fan_speed")
            cooling_fan_speed = (
                _parse_fan_speed(raw_cooling, self._last_state.get("cooling_fan_speed", 0))
                if raw_cooling is not None
                else self._last_state.get("cooling_fan_speed", 0)
            )

            raw_aux = print_data.get("big_fan1_speed")
            aux_fan_speed = (
                _parse_fan_speed(raw_aux, self._last_state.get("aux_fan_speed", 0))
                if raw_aux is not None
                else self._last_state.get("aux_fan_speed", 0)
            )

            raw_chamber = print_data.get("big_fan2_speed")
            chamber_fan_speed = (
                _parse_fan_speed(raw_chamber, self._last_state.get("chamber_fan_speed", 0))
                if raw_chamber is not None
                else self._last_state.get("chamber_fan_speed", 0)
            )

            # Chamber fan hardware capability
            norm_model = (self.model or "").upper()
            if norm_model in {"A1", "A1_MINI", "A1 MINI"}:
                has_chamber_fan = False
            elif norm_model in {"X1", "X1C", "X1E", "P1S"} or "X1" in norm_model or "P1S" in norm_model:
                has_chamber_fan = True
            elif raw_chamber is not None and str(raw_chamber).strip() not in {"", "null", "none"}:
                has_chamber_fan = True
            else:
                has_chamber_fan = bool(self._last_state.get("has_chamber_fan", False))

            # Chamber light state
            lights = print_data.get("lights_report")
            chamber_light = self._last_state.get("chamber_light", "off")
            if isinstance(lights, list):
                for light in lights:
                    if light.get("node") == "chamber_light":
                        chamber_light = light.get("mode", "off")

            # Check for Access Control System (ACS) denial on firmware 01.05.00.00+
            result_code = str(print_data.get("result", "")).upper()
            reason_code = str(print_data.get("reason", "")).upper()
            if result_code == "FAILED" and any(
                term in reason_code for term in ("ACS", "ACCESS_CONTROL", "DENIED", "134217728", "AUTH")
            ):
                self._last_error = f"ACS_DENIED: {reason_code or 'Access Control System blocked command'}"
                logger.warning("Bambu printer ACS restriction on %s: %s", self.ip, self._last_error)
            elif result_code == "SUCCESS":
                self._last_error = None

            # State transition alert trigger
            if current_state != self._previous_gcode_state:
                if current_state in {"FINISH", "FAILED", "PAUSE"}:
                    level = "warning" if current_state == "FAILED" else "info"
                    NotificationService.notify(
                        title=f"Bambu Lab {self.model} ({self.serial_number[-6:]})",
                        message=f"Tác vụ in '{subtask_name}' đã chuyển sang trạng thái: {current_state}",
                        level=level,
                        metadata={
                            "serial_number": self.serial_number,
                            "model": self.model,
                            "gcode_state": current_state,
                            "subtask_name": subtask_name,
                            "progress": progress,
                        },
                    )
                self._previous_gcode_state = current_state

            self._last_state.update({
                "status": current_state,
                "progress": progress,
                "remaining_time": remaining_time,
                "subtask_name": subtask_name,
                "nozzle_temp": nozzle_temp,
                "target_nozzle_temp": target_nozzle_temp,
                "bed_temp": bed_temp,
                "target_bed_temp": target_bed_temp,
                "chamber_temp": chamber_temp,
                "chamber_light": chamber_light,
                "cooling_fan_speed": cooling_fan_speed,
                "aux_fan_speed": aux_fan_speed,
                "chamber_fan_speed": chamber_fan_speed,
                "has_chamber_fan": has_chamber_fan,
                "model": self.model,
                "last_updated": time.time(),
            })

            self._telemetry_event.set()
            return dict(self._last_state)

    def publish_request(self, payload: dict[str, Any]) -> bool:
        """Publish a command JSON payload to device/{serial}/request."""
        topic = f"device/{self.serial_number}/request"
        body = json.dumps(payload)

        if mqtt is None:
            logger.info("Publishing Bambu command (fallback mode) to %s: %s", topic, body)
            return True

        with self._lock:
            client = self._client
            connected = self._connected

        if client is None or not connected:
            logger.warning("Cannot publish Bambu command to %s: MQTT client is offline", topic)
            return False

        logger.info("Publishing Bambu command to %s: %s", topic, body)
        try:
            info = client.publish(topic, body, qos=0)
            return getattr(info, "rc", 0) == 0
        except Exception as exc:
            logger.warning("Failed to publish Bambu command to %s: %s", topic, exc)
            return False

    def request_full_status(self) -> bool:
        """Request full state dump (pushall) from the printer."""
        return self.publish_request({
            "pushing": {
                "sequence_id": "0",
                "command": "pushall",
            }
        })

    def pause_print(self) -> bool:
        """Pause active printing."""
        return self.publish_request({
            "print": {
                "sequence_id": "0",
                "command": "pause",
            }
        })

    def resume_print(self) -> bool:
        """Resume paused printing."""
        return self.publish_request({
            "print": {
                "sequence_id": "0",
                "command": "resume",
            }
        })

    def stop_print(self) -> bool:
        """Stop / cancel printing."""
        return self.publish_request({
            "print": {
                "sequence_id": "0",
                "command": "stop",
            }
        })

    def set_chamber_light(self, on: bool) -> bool:
        """Toggle chamber lighting."""
        mode_str = "on" if on else "off"
        return self.publish_request({
            "system": {
                "sequence_id": "0",
                "command": "ledctrl",
                "led_node": "chamber_light",
                "led_mode": mode_str,
            }
        })

    def set_nozzle_temperature(self, temp: int | float) -> bool:
        """Set target nozzle temperature (°C) clamped between 0 and 300°C."""
        try:
            val = float(temp)
        except (ValueError, TypeError):
            val = 0.0
        clamped = max(0, min(300, int(round(val))))
        with self._lock:
            self._last_state["target_nozzle_temp"] = clamped
        return self.publish_request({
            "print": {
                "sequence_id": "0",
                "command": "gcode_line",
                "param": f"M104 S{clamped}\n",
            }
        })

    def set_bed_temperature(self, temp: int | float) -> bool:
        """Set target heated bed temperature (°C) clamped between 0 and 120°C."""
        try:
            val = float(temp)
        except (ValueError, TypeError):
            val = 0.0
        clamped = max(0, min(120, int(round(val))))
        with self._lock:
            self._last_state["target_bed_temp"] = clamped
        return self.publish_request({
            "print": {
                "sequence_id": "0",
                "command": "gcode_line",
                "param": f"M140 S{clamped}\n",
            }
        })

    def set_fan_speed(self, fan_type: str, speed_pct: int | float) -> bool:
        """Set fan speed percentage (0-100%) for cooling/part (P1), aux (P2), or chamber (P3) fan."""
        ft = str(fan_type or "").strip().lower()
        if ft in ("aux", "aux_fan", "big_fan1", "p2", "2"):
            p_num = 2
            state_key = "aux_fan_speed"
        elif ft in ("chamber", "chamber_fan", "big_fan2", "p3", "3"):
            p_num = 3
            state_key = "chamber_fan_speed"
        else:
            p_num = 1
            state_key = "cooling_fan_speed"

        try:
            val = float(speed_pct)
        except (ValueError, TypeError):
            val = 0.0
        pct = max(0.0, min(100.0, val))
        pwm = int(pct * 255 / 100)
        with self._lock:
            self._last_state[state_key] = int(round(pct))

        return self.publish_request({
            "print": {
                "sequence_id": "0",
                "command": "gcode_line",
                "param": f"M106 P{p_num} S{pwm}\n",
            }
        })

    def send_gcode(self, gcode_line: str) -> bool:
        """Send a raw GCODE line to the printer."""
        line = str(gcode_line or "").strip()
        if not line:
            return False
        return self.publish_request({
            "print": {
                "sequence_id": "0",
                "command": "gcode_line",
                "param": f"{line}\n",
            }
        })
