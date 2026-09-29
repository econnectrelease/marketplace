# Copyright (c) 2026 E-Connect Team. All rights reserved.

from __future__ import annotations

import os
import json
import logging
import threading
import time
from typing import Any

import paho.mqtt.client as mqtt

# Setup logging
logger = logging.getLogger("econnect.zigbee_manager")

# Exceptions compatibility helper
try:
    from app.services.extension_runtime_api import (
        ExtensionRuntimeError,
        ExtensionUnsupportedError,
        ExtensionValidationError,
    )
except ImportError:
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

    class ExtensionValidationError(ValueError):
        pass

    class ExtensionUnsupportedError(RuntimeError):
        pass


# Global states and caches
BRIDGE_STATE = "offline"
ZIGBEE_DEVICES_LIST: list[dict[str, Any]] = []
ZIGBEE_DEVICE_STATES: dict[str, dict[str, Any]] = {}
ZIGBEE_STATE_LOCK = threading.Lock()

mqtt_client: mqtt.Client | None = None
mqtt_connected = False
mqtt_init_lock = threading.Lock()


def on_connect(client: mqtt.Client, userdata: Any, flags: Any, reason_code: Any, properties: Any = None) -> None:
    global mqtt_connected
    mqtt_connected = True
    logger.info("Zigbee Extension connected to MQTT broker successfully.")
    client.subscribe("zigbee2mqtt/#")


def on_disconnect(client: mqtt.Client, userdata: Any, flags: Any, reason_code: Any, properties: Any = None) -> None:
    global mqtt_connected
    mqtt_connected = False
    logger.warning("Zigbee Extension disconnected from MQTT broker.")


def on_message(client: mqtt.Client, userdata: Any, msg: mqtt.MQTTMessage) -> None:
    global BRIDGE_STATE, ZIGBEE_DEVICES_LIST
    topic = msg.topic
    payload_str = msg.payload.decode("utf-8", errors="ignore").strip()

    if not payload_str:
        return

    try:
        payload = json.loads(payload_str)
    except json.JSONDecodeError:
        payload = payload_str

    with ZIGBEE_STATE_LOCK:
        if topic == "zigbee2mqtt/bridge/state":
            BRIDGE_STATE = payload_str  # "online" or "offline"
        elif topic == "zigbee2mqtt/bridge/devices":
            if isinstance(payload, list):
                ZIGBEE_DEVICES_LIST = payload
        else:
            # Topic format: zigbee2mqtt/<friendly_name>
            parts = topic.split('/')
            if len(parts) == 2 and parts[0] == "zigbee2mqtt" and parts[1] != "bridge":
                friendly_name = parts[1]
                if isinstance(payload, dict):
                    ZIGBEE_DEVICE_STATES[friendly_name] = payload


def init_mqtt_client() -> None:
    global mqtt_client, mqtt_init_lock
    with mqtt_init_lock:
        if mqtt_client is not None:
            return

        broker = os.getenv("MQTT_BROKER", "localhost")
        try:
            port = int(os.getenv("MQTT_PORT", "1883"))
        except ValueError:
            port = 1883

        logger.info(f"Initializing Zigbee Extension MQTT Client on {broker}:{port}")

        try:
            # Try initializing with Callback API Version 2 (Paho-mqtt 2.0+)
            mqtt_client = mqtt.Client(
                callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
                client_id="econnect_zigbee_bridge_ext",
                clean_session=True,
            )
        except AttributeError:
            # Fallback to Callback API Version 1 (Older paho-mqtt versions)
            mqtt_client = mqtt.Client(
                client_id="econnect_zigbee_bridge_ext",
                clean_session=True,
            )

        mqtt_client.on_connect = on_connect
        mqtt_client.on_disconnect = on_disconnect
        mqtt_client.on_message = on_message

        try:
            mqtt_client.connect(broker, port, keepalive=60)
            mqtt_client.loop_start()
        except Exception as exc:
            logger.exception(f"Zigbee Extension failed to connect to broker: {exc}")
            mqtt_client = None


# Extension hooks

def validate_command(device: dict[str, Any], command: dict[str, Any]) -> None:
    schema_id = device.get("device_schema_id", "")
    kind = str(command.get("kind") or "action").strip().lower()

    if schema_id == "zigbee_coordinator":
        raise ExtensionValidationError("Zigbee Coordinator does not support direct command control.")

    if kind != "action":
        raise ExtensionValidationError("Only action commands are supported.")


def execute_command(device: dict[str, Any], command: dict[str, Any]) -> dict[str, Any]:
    init_mqtt_client()

    schema_id = device.get("device_schema_id", "")
    config = device.get("config") if isinstance(device.get("config"), dict) else {}
    friendly_name = config.get("friendly_name", "")

    if not friendly_name:
        raise ExtensionValidationError("Zigbee device friendly_name is missing in configuration.")

    set_topic = f"zigbee2mqtt/{friendly_name}/set"
    payload: dict[str, Any] = {}

    if schema_id == "zigbee_switch":
        if "value" in command:
            payload["state"] = "ON" if bool(command["value"]) else "OFF"
        elif "power" in command:
            payload["state"] = "ON" if command["power"] == "on" else "OFF"

    elif schema_id == "zigbee_light":
        if "value" in command:
            payload["state"] = "ON" if bool(command["value"]) else "OFF"
        if "power" in command:
            payload["state"] = "ON" if command["power"] == "on" else "OFF"
        if "brightness" in command:
            # E-Connect uses 0-255 brightness
            payload["brightness"] = int(command["brightness"])
        if "color_temperature" in command:
            # Kelvin to Mireds conversion (Mireds = 1,000,000 / Kelvin)
            try:
                kelvin = int(command["color_temperature"])
                payload["color_temp"] = int(1000000 / kelvin)
            except (ValueError, ZeroDivisionError):
                pass
        if "rgb" in command:
            rgb = command["rgb"]
            if isinstance(rgb, dict):
                payload["color"] = {
                    "r": int(rgb.get("r", 0)),
                    "g": int(rgb.get("g", 0)),
                    "b": int(rgb.get("b", 0)),
                }

    if payload and mqtt_client is not None and mqtt_connected:
        try:
            mqtt_client.publish(set_topic, json.dumps(payload), qos=1)
            # Eager cache update to keep UI responsive
            with ZIGBEE_STATE_LOCK:
                cached = ZIGBEE_DEVICE_STATES.get(friendly_name, {})
                cached.update(payload)
                if "state" in payload:
                    cached["value"] = 1 if payload["state"] == "ON" else 0
                    cached["power"] = "on" if payload["state"] == "ON" else "off"
                ZIGBEE_DEVICE_STATES[friendly_name] = cached
        except Exception as exc:
            raise ExtensionRuntimeError(f"Failed to publish control command to MQTT: {exc}")

    return probe_state(device)


def probe_state(device: dict[str, Any]) -> dict[str, Any]:
    init_mqtt_client()

    schema_id = device.get("device_schema_id", "")
    config = device.get("config") if isinstance(device.get("config"), dict) else {}

    if schema_id == "zigbee_coordinator":
        usb_port = config.get("usb_port", "")
        if not usb_port:
            raise ExtensionRuntimeError("Chưa cấu hình địa chỉ cổng USB", mark_offline=True)

        if not os.path.exists(usb_port):
            raise ExtensionRuntimeError(f"Cổng USB '{usb_port}' không tồn tại trên máy chủ", mark_offline=True)

        if not os.access(usb_port, os.R_OK | os.W_OK):
            raise ExtensionRuntimeError(f"Không có quyền đọc/ghi vào cổng '{usb_port}'", mark_offline=True)

        with ZIGBEE_STATE_LOCK:
            current_bridge_state = BRIDGE_STATE

        if current_bridge_state == "offline":
            raise ExtensionRuntimeError("Dịch vụ Zigbee2MQTT đang Offline hoặc chưa kết nối broker", mark_offline=True)

        return {
            "conn_status": "online",
            "state": {
                "pin": 1,
                "value": 1,
                "mode": "INPUT",
                "message": f"Mạng Zigbee online. USB: {usb_port}",
            },
        }

    friendly_name = config.get("friendly_name", "")
    ieee_address = config.get("ieee_address", "")

    if not friendly_name:
        raise ExtensionValidationError("Zigbee device friendly_name is missing in configuration.")

    raw_state = None
    with ZIGBEE_STATE_LOCK:
        raw_state = ZIGBEE_DEVICE_STATES.get(friendly_name)
        if raw_state is None and ieee_address:
            # Fallback lookup in case the topic uses friendly_name but device was paired with ieee_address
            for dev in ZIGBEE_DEVICES_LIST:
                if dev.get("ieee_address") == ieee_address or dev.get("ieeeAddress") == ieee_address:
                    alt_name = dev.get("friendly_name") or dev.get("friendlyName")
                    if alt_name:
                        raw_state = ZIGBEE_DEVICE_STATES.get(alt_name)
                        break

    if raw_state is None:
        return {
            "conn_status": "offline",
            "state": {
                "pin": 0,
                "value": 0,
                "message": "Chưa nhận được trạng thái từ Zigbee2MQTT",
            },
        }

    power_str = str(raw_state.get("state", "OFF")).upper()
    power_on = (power_str == "ON")

    state_payload: dict[str, Any] = {
        "pin": 0,
        "value": 1 if power_on else 0,
        "power": "on" if power_on else "off",
    }

    # Extract sensor readings
    if "temperature" in raw_state:
        state_payload["value"] = float(raw_state["temperature"])
        state_payload["temperature"] = float(raw_state["temperature"])
    if "humidity" in raw_state:
        state_payload["humidity"] = float(raw_state["humidity"])
    if "illuminance" in raw_state:
        state_payload["illuminance"] = float(raw_state["illuminance"])
    if "occupancy" in raw_state:
        occupied = bool(raw_state["occupancy"])
        state_payload["value"] = 1 if occupied else 0
        state_payload["occupancy"] = occupied

    # Extract light settings
    if "brightness" in raw_state:
        state_payload["brightness"] = int(raw_state["brightness"])
    if "color_temp" in raw_state:
        try:
            mireds = int(raw_state["color_temp"])
            state_payload["color_temperature"] = int(1000000 / mireds)
        except (ValueError, ZeroDivisionError):
            pass
    if "color" in raw_state:
        color = raw_state["color"]
        if isinstance(color, dict):
            if "r" in color and "g" in color and "b" in color:
                state_payload["rgb"] = {
                    "r": int(color["r"]),
                    "g": int(color["g"]),
                    "b": int(color["b"]),
                }

    return {
        "conn_status": "online",
        "state": state_payload,
    }


def discover_devices() -> list[dict[str, Any]]:
    init_mqtt_client()

    # Wait up to 1 second for device data to populate from MQTT cache
    for _ in range(10):
        with ZIGBEE_STATE_LOCK:
            if ZIGBEE_DEVICES_LIST:
                break
        time.sleep(0.1)

    candidates: list[dict[str, Any]] = []
    with ZIGBEE_STATE_LOCK:
        devices = list(ZIGBEE_DEVICES_LIST)

    for dev in devices:
        if dev.get("type") == "Coordinator":
            continue

        ieee_address = dev.get("ieee_address") or dev.get("ieeeAddress")
        friendly_name = dev.get("friendly_name") or dev.get("friendlyName")
        definition = dev.get("definition") or {}
        model = definition.get("model", "")
        vendor = definition.get("vendor", "")
        exposes = definition.get("exposes", [])

        if not ieee_address or not friendly_name:
            continue

        features = []
        for exp in exposes:
            if isinstance(exp, dict):
                features.append(exp.get("name") or exp.get("property"))
                sub_features = exp.get("features", [])
                for sub in sub_features:
                    if isinstance(sub, dict):
                        features.append(sub.get("name") or sub.get("property"))

        schema_id = "zigbee_sensor"  # Default fallback
        if "color" in features or "color_temp" in features or ("brightness" in features and "state" in features):
            schema_id = "zigbee_light"
        elif "state" in features:
            schema_id = "zigbee_switch"

        candidates.append({
            "name": f"{vendor} {model} ({friendly_name})".strip(),
            "device_schema_id": schema_id,
            "config": {
                "ieee_address": ieee_address,
                "friendly_name": friendly_name,
            },
        })

    return candidates
