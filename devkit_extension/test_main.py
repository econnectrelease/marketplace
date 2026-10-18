"""Focused behavioural checks for DevKit device-session isolation on a single shared port."""
import importlib.util
import pathlib
import urllib.request
import unittest
from unittest.mock import patch


MODULE_PATH = pathlib.Path(__file__).with_name("main.py")
SPEC = importlib.util.spec_from_file_location("devkit_extension_main", MODULE_PATH)
assert SPEC and SPEC.loader
devkit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(devkit)


def context(device_id, schema_id, port=None, **config):
    cfg = dict(config)
    if port is not None:
        cfg["simulator_port"] = port
    return {
        "device_id": device_id,
        "device_schema_id": schema_id,
        "config": cfg,
        "schema_snapshot": {"device_type": schema_id.removeprefix("devkit_")},
    }


class DevKitSessionTests(unittest.TestCase):
    def setUp(self):
        for device_id in list(devkit.SESSIONS):
            devkit._release(device_id)
        devkit.SESSIONS.clear()
        # Binding to loopback is test-only. Production resolution rejects it.
        self.host = patch.object(devkit, "_resolve_hub_host", return_value="127.0.0.1")
        self.host.start()

    def tearDown(self):
        self.host.stop()
        for device_id in list(devkit.SESSIONS):
            devkit._release(device_id)

    def test_default_port_is_18080_when_omitted(self):
        device = context("test-no-port", "devkit_light")
        self.assertEqual(devkit._port(device), 18080)

    def test_hub_host_accepts_only_non_loopback_rfc1918_ipv4(self):
        self.host.stop()
        self.assertEqual(devkit._resolve_hub_host(context("resolve-ok", "devkit_switch", 18080, hub_host="192.168.8.10")), "192.168.8.10")
        self.assertIsNone(devkit._private_ipv4("127.0.0.1"))
        self.assertIsNone(devkit._private_ipv4("169.254.1.1"))
        self.assertIsNone(devkit._private_ipv4("198.18.0.1"))
        self.assertIsNone(devkit._private_ipv4("8.8.8.8"))
        self.assertIsNone(devkit._private_ipv4("not-an-ip"))
        self.host.start()

    def test_multiple_lan_candidates_require_explicit_hub_host(self):
        self.host.stop()
        device = context("ambiguous-hub", "devkit_switch", 18090)
        with patch.object(devkit, "_lan_host_candidates", return_value={"192.168.1.20", "10.10.0.5"}):
            self.assertIsNone(devkit._resolve_hub_host(device))
            self.assertIn("Multiple Hub LAN", devkit._hub_host_error(device))
            session = devkit._session(device)
        self.assertFalse(session["connected"])
        self.assertIn("Multiple Hub LAN", session["hub_host_error"])
        self.host.start()

    def test_devices_keep_separate_type_and_state(self):
        light = context("test-light", "devkit_light", 18081)
        fan = context("test-fan", "devkit_fan", 18082)
        devkit.on_execute_command(light, {"command": "set_brightness", "args": {"brightness": 12}})
        devkit.on_execute_command(fan, {"command": "set_fan_speed", "args": {"fan_speed": 66}})

        self.assertEqual(devkit.on_probe_state(light)["state"]["brightness"], 12)
        self.assertNotIn("fan_speed", devkit.on_probe_state(light)["state"])
        self.assertEqual(devkit.on_probe_state(fan)["state"]["fan_speed"], 66)
        self.assertEqual(devkit.on_probe_state(fan)["state"]["speed"], 66)
        self.assertEqual(devkit._payload("test-fan")["device_type"], "fan")

        # Test standard E-Connect Action payloads (fan speed, toggle, brightness)
        res_fan = devkit.on_execute_command(fan, {"kind": "action", "pin": 0, "value": 1, "speed": 100, "restore_speed": 100})
        self.assertEqual(res_fan["status"], "success")
        self.assertEqual(res_fan["state"]["fan_speed"], 100)
        self.assertEqual(res_fan["state"]["speed"], 100)
        self.assertEqual(res_fan["state"]["power"], "on")

        # Turning off fan
        res_off = devkit.on_execute_command(fan, {"kind": "action", "pin": 0, "value": 0, "speed": 0, "restore_speed": 100})
        self.assertEqual(res_off["state"]["fan_speed"], 0)
        self.assertEqual(res_off["state"]["power"], "off")

        # Light action brightness
        res_light = devkit.on_execute_command(light, {"kind": "action", "pin": 0, "brightness": 180, "value": 1})
        self.assertEqual(res_light["state"]["brightness"], 180)
        self.assertEqual(res_light["state"]["power"], "on")

    def test_probe_state_includes_simulator_url_as_ip_address(self):
        device = context("test-ip-dev", "devkit_fan", 18080)
        res = devkit.on_probe_state(device)
        self.assertIn("ip_address", res["state"])
        self.assertEqual(res["state"]["ip_address"], "http://127.0.0.1:18080/test-ip-dev/test")

    def test_events_redact_sensitive_command_data(self):
        device = context("test-switch", "devkit_switch", 18083)
        devkit.on_execute_command(device, {"command": "turn_on", "args": {"token": "not-public"}})
        events = devkit._payload("test-switch")["events"]
        self.assertEqual(events[-1]["payload"]["command"]["args"]["token"], "***")

    def test_unsafe_context_id_is_replaced_with_safe_slug(self):
        self.assertTrue(devkit.SAFE_ID.fullmatch(devkit._id({"device_id": "not/a/path"})))

    def test_devices_share_single_port_multiplexed_by_device_id(self):
        first = context("device-one", "devkit_switch", 18084)
        second = context("device-two", "devkit_sensor", 18084)
        self.assertEqual(devkit.on_execute_command(first, {"command": "turn_on"})["status"], "success")
        self.assertEqual(devkit.on_execute_command(second, {"command": "set_value", "args": {"value": 42}})["status"], "success")

        probe_first = devkit.on_probe_state(first)
        probe_second = devkit.on_probe_state(second)
        self.assertTrue(probe_first["connected"])
        self.assertTrue(probe_second["connected"])
        self.assertEqual(probe_first["state"]["power"], "on")
        self.assertEqual(probe_second["state"]["value"], 42)

        # Both devices are reachable on the SAME port at their distinct URLs
        page_first = urllib.request.urlopen("http://127.0.0.1:18084/device-one/test", timeout=2).read().decode()
        page_second = urllib.request.urlopen("http://127.0.0.1:18084/device-two/test", timeout=2).read().decode()
        self.assertIn("DevKit Protocol Console", page_first)
        self.assertIn("DevKit Protocol Console", page_second)

        # Server index also lists both devices
        index_page = urllib.request.urlopen("http://127.0.0.1:18084/", timeout=2).read().decode()
        self.assertIn("device-one", index_page)
        self.assertIn("device-two", index_page)

    def test_canonical_port_route_and_ui_do_not_interpolate_state_as_html(self):
        device = context("test-canonical", "devkit_light", 18085)
        devkit.on_execute_command(device, {"command": "set_rgb", "args": {"rgb": "\"><img src=x onerror=alert(1)>"}})
        page = urllib.request.urlopen("http://127.0.0.1:18085/test-canonical/test", timeout=2).read().decode()
        self.assertIn("DevKit Protocol Console", page)
        self.assertNotIn("innerHTML", page)
        self.assertNotIn("onerror=alert", page)

    def test_payload_exposes_lan_canonical_url_without_config(self):
        self.host.stop()
        with patch.object(devkit, "_resolve_hub_host", return_value="192.168.50.20"):
            device = context("test-lan-url", "devkit_switch", 18089)
            session = devkit._session(device)
            self.assertEqual(session["hub_host"], "192.168.50.20")
            payload = devkit._payload("test-lan-url")
        self.assertEqual(payload["simulator_url"], "http://192.168.50.20:18089/test-lan-url/test")
        self.assertNotIn("config", payload)
        self.host.start()

    def test_lifecycle_cleanup_keeps_server_until_last_device_is_deleted(self):
        first = context("test-cleanup-first", "devkit_switch", 18086)
        second = context("test-cleanup-second", "devkit_sensor", 18086)
        self.assertEqual(devkit.on_execute_command(first, {"command": "turn_on"})["status"], "success")
        self.assertEqual(devkit.on_execute_command(second, {"command": "set_value", "args": {"value": 100}})["status"], "success")
        self.assertIn(18086, devkit.SERVERS)

        # Delete first device: server remains alive for second device
        devkit.on_device_deleted(first)
        self.assertIn(18086, devkit.SERVERS)
        self.assertEqual(devkit.on_execute_command(second, {"command": "set_value", "args": {"value": 101}})["status"], "success")
        self.assertEqual(devkit.on_probe_state(second)["state"]["value"], 101)

        # Delete second device: server is cleanly released
        devkit.on_device_deleted(second)
        self.assertNotIn(18086, devkit.SERVERS)


if __name__ == "__main__":
    unittest.main()
