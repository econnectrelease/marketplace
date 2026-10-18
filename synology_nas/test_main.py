# Copyright (c) 2026 E-Connect Project. All rights reserved.

from __future__ import annotations

import json
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs

import main


class _Response:
    def __init__(self, payload: dict[str, object]) -> None:
        self.payload = json.dumps(payload).encode("utf-8")

    def read(self, _: int) -> bytes:
        return self.payload

    def __enter__(self) -> "_Response":
        return self

    def __exit__(self, *_: object) -> None:
        return None


class SynologyNasExtensionTests(unittest.TestCase):
    def setUp(self) -> None:
        main._clear_all_sessions()
        self.device = {
            "config": {
                "base_url": "https://nas.example.test:5001",
                "username": "monitor",
                "password": "not-a-real-password",
                "verify_tls": True,
            }
        }

    def tearDown(self) -> None:
        main._clear_all_sessions()

    def test_probe_returns_storage_temperature_and_online_status(self) -> None:
        def fake_urlopen(request: object, **_: object) -> _Response:
            query = parse_qs(request.data.decode("utf-8"))
            api = query["api"][0]
            method = query["method"][0]
            if api == main.API_INFO:
                return _Response({"success": True, "data": {
                    main.AUTH_API: {"path": "/webapi/custom-auth.cgi", "maxVersion": 6},
                    main.STORAGE_API: {"path": "/webapi/entry.cgi", "maxVersion": 3},
                    main.SYSTEM_API: {"path": "/webapi/entry.cgi", "maxVersion": 2},
                }})
            if api == main.AUTH_API and method == "login":
                self.assertTrue(request.full_url.endswith("/webapi/custom-auth.cgi"))
                self.assertEqual(query["version"], ["6"])
                self.assertNotIn("otp_code", query)
                self.assertEqual(query["enable_device_token"], ["yes"])
                return _Response({"success": True, "data": {"sid": "session-id", "device_id": "trusted-token-123"}})
            if api == main.STORAGE_API:
                self.assertEqual(query["version"], ["3"])
                self.assertEqual(query["_sid"], ["session-id"])
                return _Response({"success": True, "data": {"volumes": [
                    {"size": {"total": "1000", "used": "250"}},
                    {"size": {"total": "500", "used": "100"}},
                ]}})
            if api == main.SYSTEM_API:
                self.assertEqual(query["version"], ["2"])
                self.assertEqual(query["_sid"], ["session-id"])
                return _Response({"success": True, "data": {"sys_temp": 43}})
            self.fail(f"Unexpected DSM request: {api} {method}")

        with patch.object(main, "urlopen", side_effect=fake_urlopen):
            result = main.probe_state(self.device)

        self.assertEqual(result["conn_status"], "online")
        self.assertEqual(result["state"]["value"], "healthy")
        self.assertEqual(result["state"]["value2"], 1500)
        self.assertEqual(result["state"]["value1"], 350)
        self.assertEqual(result["state"]["value3"], 43.0)

    def test_probe_extracts_data_protection_and_disks(self) -> None:
        def fake_urlopen(request: object, **_: object) -> _Response:
            query = parse_qs(request.data.decode("utf-8"))
            api = query["api"][0]
            if api == main.API_INFO:
                return _Response({"success": True, "data": {}})
            if api == main.AUTH_API:
                return _Response({"success": True, "data": {"sid": "sid-protection"}})
            if api == main.STORAGE_API:
                return _Response({"success": True, "data": {
                    "storagePools": [{
                        "id": "pool_1",
                        "device_type": "shr_with_1_disk_protect",
                        "status": "normal",
                        "disk_failure_number": 0,
                        "scrubbingStatus": "schedule_done",
                        "last_done_time": 1700000000,
                    }],
                    "volumes": [{
                        "id": "volume_1",
                        "vol_desc": "Volume 1",
                        "fs_type": "btrfs",
                        "status": "normal",
                        "size": {"total": "5000", "used": "2000"},
                    }],
                    "disks": [
                        {
                            "id": "sata1",
                            "name": "Drive 1",
                            "vendor": "Seagate",
                            "status": "normal",
                            "smart_status": "normal",
                            "unc": 0,
                            "temp": 39,
                        },
                        {
                            "id": "sata2",
                            "name": "Drive 2",
                            "vendor": "Seagate",
                            "status": "normal",
                            "smart_status": "normal",
                            "unc": 0,
                            "temp": 41,
                        },
                    ],
                }})
            if api == main.SYSTEM_API:
                return _Response({"success": True, "data": {
                    "model": "DS920+",
                    "firmware_ver": "DSM 7.4.1",
                    "sys_temp": 45,
                }})
            self.fail(f"Unexpected request: {api}")

        with patch.object(main, "urlopen", side_effect=fake_urlopen):
            res = main.probe_state(self.device)

        state = res["state"]
        self.assertIn("data_protection", state)
        self.assertEqual(state["data_protection"]["overall"], "safe")
        self.assertEqual(state["data_protection"]["raid_name"], "Synology Hybrid RAID (SHR)")
        self.assertEqual(state["data_protection"]["total_drives"], 2)
        self.assertEqual(state["data_protection"]["healthy_drives"], 2)
        self.assertEqual(state["data_protection"]["total_bad_sectors"], 0)
        self.assertEqual(len(state["disks"]), 2)
        self.assertEqual(state["disks"][0]["name"], "Drive 1")
        self.assertEqual(state["system_info"]["model"], "DS920+")

    def test_subsequent_probe_reuses_cached_session_without_login_roundtrip(self) -> None:
        login_count = 0

        def fake_urlopen(request: object, **_: object) -> _Response:
            nonlocal login_count
            query = parse_qs(request.data.decode("utf-8"))
            api = query["api"][0]
            method = query["method"][0]
            if api == main.API_INFO:
                return _Response({"success": True, "data": {}})
            if api == main.AUTH_API and method == "login":
                login_count += 1
                return _Response({"success": True, "data": {"sid": "reused-sid", "device_id": "tok-456"}})
            if api == main.STORAGE_API:
                self.assertEqual(query["_sid"], ["reused-sid"])
                return _Response({"success": True, "data": {"volumes": [{"size": {"total": "100", "used": "50"}}]}})
            if api == main.SYSTEM_API:
                return _Response({"success": True, "data": {"sys_temp": 40}})
            self.fail(f"Unexpected DSM request: {api} {method}")

        with patch.object(main, "urlopen", side_effect=fake_urlopen):
            # First probe: performs login and saves session
            r1 = main.probe_state(self.device)
            self.assertEqual(r1["conn_status"], "online")
            self.assertEqual(login_count, 1)

            # Second probe: should directly reuse cached sid without calling login!
            r2 = main.probe_state(self.device)
            self.assertEqual(r2["conn_status"], "online")
            self.assertEqual(login_count, 1, "Second probe must reuse session without calling login")

    def test_expired_session_re_authenticates_using_saved_device_token(self) -> None:
        login_calls = []
        probe_number = 1

        def fake_urlopen(request: object, **_: object) -> _Response:
            query = parse_qs(request.data.decode("utf-8"))
            api = query["api"][0]
            method = query["method"][0]
            if api == main.API_INFO:
                return _Response({"success": True, "data": {}})
            if api == main.AUTH_API and method == "login":
                login_calls.append(query)
                if len(login_calls) == 1:
                    # First login: returns sid-1 and device-id-123
                    return _Response({"success": True, "data": {"sid": "sid-1", "device_id": "device-token-123"}})
                else:
                    # Second login after expiry: returns sid-2
                    return _Response({"success": True, "data": {"sid": "sid-2", "device_id": "device-token-123"}})
            if api == main.STORAGE_API:
                if probe_number == 2 and query["_sid"] == ["sid-1"]:
                    # Simulate session expiration on 2nd probe
                    return _Response({"success": False, "error": {"code": 119}})
                return _Response({"success": True, "data": {"volumes": [{"size": {"total": "200", "used": "100"}}]}})
            if api == main.SYSTEM_API:
                return _Response({"success": True, "data": {"sys_temp": 42}})
            self.fail(f"Unexpected DSM request: {api} {method}")

        with patch.object(main, "urlopen", side_effect=fake_urlopen):
            # First probe: performs initial login
            main.probe_state(self.device)
            self.assertEqual(len(login_calls), 1)
            self.assertNotIn("device_id", login_calls[0])

            # Second probe: encounters code 119, re-authenticates using saved device_id!
            probe_number = 2
            r = main.probe_state(self.device)
            self.assertEqual(r["conn_status"], "online")
            self.assertEqual(len(login_calls), 2)
            self.assertEqual(login_calls[1]["device_id"], ["device-token-123"], "Re-login must pass saved device_id")

    def test_probe_keeps_nas_online_when_temperature_is_unsupported(self) -> None:
        def fake_urlopen(request: object, **_: object) -> _Response:
            query = parse_qs(request.data.decode("utf-8"))
            api = query["api"][0]
            if api == main.API_INFO:
                return _Response({"success": True, "data": {}})
            if api == main.AUTH_API:
                return _Response({"success": True, "data": {"sid": "session-id"}})
            if api == main.STORAGE_API:
                return _Response({"success": True, "data": {"volumes": [{"size": {"total": "10", "used": "5"}}]}})
            if api == main.SYSTEM_API:
                return _Response({"success": True, "data": {}})
            self.fail(f"Unexpected DSM request: {api}")

        with patch.object(main, "urlopen", side_effect=fake_urlopen):
            result = main.probe_state(self.device)

        self.assertEqual(result["conn_status"], "online")
        self.assertIsNone(result["state"]["value3"])
        self.assertIn("temperature", result["state"]["metric_warnings"][0].lower())

    def test_authentication_failure_marks_the_nas_offline(self) -> None:
        def fake_urlopen(request: object, **_: object) -> _Response:
            query = parse_qs(request.data.decode("utf-8"))
            api = query["api"][0]
            if api == main.API_INFO:
                return _Response({"success": True, "data": {}})
            if api == main.AUTH_API:
                return _Response({"success": False, "error": {"code": 400}})
            self.fail(f"Unexpected DSM request: {api}")

        with patch.object(main, "urlopen", side_effect=fake_urlopen):
            with self.assertRaises(main.ExtensionRuntimeError) as raised:
                main.probe_state(self.device)

        self.assertTrue(raised.exception.mark_offline)
        self.assertTrue(raised.exception.connection_failed)

    def test_probe_sends_the_current_totp_code_for_two_factor_accounts(self) -> None:
        self.device["config"]["otp_code"] = "123456"

        def fake_urlopen(request: object, **_: object) -> _Response:
            query = parse_qs(request.data.decode("utf-8"))
            api = query["api"][0]
            method = query["method"][0]
            if api == main.API_INFO:
                return _Response({"success": True, "data": {}})
            if api == main.AUTH_API and method == "login":
                self.assertEqual(query["otp_code"], ["123456"])
                self.assertEqual(query["enable_device_token"], ["yes"])
                return _Response({"success": True, "data": {"sid": "session-id", "device_id": "tok-789"}})
            if api == main.STORAGE_API:
                return _Response({"success": True, "data": {"volumes": [{"size": {"total": "20", "used": "10"}}]}})
            if api == main.SYSTEM_API:
                return _Response({"success": True, "data": {}})
            self.fail(f"Unexpected DSM request: {api} {method}")

        with patch.object(main, "urlopen", side_effect=fake_urlopen):
            result = main.probe_state(self.device)

        self.assertEqual(result["conn_status"], "online")

    def test_failed_two_factor_authentication_marks_the_nas_offline_without_leaking_otp(self) -> None:
        self.device["config"]["otp_code"] = "123456"

        def fake_urlopen(request: object, **_: object) -> _Response:
            query = parse_qs(request.data.decode("utf-8"))
            if query["api"] == [main.API_INFO]:
                return _Response({"success": True, "data": {}})
            self.assertEqual(query["api"], [main.AUTH_API])
            self.assertEqual(query["method"], [main.AUTH_API]) if False else None
            return _Response({"success": False, "error": {"code": 404}})

        with patch.object(main, "urlopen", side_effect=fake_urlopen):
            with self.assertRaises(main.ExtensionRuntimeError) as raised:
                main.probe_state(self.device)

        self.assertTrue(raised.exception.mark_offline)
        self.assertNotIn("123456", str(raised.exception))

    def test_invalid_totp_is_rejected_before_network_access(self) -> None:
        self.device["config"]["otp_code"] = "not-a-code"
        with self.assertRaises(main.ExtensionValidationError):
            main.probe_state(self.device)

    def test_invalid_base_url_is_rejected_before_network_access(self) -> None:
        self.device["config"]["base_url"] = "nas.local"
        with self.assertRaises(main.ExtensionValidationError):
            main.probe_state(self.device)


if __name__ == "__main__":
    unittest.main()
