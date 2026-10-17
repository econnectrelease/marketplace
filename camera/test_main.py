# Copyright (c) 2026 E-Connect Project. All rights reserved.

from __future__ import annotations

import sys
from pathlib import Path
import unittest
from unittest.mock import MagicMock, patch

# Ensure camera module is discoverable
sys.path.insert(0, str(Path(__file__).parent))
import main


class TestCameraExtension(unittest.TestCase):
    def test_build_authenticated_stream_url(self):
        # RTSP
        url = "rtsp://192.168.1.50:554/live"
        res = main._build_authenticated_stream_url(url, "admin", "123456")
        self.assertEqual(res, "rtsp://admin:123456@192.168.1.50:554/live")

        # HTTP MJPEG
        url_http = "http://192.168.1.200:81/stream"
        res_http = main._build_authenticated_stream_url(url_http, "admin", "secret")
        self.assertEqual(res_http, "http://admin:secret@192.168.1.200:81/stream")

        # Don't double inject
        already = "rtsp://user:pass@192.168.1.50:554/live"
        self.assertEqual(main._build_authenticated_stream_url(already, "admin", "123456"), already)

    def test_mask_stream_url(self):
        url = "rtsp://admin:secret123@192.168.1.50:554/stream"
        masked = main._mask_stream_url(url)
        self.assertEqual(masked, "rtsp://admin:***@192.168.1.50:554/stream")

        url_http = "http://admin:pass@192.168.1.50:8080/video.mjpg"
        masked_http = main._mask_stream_url(url_http)
        self.assertEqual(masked_http, "http://admin:***@192.168.1.50:8080/video.mjpg")

    def test_validate_and_execute_command(self):
        device = {
            "device_id": "cam_001",
            "last_state": {"power": "on", "status": "online"},
        }
        cmd = {"power": "off"}
        main.validate_command(device, cmd)
        result = main.execute_command(device, cmd)
        self.assertEqual(result["power"], "off")
        self.assertEqual(result["stream_url"], "/api/v1/cameras/cam_001/stream")

    def test_probe_state_testsrc(self):
        device = {
            "device_id": "cam_demo",
            "config": {"stream_url": "test", "protocol": "auto"},
        }
        state = main.probe_state(device)
        self.assertEqual(state["status"], "online")
        self.assertEqual(state["fps"], 15)
        self.assertEqual(state["resolution"], "640x360")
        self.assertEqual(state["codec"], "MJPEG")
        self.assertEqual(state["protocol"], "Test Stream")
        self.assertIn("/api/v1/cameras/cam_demo/stream", state["stream_url"])

    def test_probe_state_rtsp_online(self):
        device = {
            "device_id": "cam_rtsp",
            "config": {
                "stream_url": "rtsp://192.168.1.100:554/live",
                "protocol": "rtsp",
            },
        }
        with patch.object(main, "_probe_rtsp_stream", return_value=True):
            state = main.probe_state(device)
            self.assertEqual(state["status"], "online")
            self.assertEqual(state["protocol"], "RTSP")
            self.assertEqual(state["codec"], "H.264")

    def test_probe_state_rtsp_offline(self):
        device = {
            "device_id": "cam_rtsp_dead",
            "config": {
                "stream_url": "rtsp://192.168.1.250:554/live",
                "protocol": "rtsp",
            },
        }
        with patch.object(main, "_probe_rtsp_stream", return_value=False):
            with self.assertRaises(main.ExtensionRuntimeError) as ctx:
                main.probe_state(device)
            self.assertTrue(ctx.exception.mark_offline)
            self.assertTrue(ctx.exception.connection_failed)


if __name__ == "__main__":
    unittest.main()
