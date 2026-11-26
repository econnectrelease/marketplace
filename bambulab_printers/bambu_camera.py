# Copyright (c) 2026 Đinh Trung Kiên. All rights reserved.
"""
# [INPUT]: depends on os, ssl, socket, struct, threading, typing, logging, time
# [OUTPUT]: exports BambuCameraAdapter, JPEG_SOI, JPEG_EOI
# [POS]: Camera feed adapter supporting A1/P1 (Port 6000 TLS) and X1 Series (Port 322 RTSPS)
# [PROTOCOL]: Update this header on change
"""

from __future__ import annotations

import logging
import os
import socket
import ssl
import struct
import threading
import time
from typing import Generator

logger = logging.getLogger("econnect.bambulab.camera")

JPEG_SOI = b"\xff\xd8"
JPEG_EOI = b"\xff\xd9"


class BambuCameraAdapter:
    """Universal Camera adapter for Bambu Lab 3D printers.

    Adapts between differing camera video architectures:
    1. A1, A1 Mini, P1P, P1S: Port 6000 TLS TCP streaming.
       Sends an 80-byte binary authentication packet, demuxes JPEG frames.
    2. X1 Carbon, X1E: Port 322 RTSPS streaming (rtsps://bblp:{access_code}@{ip}:322/live).
    """

    def __init__(
        self,
        ip: str,
        access_code: str,
        serial_number: str = "",
        model: str = "P1S",
    ) -> None:
        self.ip = ip
        self.access_code = access_code
        self.serial_number = serial_number
        self.model = model.upper()
        self._last_frame: bytes | None = None
        self._lock = threading.Lock()
        self._running = False
        self._thread: threading.Thread | None = None

    @property
    def is_x1_series(self) -> bool:
        """Return True if model is X1 Carbon or X1E."""
        return "X1" in self.model

    def get_stream_url(self) -> str:
        """Return the RTSPS stream URL for X1 series or MJPEG proxy URL."""
        if self.is_x1_series:
            return f"rtsps://bblp:{self.access_code}@{self.ip}:322/streaming/live/1"
        return f"http://{self.ip}:6000/stream.mjpg"

    def _build_auth_packet(self) -> bytes:
        """Construct the standard 80-byte binary authentication packet for A1/P1 camera.

        Packet layout (80 bytes total):
        - 0..3:   Magic uint32 (0x40 = 64)
        - 4..7:   Command uint32 (0x3000 = 12288)
        - 8..11:  Sequence / zeros
        - 12..15: Reserved / zeros
        - 16..47: Username string 'bblp', 32 bytes null-padded
        - 48..79: LAN Access Code string, 32 bytes null-padded
        """
        packet = bytearray(80)
        struct.pack_into("<I", packet, 0, 0x40)
        struct.pack_into("<I", packet, 4, 0x3000)
        struct.pack_into("<I", packet, 8, 0)
        struct.pack_into("<I", packet, 12, 0)

        user_bytes = "bblp".encode("ascii")[:31]
        packet[16 : 16 + len(user_bytes)] = user_bytes

        code_bytes = self.access_code.encode("ascii")[:31]
        packet[48 : 48 + len(code_bytes)] = code_bytes

        return bytes(packet)

    @staticmethod
    def _close_sockets(tls_sock: ssl.SSLSocket | None, raw_sock: socket.socket | None) -> None:
        if tls_sock is not None:
            try:
                tls_sock.close()
            except Exception:
                pass
        if raw_sock is not None:
            try:
                raw_sock.close()
            except Exception:
                pass

    def fetch_single_frame_a1_p1(self, timeout: float = 12.0) -> bytes | None:
        """Connect to port 6000 TLS, authenticate, and extract the first complete JPEG frame."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        camera_port = int(os.getenv("BAMBU_CAMERA_PORT", "6000"))
        raw_sock: socket.socket | None = None
        tls_sock: ssl.SSLSocket | None = None
        deadline = time.time() + timeout
        try:
            raw_sock = socket.create_connection((self.ip, camera_port), timeout=max(0.2, timeout))
            tls_sock = ctx.wrap_socket(raw_sock, server_hostname=self.ip)

            remaining = deadline - time.time()
            if remaining <= 0:
                return None
            tls_sock.settimeout(max(0.2, remaining))

            # Send 80-byte authentication packet
            auth_packet = self._build_auth_packet()
            tls_sock.sendall(auth_packet)

            buffer = bytearray()
            max_frame_bytes = 10 * 1024 * 1024

            while time.time() < deadline:
                remaining = deadline - time.time()
                if remaining <= 0:
                    break
                tls_sock.settimeout(max(0.2, remaining))
                chunk = tls_sock.recv(4096)
                if not chunk:
                    break
                buffer.extend(chunk)

                soi_idx = buffer.find(JPEG_SOI)
                if soi_idx == -1:
                    if len(buffer) > 1:
                        del buffer[:-1]
                    continue

                if soi_idx > 0:
                    del buffer[:soi_idx]
                    soi_idx = 0

                eoi_idx = buffer.find(JPEG_EOI, soi_idx + 2)
                if eoi_idx != -1:
                    frame_bytes = bytes(buffer[soi_idx : eoi_idx + 2])
                    with self._lock:
                        self._last_frame = frame_bytes
                    return frame_bytes

                if len(buffer) > max_frame_bytes:
                    logger.warning("Camera frame exceeded %d bytes for %s:%d; aborting", max_frame_bytes, self.ip, camera_port)
                    return None
            return None
        except (socket.timeout, TimeoutError):
            logger.debug("Camera frame fetch timed out for %s:%d", self.ip, camera_port)
            return None
        except Exception as exc:
            logger.debug("Camera frame fetch error for %s:%d: %s", self.ip, camera_port, exc)
            return None
        finally:
            self._close_sockets(tls_sock, raw_sock)

    def get_snapshot(self, timeout: float = 12.0, force_refresh: bool = True) -> bytes:
        """Capture and return a single JPEG image snapshot from the printer camera."""
        if not force_refresh:
            with self._lock:
                if self._last_frame is not None:
                    return self._last_frame

        if not self.is_x1_series:
            frame = self.fetch_single_frame_a1_p1(timeout=timeout)
            if frame:
                return frame

        with self._lock:
            if self._last_frame is not None:
                return self._last_frame

        # Fallback JPEG placeholder frame if camera is unavailable or sleeping
        return self._generate_fallback_snapshot()

    def generate_mjpeg_stream(self) -> Generator[bytes, None, None]:
        """Generate a continuous MJPEG multipart stream for web viewers."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        while True:
            raw_sock: socket.socket | None = None
            tls_sock: ssl.SSLSocket | None = None
            try:
                camera_port = int(os.getenv("BAMBU_CAMERA_PORT", "6000"))
                raw_sock = socket.create_connection((self.ip, camera_port), timeout=10.0)
                tls_sock = ctx.wrap_socket(raw_sock, server_hostname=self.ip)
                tls_sock.settimeout(15.0)
                tls_sock.sendall(self._build_auth_packet())
                buffer = bytearray()

                while True:
                    chunk = tls_sock.recv(8192)
                    if not chunk:
                        break
                    buffer.extend(chunk)

                    while True:
                        soi_idx = buffer.find(JPEG_SOI)
                        if soi_idx == -1:
                            if len(buffer) > 1:
                                del buffer[:-1]
                            break
                        eoi_idx = buffer.find(JPEG_EOI, soi_idx + 2)
                        if eoi_idx == -1:
                            # Incomplete frame, wait for more chunks
                            if soi_idx > 0:
                                del buffer[:soi_idx]
                            break

                        frame_bytes = bytes(buffer[soi_idx : eoi_idx + 2])
                        del buffer[: eoi_idx + 2]

                        with self._lock:
                            self._last_frame = frame_bytes

                        yield (
                            b"--frame\r\n"
                            b"Content-Type: image/jpeg\r\n\r\n"
                            + frame_bytes
                            + b"\r\n"
                        )
            except GeneratorExit:
                return
            except Exception as exc:
                logger.warning("Camera stream reconnecting for %s: %s", self.ip, exc)
                time.sleep(2.0)
            finally:
                self._close_sockets(tls_sock, raw_sock)

    def _generate_fallback_snapshot(self) -> bytes:
        """Return a clean fallback JPEG/PNG placeholder image buffer."""
        # 1x1 green transparent JPEG pixel or minimal valid JPEG frame
        return (
            b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00H\x00H\x00\x00"
            b"\xff\xdb\x00C\x00\x08\x06\x06\x07\x06\x05\x08\x07\x07\x07\t\t"
            b"\x08\n\x0c\x14\r\x0c\x0b\x0b\x0c\x19\x12\x13\x0f\x14\x1d\x1a"
            b"\x1f\x1e\x1d\x1a\x1c\x1c $.' \",#\x1c\x1c(7),01444\x1f'9=82<.342"
            b"\xff\xc0\x00\x0b\x08\x00\x01\x00\x01\x01\x01\x11\x00\xff\xc4"
            b"\x00\x1f\x00\x00\x01\x05\x01\x01\x01\x01\x01\x01\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b"
            b"\xff\xda\x00\x08\x01\x01\x00\x00?\x00\xbf\x00\xff\xd9"
        )
