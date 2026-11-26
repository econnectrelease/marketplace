# Copyright (c) 2026 Đinh Trung Kiên. All rights reserved.
"""
# [INPUT]: depends on ftplib, ssl, socket, io, os, typing, logging
# [OUTPUT]: exports ImplicitFTP_TLS, stream_3mf_to_printer
# [POS]: FTPS client module with Zero-Disk Cache and TLS Session Reuse for Bambu Lab SD card transfer
# [PROTOCOL]: Update this header on change
"""

from __future__ import annotations

import ftplib  # nosec B402
import io
import logging
import os
import socket
import ssl
from typing import BinaryIO

logger = logging.getLogger("econnect.bambulab.ftps")


class ImplicitFTP_TLS(ftplib.FTP_TLS):
    """Implicit FTPS client implementation for Bambu Lab printers.

    Bambu Lab 3D printers serve FTPS on port 990 with implicit SSL/TLS.
    Standard Python ftplib.FTP_TLS assumes explicit TLS on port 21 via AUTH TLS.
    This class wraps the control socket immediately on connection and enforces
    TLS session reuse on the secondary data connection channel.
    """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._sock = None

    def connect(self, host: str = "", port: int = 990, timeout: float = -999) -> str:
        """Establish an implicit TLS connection to the Bambu FTPS server."""
        if host != "":
            self.host = host
        if port > 0:
            self.port = port
        if timeout != -999:
            self.timeout = timeout

        # Create base TCP connection
        raw_sock = socket.create_connection((self.host, self.port), self.timeout)

        # Build SSL context with certificate verification disabled for printer LAN self-signed certs
        if self.context is None:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            self.context = ctx

        # Wrap raw socket in TLS before reading the welcome message
        self.sock = self.context.wrap_socket(raw_sock, server_hostname=self.host)
        self.af = self.sock.family
        self.file = self.sock.makefile("r", encoding=self.encoding)

        # Read banner response from printer
        self.welcome = self.getresp()
        return self.welcome

    def ntransfercmd(self, cmd: str, rest: int | None = None) -> tuple[socket.socket, int | None]:
        """Wrap data connection using the existing TLS session (TLS Session Reuse).

        Bambu Lab printer FTPS server strictly requires that the SSL session of the
        data connection matches the control channel SSL session.
        """
        conn, size = super().ntransfercmd(cmd, rest)
        if self._prot_p and not isinstance(conn, ssl.SSLSocket):
            # Enforce TLS session reuse on data socket
            session = getattr(self.sock, "session", None)
            conn = self.context.wrap_socket(
                conn,
                server_hostname=self.host,
                session=session,
            )
        return conn, size


def stream_3mf_to_printer(
    ip: str,
    access_code: str,
    file_stream: BinaryIO | io.BytesIO,
    filename: str,
    timeout: float = 30.0,
    port: int | None = None,
) -> bool:
    """Stream a .3mf sliced file from an in-memory buffer directly to the printer's SD card.

    Architecture constraint: Zero-Disk Cache.
    The file data is read exclusively from the RAM stream (file_stream) and pushed
    via FTPS block transfer directly into the printer's MicroSD storage.
    No temporary files are created on the host machine filesystem.

    Args:
        ip: Printer IP address.
        access_code: LAN Access Code.
        file_stream: In-memory binary file buffer.
        filename: Target filename on the SD card (e.g. 'plate_1.gcode.3mf').
        timeout: Network socket timeout in seconds.
        port: Optional FTPS port override (defaults to BAMBU_FTPS_PORT or 990).

    Returns:
        bool: True if upload completed with FTP 226 success code.
    """
    raw_name = str(filename or "").replace("\\", "/")
    parts = [p for p in raw_name.split("/") if p]
    if ".." in parts:
        raise ValueError(f"Path traversal detected in filename '{filename}'.")

    safe_filename = os.path.basename(raw_name).lstrip("/")
    if not safe_filename:
        raise ValueError("Filename cannot be empty or root path.")
    target_path = f"/{safe_filename}"

    logger.info("Starting Zero-Disk FTPS upload of '%s' to printer %s", safe_filename, ip)

    ftps_port = port if port is not None else int(os.getenv("BAMBU_FTPS_PORT", "990"))
    ftps = ImplicitFTP_TLS(timeout=timeout)
    try:
        ftps.connect(host=ip, port=ftps_port)
        ftps.login(user="bblp", passwd=access_code)
        ftps.prot_p()  # Enforce Private data channel protection

        # Seek to beginning of stream if possible
        if hasattr(file_stream, "seek"):
            file_stream.seek(0)

        # Stream memory buffer in 64 KB blocks directly to remote SD card
        response = ftps.storbinary(f"STOR {target_path}", file_stream, blocksize=65536)
        logger.info("Upload of '%s' finished with response: %s", safe_filename, response)
        return "226" in response or "Transfer complete" in response
    except Exception as exc:
        logger.error("Failed to stream .3mf to printer %s: %s", ip, exc)
        raise RuntimeError(f"FTPS stream upload error: {exc}") from exc
    finally:
        try:
            ftps.quit()
        except Exception:
            try:
                ftps.close()
            except Exception:
                pass

