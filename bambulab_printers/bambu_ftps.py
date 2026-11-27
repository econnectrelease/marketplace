# Copyright (c) 2026 Đinh Trung Kiên. All rights reserved.
"""
# [INPUT]: depends on ftplib, ssl, socket, io, os, zipfile, json, base64, re, math, threading, time, typing, logging
# [OUTPUT]: exports ImplicitFTP_TLS, stream_3mf_to_printer, list_sd_files, extract_3mf_preview, clear_3mf_preview_cache, _3MF_PREVIEW_CACHE, simplify_points, chain_segments
# [POS]: FTPS client module with Zero-Disk Cache, TLS Session Reuse, non-blocking background preview extraction, multi-object outer wall G-code parsing with segment chaining, and in-memory 3MF parsing for Bambu Lab SD card transfer
# [PROTOCOL]: Update this header on change, then check GEMINI.md
"""

from __future__ import annotations

import base64
import ftplib  # nosec B402
import io
import json
import logging
import math
import os
import re
import socket
import ssl
import threading
import time
from typing import Any, BinaryIO
import zipfile

logger = logging.getLogger("econnect.bambulab.ftps")

# In-memory RAM cache for extracted 3MF previews (Zero-Disk Cache architecture)
_3MF_PREVIEW_CACHE: dict[str, dict[str, Any]] = {}
_3MF_PREVIEW_LOCK = threading.Lock()
_PENDING_DOWNLOADS: set[str] = set()
_FAILED_ATTEMPTS: dict[str, float] = {}
_RETRY_INTERVAL = 15.0


def clear_3mf_preview_cache() -> None:
    """Clear in-memory 3MF preview cache (useful for testing or cache invalidation)."""
    with _3MF_PREVIEW_LOCK:
        _3MF_PREVIEW_CACHE.clear()
        _PENDING_DOWNLOADS.clear()
        _FAILED_ATTEMPTS.clear()


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


def list_sd_files(
    ip: str,
    access_code: str,
    directory: str = "/",
    timeout: float = 10.0,
    port: int | None = None,
) -> list[dict[str, Any]]:
    """List 3D printable files (.3mf, .gcode) on the printer's MicroSD card via FTPS.

    Connects using Implicit TLS on port 990, logs in with bblp credentials, and lists
    files using ftps.mlsd() with a fallback to ftps.nlst().

    Args:
        ip: Printer IP address.
        access_code: LAN Access Code.
        directory: Target directory on the SD card (default "/").
        timeout: Network socket timeout in seconds.
        port: Optional FTPS port override (defaults to BAMBU_FTPS_PORT or 990).

    Returns:
        list[dict[str, Any]]: List of file records:
            [{"name": "cube.3mf", "path": "cube.3mf", "size": 1024000, "modify": "..."}]
    """
    ftps_port = port if port is not None else int(os.getenv("BAMBU_FTPS_PORT", "990"))
    ftps = ImplicitFTP_TLS(timeout=timeout)
    results: list[dict[str, Any]] = []

    clean_dir = directory.strip() or "/"
    try:
        ftps.connect(host=ip, port=ftps_port)
        ftps.login(user="bblp", passwd=access_code)
        ftps.prot_p()

        use_nlst = False
        try:
            entries = list(ftps.mlsd(clean_dir))
            for name, facts in entries:
                if facts.get("type") in ("dir", "pdir", "cdir"):
                    continue
                clean_name = os.path.basename(name.replace("\\", "/")).lstrip("/")
                if not clean_name or clean_name.startswith("."):
                    continue
                lower_name = clean_name.lower()
                if lower_name.endswith(".3mf") or lower_name.endswith(".gcode"):
                    try:
                        size = int(facts.get("size", 0))
                    except (ValueError, TypeError):
                        size = 0
                    modify = str(facts.get("modify", ""))
                    item_path = f"{clean_dir.rstrip('/')}/{clean_name}".lstrip("/") if clean_dir.strip("/") else clean_name
                    results.append({
                        "name": clean_name,
                        "path": item_path,
                        "size": size,
                        "modify": modify,
                    })
        except Exception as mlsd_err:
            logger.debug("mlsd failed on %s, falling back to nlst: %s", ip, mlsd_err)
            use_nlst = True

        if use_nlst:
            raw_entries = ftps.nlst(clean_dir)
            for entry in raw_entries:
                clean_name = os.path.basename(entry.replace("\\", "/")).lstrip("/")
                if not clean_name or clean_name.startswith("."):
                    continue
                lower_name = clean_name.lower()
                if lower_name.endswith(".3mf") or lower_name.endswith(".gcode"):
                    item_path = f"{clean_dir.rstrip('/')}/{clean_name}".lstrip("/") if clean_dir.strip("/") else clean_name
                    size = 0
                    try:
                        size = ftps.size(entry) or 0
                    except Exception:
                        pass
                    results.append({
                        "name": clean_name,
                        "path": item_path,
                        "size": size,
                        "modify": "",
                    })

        return results
    except Exception as exc:
        logger.warning("Failed to list SD files from printer %s: %s", ip, exc)
        return []
    finally:
        try:
            ftps.quit()
        except Exception:
            try:
                ftps.close()
            except Exception:
                pass


def _clean_subtask_and_candidates(name: str) -> tuple[str, str, list[str]]:
    """Clean filename or subtask name and construct candidate FTPS download paths in order.

    Returns:
        tuple[base_name, safe_name, candidate_paths]
    """
    raw_name = str(name or "").strip().replace("\\", "/")
    parts = [p for p in raw_name.split("/") if p]
    if ".." in parts:
        raise ValueError(f"Path traversal detected in filename '{name}'.")

    cleaned = raw_name.lstrip("/")
    normalized = re.sub(r"^cache/", "", cleaned, flags=re.IGNORECASE).lstrip("/")
    base_name = re.sub(r"\.3mf$", "", normalized, flags=re.IGNORECASE)
    safe_name = f"{base_name}.3mf"

    raw_candidates = [
        f"/cache/{base_name}.3mf",
        f"/{base_name}.3mf",
        f"/cache/{normalized}",
        f"/{normalized}",
    ]
    candidate_paths: list[str] = []
    seen: set[str] = set()
    for c in raw_candidates:
        if c not in seen:
            seen.add(c)
            candidate_paths.append(c)

    return base_name, safe_name, candidate_paths


def simplify_points(pts: list[list[float]], min_dist: float = 0.5) -> list[list[float]]:
    """Simplify 2D polygon points by discarding points closer than min_dist.

    Preserves first and last point to maintain closed loop contours.
    """
    if len(pts) <= 2:
        return [[round(p[0], 2), round(p[1], 2)] for p in pts]

    simplified: list[list[float]] = [pts[0]]
    for pt in pts[1:-1]:
        last = simplified[-1]
        dist = math.hypot(pt[0] - last[0], pt[1] - last[1])
        if dist >= min_dist:
            simplified.append(pt)

    # If original loop was closed (end close to start), always close it
    is_closed = math.hypot(pts[-1][0] - pts[0][0], pts[-1][1] - pts[0][1]) < 3.5
    if is_closed:
        if math.hypot(pts[-1][0] - simplified[-1][0], pts[-1][1] - simplified[-1][1]) > 0.05:
            simplified.append(pts[-1])
    else:
        last = simplified[-1]
        dist = math.hypot(pts[-1][0] - last[0], pts[-1][1] - last[1])
        if dist < (min_dist / 2.0) and len(simplified) > 1:
            simplified[-1] = pts[-1]
        else:
            simplified.append(pts[-1])

    return [[round(p[0], 2), round(p[1], 2)] for p in simplified]


def chain_segments(segments: list[list[list[float]]], max_gap: float = 3.5) -> list[list[list[float]]]:
    """Chain contiguous or fragmented outer wall segments into closed loops or extended paths."""
    if not segments:
        return []
    pool = [list(s) for s in segments if len(s) >= 2]
    if not pool:
        return []

    def _pt_dist(p1: list[float], p2: list[float]) -> float:
        return math.hypot(p1[0] - p2[0], p1[1] - p2[1])

    chains: list[list[list[float]]] = []
    while pool:
        chain = pool.pop(0)
        extended = True
        while extended:
            extended = False
            last_p = chain[-1]
            first_p = chain[0]
            best_idx = None
            best_d = max_gap
            mode = None

            for j, seg in enumerate(pool):
                d = _pt_dist(last_p, seg[0])
                if d < best_d:
                    best_d = d
                    best_idx = j
                    mode = "append"
                d = _pt_dist(last_p, seg[-1])
                if d < best_d:
                    best_d = d
                    best_idx = j
                    mode = "append_rev"
                d = _pt_dist(seg[-1], first_p)
                if d < best_d:
                    best_d = d
                    best_idx = j
                    mode = "prepend"
                d = _pt_dist(seg[0], first_p)
                if d < best_d:
                    best_d = d
                    best_idx = j
                    mode = "prepend_rev"

            if best_idx is not None:
                seg = pool.pop(best_idx)
                if mode == "append":
                    chain.extend(seg)
                elif mode == "append_rev":
                    chain.extend(reversed(seg))
                elif mode == "prepend":
                    chain = seg + chain
                elif mode == "prepend_rev":
                    chain = list(reversed(seg)) + chain
                extended = True

        if len(chain) >= 3 and 0.05 < _pt_dist(chain[0], chain[-1]) < max_gap:
            chain.append(list(chain[0]))
        chains.append(chain)

    return chains


def _parse_gcode_layers(
    gcode_text: str,
) -> tuple[int, float, float, list[dict[str, Any]]]:
    """Parse BambuStudio/OrcaSlicer G-code to extract real outer wall loops per layer.

    Supports multiple discrete objects on the build plate (e.g. Removable Bucket and Holder).
    Chains fragmented perimeter segments up to 3.5mm, sorts loops by 2D bbox area,
    keeps up to 64 loops per layer without dropping slats/louvers, interpolates circular arcs (G2/G3),
    and simplifies points to keep payload compact and 60fps fast.
    """
    header_total = re.search(r";\s*total layer number:\s*(\d+)", gcode_text, re.IGNORECASE)
    header_max_z = re.search(r";\s*max_z_height:\s*([\d\.]+)", gcode_text, re.IGNORECASE)
    header_lh = re.search(r";\s*layer_height\s*=\s*([\d\.]+)", gcode_text, re.IGNORECASE)

    total_layers = int(header_total.group(1)) if header_total else 0
    max_z = float(header_max_z.group(1)) if header_max_z else 0.0
    layer_height = float(header_lh.group(1)) if header_lh else 0.2

    layers: list[dict[str, Any]] = []
    cur_loop: list[list[float]] = []
    outer_wall_loops: list[list[list[float]]] = []
    all_loops: list[list[list[float]]] = []
    layer_z_samples: list[float] = []

    cur_x: float | None = None
    cur_y: float | None = None
    cur_z: float | None = None
    cur_e: float | None = None
    relative_e: bool = True  # Bambu standard (M83)
    cur_outer_wall: bool = False
    in_block = False
    started = False

    has_layer_num = bool(re.search(r";\s*layer num/total_layer_count:\s*\d+/\d+", gcode_text, re.IGNORECASE))
    if has_layer_num:
        layer_marker = re.compile(r"^\s*;\s*layer num/total_layer_count:\s*(\d+)/(\d+)", re.IGNORECASE)
    else:
        layer_marker = re.compile(
            r"^\s*;\s*(?:CHANGE_LAYER|LAYER_CHANGE|AFTER_LAYER_CHANGE|BEFORE_LAYER_CHANGE|LAYER:\s*\d+)",
            re.IGNORECASE,
        )

    object_marker = re.compile(
        r"^\s*;\s*(?:start printing object|stop printing object|printing object)",
        re.IGNORECASE,
    )
    feature_marker = re.compile(
        r"^\s*;\s*(?:FEATURE|TYPE):\s*(.+)$",
        re.IGNORECASE,
    )

    def finish_loop() -> None:
        nonlocal cur_loop
        if len(cur_loop) >= 2:
            loop_copy = list(cur_loop)
            all_loops.append(loop_copy)
            if cur_outer_wall:
                outer_wall_loops.append(loop_copy)
        cur_loop = []

    def loop_bbox_area(pts: list[list[float]]) -> float:
        if len(pts) < 2:
            return 0.0
        xs = [p[0] for p in pts]
        ys = [p[1] for p in pts]
        return (max(xs) - min(xs)) * (max(ys) - min(ys))

    def finish_layer() -> None:
        nonlocal outer_wall_loops, all_loops, layer_z_samples, cur_loop
        finish_loop()

        raw_segments = outer_wall_loops if outer_wall_loops else all_loops
        if not raw_segments:
            outer_wall_loops = []
            all_loops = []
            layer_z_samples = []
            return

        lz = min(layer_z_samples) if layer_z_samples else (cur_z if cur_z is not None else 0.0)

        chained = chain_segments(raw_segments, max_gap=3.5)
        valid_loops = []
        for ch in chained:
            if len(ch) < 2:
                continue
            xs = [p[0] for p in ch]
            ys = [p[1] for p in ch]
            diag = math.hypot(max(xs) - min(xs), max(ys) - min(ys))
            if diag >= 1.0:
                valid_loops.append(ch)

        if not valid_loops and chained:
            valid_loops = [ch for ch in chained if len(ch) >= 2]

        sorted_loops = sorted(valid_loops, key=loop_bbox_area, reverse=True)
        sig_raw = sorted_loops[:64]

        sig_loops: list[list[list[float]]] = []
        for l in sig_raw:
            simplified = simplify_points(l, min_dist=0.5)
            if len(simplified) >= 2:
                sig_loops.append(simplified)

        main_pts = sig_loops[0] if sig_loops else []

        if sig_loops:
            layers.append({
                "z": round(lz, 2),
                "pts": main_pts,
                "paths": sig_loops,
            })

        outer_wall_loops = []
        all_loops = []
        layer_z_samples = []

    for line in gcode_text.splitlines():
        trimmed = line.strip()
        if not trimmed:
            continue

        if "; CONFIG_BLOCK_START" in trimmed or "; HEADER_BLOCK_START" in trimmed:
            in_block = True
            continue
        if "; CONFIG_BLOCK_END" in trimmed or "; HEADER_BLOCK_END" in trimmed:
            in_block = False
            continue
        if in_block:
            continue

        if layer_marker.match(trimmed):
            if started:
                finish_layer()
            started = True
            cur_outer_wall = False
            continue

        if not started:
            continue

        if object_marker.match(trimmed):
            finish_loop()
            cur_outer_wall = False
            continue

        feat_match = feature_marker.match(trimmed)
        if feat_match:
            finish_loop()
            feat_name = feat_match.group(1).strip().lower()
            if any(k in feat_name for k in ("outer wall", "wall-outer", "external perimeter", "overhang wall", "floating vertical shell")):
                cur_outer_wall = True
            else:
                cur_outer_wall = False
            continue

        if trimmed.startswith("M82"):
            relative_e = False
            continue
        if trimmed.startswith("M83"):
            relative_e = True
            continue
        if trimmed.startswith("G92"):
            for p in trimmed.split(";", 1)[0].split():
                if p.startswith("E"):
                    try:
                        cur_e = float(p[1:])
                    except ValueError:
                        pass
            continue

        if (
            trimmed.startswith("G0 ")
            or trimmed.startswith("G1 ")
            or trimmed.startswith("G2 ")
            or trimmed.startswith("G3 ")
            or trimmed == "G0"
            or trimmed == "G1"
        ):
            cmd_body = trimmed.split(";", 1)[0]
            parts = cmd_body.split()
            cmd = parts[0]
            nx = cur_x
            ny = cur_y
            nz = cur_z
            e_val: float | None = None
            arc_i: float | None = None
            arc_j: float | None = None

            for p in parts[1:]:
                if p.startswith("X"):
                    try:
                        nx = float(p[1:])
                    except ValueError:
                        pass
                elif p.startswith("Y"):
                    try:
                        ny = float(p[1:])
                    except ValueError:
                        pass
                elif p.startswith("Z"):
                    try:
                        nz = float(p[1:])
                    except ValueError:
                        pass
                elif p.startswith("E"):
                    try:
                        e_val = float(p[1:])
                    except ValueError:
                        pass
                elif p.startswith("I"):
                    try:
                        arc_i = float(p[1:])
                    except ValueError:
                        pass
                elif p.startswith("J"):
                    try:
                        arc_j = float(p[1:])
                    except ValueError:
                        pass

            if nz is not None:
                cur_z = nz

            if e_val is not None:
                if relative_e:
                    is_extruding = e_val > 0.0
                else:
                    is_extruding = (cur_e is not None and e_val > cur_e) or (cur_e is None and e_val > 0.0)
                cur_e = e_val
            else:
                is_extruding = False

            has_xy_move = (
                nx is not None
                and ny is not None
                and cur_x is not None
                and cur_y is not None
                and (nx != cur_x or ny != cur_y)
            )

            if has_xy_move:
                if is_extruding:
                    if not cur_loop:
                        cur_loop.append([round(cur_x, 2), round(cur_y, 2)])
                    if (cmd == "G2" or cmd == "G3") and arc_i is not None and arc_j is not None:
                        is_cw = cmd == "G2"
                        cen_x = cur_x + arc_i
                        cen_y = cur_y + arc_j
                        r = math.hypot(arc_i, arc_j)
                        if r >= 0.2:
                            sa = math.atan2(cur_y - cen_y, cur_x - cen_x)
                            ea = math.atan2(ny - cen_y, nx - cen_x)
                            if is_cw:
                                if ea >= sa:
                                    ea -= 2 * math.pi
                                diff = sa - ea
                            else:
                                if ea <= sa:
                                    ea += 2 * math.pi
                                diff = ea - sa
                            steps = max(1, min(8, int((r * diff) / 1.5)))
                            for s in range(1, steps):
                                frac = s / steps
                                ang = sa - frac * diff if is_cw else sa + frac * diff
                                cur_loop.append([round(cen_x + r * math.cos(ang), 2), round(cen_y + r * math.sin(ang), 2)])
                    cur_loop.append([round(nx, 2), round(ny, 2)])
                    if cur_z is not None:
                        layer_z_samples.append(cur_z)
                else:
                    finish_loop()

                cur_x = nx
                cur_y = ny
            elif nx is not None and ny is not None:
                cur_x = nx
                cur_y = ny

    if started:
        finish_layer()

    if not total_layers:
        total_layers = len(layers)
    if not max_z and layers:
        max_z = max(l["z"] for l in layers)

    return total_layers, max_z, layer_height, layers


def _fetch_and_parse_3mf(
    ip: str,
    access_code: str,
    candidate_paths: list[str],
    safe_name: str,
    port: int | None = None,
    timeout: float = 10.0,
) -> dict[str, Any] | None:
    """Download .3mf archive from printer SD card to an in-memory buffer and parse preview data.

    Architecture constraint: Zero-Disk Cache.
    All transfers and extractions operate strictly within memory buffers (io.BytesIO).
    """
    ftps_port = port if port is not None else int(os.getenv("BAMBU_FTPS_PORT", "990"))
    ftps = ImplicitFTP_TLS(timeout=timeout)
    buf = io.BytesIO()
    download_success = False

    try:
        ftps.connect(host=ip, port=ftps_port)
        ftps.login(user="bblp", passwd=access_code)
        ftps.prot_p()

        for candidate in candidate_paths:
            buf.seek(0)
            buf.truncate(0)
            try:
                ftps.retrbinary(f"RETR {candidate}", buf.write)
                if buf.tell() > 0:
                    download_success = True
                    logger.info("Successfully fetched .3mf preview from %s (%d bytes)", candidate, buf.tell())
                    break
            except Exception as retr_err:
                logger.debug("Candidate %s not found on printer %s: %s", candidate, ip, retr_err)
                continue
    except Exception as exc:
        logger.warning("FTPS connection error fetching preview from printer %s: %s", ip, exc)
        return None
    finally:
        try:
            ftps.quit()
        except Exception:
            try:
                ftps.close()
            except Exception:
                pass

    if not download_success or buf.tell() == 0:
        logger.info("3MF file for '%s' not found on printer %s", safe_name, ip)
        return None

    # Parse archive in-memory
    buf.seek(0)
    try:
        with zipfile.ZipFile(buf) as zf:
            namelist = zf.namelist()

            def _extract_image_b64(path: str) -> str | None:
                if path in namelist:
                    try:
                        raw = zf.read(path)
                        if raw:
                            b64 = base64.b64encode(raw).decode("ascii")
                            return f"data:image/png;base64,{b64}"
                    except Exception as img_err:
                        logger.debug("Failed reading %s: %s", path, img_err)
                return None

            thumbnail = _extract_image_b64("Metadata/plate_1.png")
            if not thumbnail:
                thumbnail = _extract_image_b64("Metadata/plate_1_small.png")
            top_view = _extract_image_b64("Metadata/top_1.png")
            pick_view = _extract_image_b64("Metadata/pick_1.png")

            bbox_all: list[float] = []
            filament_colors: list[str] = []
            json_layer_height: float | None = None

            if "Metadata/plate_1.json" in namelist:
                try:
                    plate_meta = json.loads(zf.read("Metadata/plate_1.json").decode("utf-8", errors="ignore"))
                    if isinstance(plate_meta, dict):
                        if isinstance(plate_meta.get("bbox_all"), list):
                            bbox_all = [float(v) for v in plate_meta["bbox_all"]]
                        raw_colors = plate_meta.get("filament_colors")
                        if isinstance(raw_colors, list):
                            clean_cols: list[str] = []
                            for c in raw_colors:
                                col_str = str(c).strip()
                                if col_str:
                                    if not col_str.startswith("#") and len(col_str) in (6, 8):
                                        col_str = f"#{col_str}"
                                    clean_cols.append(col_str)
                            filament_colors = clean_cols
                        elif isinstance(plate_meta.get("filaments"), list):
                            clean_cols = []
                            for f in plate_meta["filaments"]:
                                if isinstance(f, dict) and "color" in f:
                                    col_str = str(f["color"]).strip()
                                    if not col_str.startswith("#") and len(col_str) in (6, 8):
                                        col_str = f"#{col_str}"
                                    clean_cols.append(col_str)
                            filament_colors = clean_cols
                        if plate_meta.get("layer_height") is not None:
                            try:
                                json_layer_height = float(plate_meta["layer_height"])
                            except (ValueError, TypeError):
                                pass
                        elif plate_meta.get("bbox_objects"):
                            objs = plate_meta["bbox_objects"]
                            if isinstance(objs, list) and len(objs) > 0 and isinstance(objs[0], dict):
                                if objs[0].get("layer_height") is not None:
                                    try:
                                        json_layer_height = float(objs[0]["layer_height"])
                                    except (ValueError, TypeError):
                                        pass
                except Exception as json_err:
                    logger.debug("Failed parsing plate_1.json from 3MF: %s", json_err)

            total_layers = 0
            max_z = 0.0
            gcode_layer_height = 0.2
            layers: list[dict[str, Any]] = []

            if "Metadata/plate_1.gcode" in namelist:
                try:
                    gcode_text = zf.read("Metadata/plate_1.gcode").decode("utf-8", errors="ignore")
                    total_layers, max_z, gcode_layer_height, layers = _parse_gcode_layers(gcode_text)
                except Exception as gcode_err:
                    logger.debug("Failed parsing plate_1.gcode: %s", gcode_err)

            final_lh = json_layer_height if json_layer_height is not None else gcode_layer_height

            return {
                "thumbnail": thumbnail,
                "top_view": top_view,
                "pick_view": pick_view,
                "bbox": bbox_all,
                "filament_colors": filament_colors,
                "total_layers": total_layers,
                "layer_height": round(final_lh, 3) if final_lh else 0.2,
                "max_z": round(max_z, 2),
                "layers": layers,
                "filename": safe_name,
                "real_preview_available": True,
            }
    except Exception as zip_err:
        logger.warning("Corrupted or invalid 3MF archive from printer %s: %s", ip, zip_err)
        return None


def _bg_worker(
    ip: str,
    access_code: str,
    cleaned_input: str,
    base_name: str,
    safe_name: str,
    candidate_paths: list[str],
    port: int | None,
    timeout: float,
) -> None:
    """Daemon thread worker performing zero-disk FTPS download and in-memory 3MF parsing."""
    cache_key = f"{ip}:{cleaned_input}"
    safe_key = f"{ip}:{safe_name}"
    base_key = f"{ip}:{base_name}"
    try:
        data = _fetch_and_parse_3mf(
            ip=ip,
            access_code=access_code,
            candidate_paths=candidate_paths,
            safe_name=safe_name,
            port=port,
            timeout=timeout,
        )
        with _3MF_PREVIEW_LOCK:
            if data is not None and data.get("real_preview_available"):
                _3MF_PREVIEW_CACHE[cache_key] = data
                _3MF_PREVIEW_CACHE[safe_key] = data
                _3MF_PREVIEW_CACHE[base_key] = data
                _FAILED_ATTEMPTS.pop(cache_key, None)
                _FAILED_ATTEMPTS.pop(safe_key, None)
                _FAILED_ATTEMPTS.pop(base_key, None)
            else:
                fail_time = time.monotonic()
                _FAILED_ATTEMPTS[cache_key] = fail_time
                _FAILED_ATTEMPTS[safe_key] = fail_time
                _FAILED_ATTEMPTS[base_key] = fail_time
    except Exception as exc:
        logger.warning("Background 3MF fetch worker error on %s: %s", ip, exc)
        with _3MF_PREVIEW_LOCK:
            fail_time = time.monotonic()
            _FAILED_ATTEMPTS[cache_key] = fail_time
            _FAILED_ATTEMPTS[safe_key] = fail_time
            _FAILED_ATTEMPTS[base_key] = fail_time
    finally:
        with _3MF_PREVIEW_LOCK:
            _PENDING_DOWNLOADS.discard(cache_key)
            _PENDING_DOWNLOADS.discard(safe_key)
            _PENDING_DOWNLOADS.discard(base_key)


def extract_3mf_preview(
    ip: str,
    access_code: str,
    filename_or_subtask: str,
    port: int | None = None,
    timeout: float = 10.0,
    non_blocking: bool = False,
) -> dict[str, Any]:
    """Extract slicer preview images, real G-code layers, bbox, and layer count from a .3mf file on SD card.

    Architecture constraint: Zero-Disk Cache.
    Operations use in-memory bytes buffers (io.BytesIO) and zipfile.ZipFile without writing to disk.
    Cached in RAM (_3MF_PREVIEW_CACHE) keyed by f"{ip}:{filename_or_subtask}".

    Args:
        ip: Printer IP address.
        access_code: LAN Access Code.
        filename_or_subtask: Target filename or active subtask name on SD card.
        port: Optional FTPS port override.
        timeout: Socket timeout for network operations.
        non_blocking: If True, returns immediately. On cache miss, spawns a background daemon thread
            _bg_worker to download and parse the .3mf, returning {"real_preview_available": False, "loading": True}.
            On cache hit, returns the parsed preview dict in <1ms.
    """
    cleaned_input = str(filename_or_subtask or "").strip()
    if not cleaned_input or not ip:
        return {"real_preview_available": False}

    try:
        base_name, safe_name, candidate_paths = _clean_subtask_and_candidates(cleaned_input)
    except Exception as clean_err:
        logger.warning("Invalid 3MF preview request for '%s': %s", filename_or_subtask, clean_err)
        return {"real_preview_available": False}

    cache_key = f"{ip}:{cleaned_input}"
    safe_key = f"{ip}:{safe_name}"
    base_key = f"{ip}:{base_name}"

    with _3MF_PREVIEW_LOCK:
        if cache_key in _3MF_PREVIEW_CACHE:
            return _3MF_PREVIEW_CACHE[cache_key]
        if safe_key in _3MF_PREVIEW_CACHE:
            return _3MF_PREVIEW_CACHE[safe_key]
        if base_key in _3MF_PREVIEW_CACHE:
            return _3MF_PREVIEW_CACHE[base_key]

        if non_blocking:
            if cache_key in _PENDING_DOWNLOADS or safe_key in _PENDING_DOWNLOADS or base_key in _PENDING_DOWNLOADS:
                return {"real_preview_available": False, "loading": True}

            now = time.monotonic()
            fail_time = _FAILED_ATTEMPTS.get(cache_key) or _FAILED_ATTEMPTS.get(safe_key) or _FAILED_ATTEMPTS.get(base_key)
            if fail_time is not None and (now - fail_time) < _RETRY_INTERVAL:
                return {"real_preview_available": False}

            _PENDING_DOWNLOADS.add(cache_key)
            _PENDING_DOWNLOADS.add(safe_key)
            _PENDING_DOWNLOADS.add(base_key)

            worker = threading.Thread(
                target=_bg_worker,
                args=(ip, access_code, cleaned_input, base_name, safe_name, candidate_paths, port, timeout),
                name=f"bambu-3mf-bg-{cleaned_input[:16]}",
                daemon=True,
            )
            worker.start()
            return {"real_preview_available": False, "loading": True}

    # Synchronous path (non_blocking=False)
    data = _fetch_and_parse_3mf(
        ip=ip,
        access_code=access_code,
        candidate_paths=candidate_paths,
        safe_name=safe_name,
        port=port,
        timeout=timeout,
    )
    if data is not None and data.get("real_preview_available"):
        with _3MF_PREVIEW_LOCK:
            _3MF_PREVIEW_CACHE[cache_key] = data
            _3MF_PREVIEW_CACHE[safe_key] = data
            _3MF_PREVIEW_CACHE[base_key] = data
            _FAILED_ATTEMPTS.pop(cache_key, None)
            _FAILED_ATTEMPTS.pop(safe_key, None)
            _FAILED_ATTEMPTS.pop(base_key, None)
        return data
    else:
        with _3MF_PREVIEW_LOCK:
            fail_time = time.monotonic()
            _FAILED_ATTEMPTS[cache_key] = fail_time
            _FAILED_ATTEMPTS[safe_key] = fail_time
            _FAILED_ATTEMPTS[base_key] = fail_time
        return {"real_preview_available": False}



