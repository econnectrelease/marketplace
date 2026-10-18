# Copyright (c) 2026 E-Connect Project. All rights reserved.
"""Read-only monitoring extension for Synology DSM appliances on the local LAN."""

from __future__ import annotations

import hashlib
import json
import logging
import os
from pathlib import Path
import ssl
import tempfile
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, urlopen

logger = logging.getLogger(__name__)

try:
    from app.services.extension_runtime_api import (
        ExtensionRuntimeError,
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


AUTH_API = "SYNO.API.Auth"
API_INFO = "SYNO.API.Info"
STORAGE_API = "SYNO.Storage.CGI.Storage"
SYSTEM_API = "SYNO.Core.System"
REQUEST_TIMEOUT_SECONDS = 8
MAX_RESPONSE_BYTES = 1024 * 1024

# Process-level memory cache for active sessions across polling loops
_MEMORY_SESSION_CACHE: dict[str, dict[str, Any]] = {}


def _resolve_session_dir() -> Path:
    """Find a reliable persistent directory for session cache files."""
    candidates = [
        Path("/var/lib/econnect/data/sessions"),
        Path.home() / ".econnect" / "synology_sessions",
        Path(tempfile.gettempdir()) / "econnect_synology_sessions",
        Path("/tmp") / "econnect_synology_sessions",
    ]
    for p in candidates:
        try:
            p.mkdir(parents=True, exist_ok=True)
            test_file = p / ".write_test"
            test_file.write_text("ok", encoding="utf-8")
            test_file.unlink(missing_ok=True)
            return p
        except Exception:
            continue
    return Path("/tmp")


def _get_cached_session(cache_key: str) -> dict[str, Any]:
    """Retrieve cached session info from memory or persistent disk file."""
    if cache_key in _MEMORY_SESSION_CACHE:
        return dict(_MEMORY_SESSION_CACHE[cache_key])

    try:
        session_file = _resolve_session_dir() / f"synology_{cache_key}.json"
        if session_file.is_file():
            payload = json.loads(session_file.read_text(encoding="utf-8"))
            if isinstance(payload, dict):
                _MEMORY_SESSION_CACHE[cache_key] = payload
                return dict(payload)
    except Exception as exc:
        logger.debug("Failed to read cached session for %s: %s", cache_key, exc)

    return {}


def _save_cached_session(cache_key: str, data: dict[str, Any]) -> None:
    """Save session info (sid, device_id, synotoken) in memory and on disk."""
    data_copy = dict(data)
    _MEMORY_SESSION_CACHE[cache_key] = data_copy
    try:
        session_dir = _resolve_session_dir()
        session_file = session_dir / f"synology_{cache_key}.json"
        tmp_file = session_dir / f"synology_{cache_key}.json.tmp"
        tmp_file.write_text(json.dumps(data_copy), encoding="utf-8")
        tmp_file.replace(session_file)
    except Exception as exc:
        logger.debug("Failed to persist cached session for %s: %s", cache_key, exc)


def _clear_cached_sid(cache_key: str) -> None:
    """Clear only the active session ID, keeping device_id (trusted 2FA token) intact."""
    cached = _get_cached_session(cache_key)
    if not cached:
        return
    cached.pop("sid", None)
    _save_cached_session(cache_key, cached)


def _clear_all_sessions() -> None:
    """Reset all sessions in memory and on disk (used in tests and reset)."""
    _MEMORY_SESSION_CACHE.clear()
    session_dir = _resolve_session_dir()
    if session_dir.exists():
        for f in session_dir.glob("synology_*.json*"):
            try:
                f.unlink(missing_ok=True)
            except OSError:
                pass


def validate_command(device: dict[str, Any], command: dict[str, Any]) -> None:
    """Allow only an explicit, non-mutating refresh action."""
    _get_config(device)
    action = str(command.get("command") or command.get("action") or "refresh").strip().lower()
    if action != "refresh":
        raise ExtensionValidationError("Synology NAS Monitor is read-only; only the 'refresh' action is supported.")


def execute_command(device: dict[str, Any], command: dict[str, Any]) -> dict[str, Any]:
    """Refreshes the monitored state without issuing a DSM control command."""
    validate_command(device, command)
    return probe_state(device)


def probe_state(device: dict[str, Any]) -> dict[str, Any]:
    """Authenticate to DSM and return monitoring & data protection metrics."""
    config = _get_config(device)
    client = _DsmClient(config)
    metric_errors: list[str] = []

    storage_raw: Any = None
    storage: dict[str, Any] | None = None
    try:
        storage_raw = client.call(STORAGE_API, "load_info")
        storage = _extract_storage(storage_raw)
        if storage is None:
            metric_errors.append("DSM did not return a usable volume capacity.")
    except ExtensionValidationError:
        raise
    except ExtensionRuntimeError as exc:
        if exc.connection_failed or exc.mark_offline:
            raise
        metric_errors.append("Storage capacity could not be read from DSM.")

    system_info: Any = None
    temperature: float | None = None
    try:
        system_info = client.call(SYSTEM_API, "info")
        temperature = _extract_temperature(system_info)
        if temperature is None:
            metric_errors.append("System temperature is not exposed by this DSM model or version.")
    except ExtensionValidationError:
        raise
    except ExtensionRuntimeError as exc:
        if exc.connection_failed or exc.mark_offline:
            raise
        metric_errors.append("System temperature could not be read from DSM.")

    # NOTE: We deliberately do NOT call client.logout() here.
    # Preserving the session across probe intervals avoids invalidating the 30-second TOTP
    # and eliminates redundant login round-trips to the NAS.

    # Extract rich Data Protection metrics (RAID, Scrubbing, Disks, SMART)
    data_protection_info = _extract_data_protection(storage_raw, system_info)

    dsm_status = storage.get("status", "healthy") if storage is not None else "healthy"

    state: dict[str, Any] = {
        "value": dsm_status,
        "value1": storage["used_bytes"] if storage is not None else None,
        "value2": storage["total_bytes"] if storage is not None else None,
        "value3": temperature,
        "storage_used": storage["used_bytes"] if storage is not None else None,
        "storage_total": storage["total_bytes"] if storage is not None else None,
        "storage_percent": storage["used_percent"] if storage is not None else None,
        "storage_free": storage["free_bytes"] if storage is not None else None,
        "dsm_status": dsm_status,
        "data_protection": data_protection_info.get("summary", {}),
        "storage_pools": data_protection_info.get("storage_pools", []),
        "volumes": data_protection_info.get("volumes", []),
        "disks": data_protection_info.get("disks", []),
        "system_info": data_protection_info.get("system", {}),
    }
    if metric_errors:
        state["metric_warnings"] = metric_errors

    return {"conn_status": "online", "state": state}


def _get_config(device: dict[str, Any]) -> dict[str, Any]:
    config = device.get("config")
    if not isinstance(config, dict):
        raise ExtensionValidationError("Synology NAS configuration is missing.")

    base_url = str(config.get("base_url") or "").strip().rstrip("/")
    username = str(config.get("username") or "").strip()
    password = config.get("password")
    otp_code = config.get("otp_code")
    parsed = urlsplit(base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ExtensionValidationError("base_url must be a complete http:// or https:// DSM URL.")
    if parsed.username or parsed.password or parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ExtensionValidationError("base_url must only contain the DSM scheme, host, and optional port.")
    if not username:
        raise ExtensionValidationError("DSM username is required.")
    if not isinstance(password, str) or not password:
        raise ExtensionValidationError("DSM password is required.")
    if otp_code is not None:
        if not isinstance(otp_code, str):
            raise ExtensionValidationError("otp_code must be a six-digit DSM TOTP code when provided.")
        otp_code = otp_code.strip()
        if not otp_code:
            otp_code = None
        elif len(otp_code) != 6 or not otp_code.isascii() or not otp_code.isdecimal():
            raise ExtensionValidationError("otp_code must be a six-digit DSM TOTP code when provided.")

    verify_tls = config.get("verify_tls", False)
    if not isinstance(verify_tls, bool):
        raise ExtensionValidationError("verify_tls must be a boolean.")
    return {
        "base_url": base_url,
        "username": username,
        "password": password,
        "otp_code": otp_code,
        "verify_tls": verify_tls,
    }


class _DsmClient:
    def __init__(self, config: dict[str, Any]) -> None:
        self.base_url = config["base_url"]
        self.username = config["username"]
        self.password = config["password"]
        self.otp_code = config.get("otp_code")
        self.verify_tls = config["verify_tls"]

        self.cache_key = hashlib.sha256(f"{self.base_url}|{self.username}".encode("utf-8")).hexdigest()[:16]
        cached = _get_cached_session(self.cache_key)
        self.sid: str | None = cached.get("sid")
        self.device_id: str | None = cached.get("device_id")
        self.synotoken: str | None = cached.get("synotoken")
        self.api_paths: dict[str, str] = {}
        self.api_versions: dict[str, int] = {}
        self._discovery_done: bool = False

    def _ensure_api_paths(self) -> None:
        if not self._discovery_done:
            self._discover_api_paths()

    def ensure_authenticated(self) -> None:
        """Reuse persistent session if present; otherwise authenticate."""
        if not self.sid:
            self.login()

    def login(self) -> None:
        self._ensure_api_paths()
        login_params: dict[str, Any] = {
            "api": AUTH_API,
            "version": self._version_for(AUTH_API, 3),
            "method": "login",
            "account": self.username,
            "passwd": self.password,
            "session": "FileStation",
            "format": "sid",
            "enable_device_token": "yes",
        }

        # If we previously established 2FA trust with this DSM, provide device_id to bypass OTP prompt
        if self.device_id:
            login_params["device_id"] = self.device_id
            login_params["device_name"] = "E-Connect Smart Home Hub"
        elif self.otp_code:
            login_params["otp_code"] = self.otp_code
            login_params["device_name"] = "E-Connect Smart Home Hub"

        path = self.api_paths.get(AUTH_API, "/webapi/entry.cgi")
        response = self._request(path, login_params)

        if response.get("success") is not True:
            error = response.get("error") if isinstance(response.get("error"), dict) else {}
            code = error.get("code")

            if code in (403, 404) and not self.otp_code and not self.device_id:
                raise ExtensionRuntimeError(
                    "Tài khoản Synology NAS đang bật bảo mật 2 bước (2FA OTP). Vui lòng nhập mã OTP 6 số hiện tại trong cấu hình để liên kết thiết bị.",
                    mark_offline=True,
                    connection_failed=True,
                )
            elif code in (404, 406):
                raise ExtensionRuntimeError(
                    "Mã xác thực 2 bước (2FA OTP) không chính xác hoặc đã hết hạn (DSM error 404/406). Vui lòng kiểm tra lại mã trên ứng dụng xác thực.",
                    mark_offline=True,
                    connection_failed=True,
                )
            elif code == 400:
                raise ExtensionRuntimeError(
                    "Tài khoản hoặc mật khẩu Synology DSM không chính xác (DSM error 400).",
                    mark_offline=True,
                    connection_failed=True,
                )
            elif code == 401:
                raise ExtensionRuntimeError(
                    "Tài khoản Synology DSM đã bị vô hiệu hóa (DSM error 401).",
                    mark_offline=True,
                    connection_failed=True,
                )
            elif code == 402:
                raise ExtensionRuntimeError(
                    "Tài khoản Synology DSM bị từ chối quyền truy cập (DSM error 402).",
                    mark_offline=True,
                    connection_failed=True,
                )
            else:
                raise _offline_error(f"DSM login request failed (DSM error {code}).")

        data = response.get("data", {})
        if not isinstance(data, dict):
            raise _offline_error("DSM login did not return valid data.")

        sid = data.get("sid")
        if not isinstance(sid, str) or not sid:
            raise _offline_error("DSM login did not return a session identifier.")

        self.sid = sid

        # Remember device token for subsequent 2FA bypass
        new_device_id = data.get("device_id") or data.get("device_token")
        if isinstance(new_device_id, str) and new_device_id.strip():
            self.device_id = new_device_id.strip()

        synotoken = data.get("synotoken")
        if isinstance(synotoken, str) and synotoken.strip():
            self.synotoken = synotoken.strip()

        # Save both login step (sid) and 2FA step (device_id) to persistent cache
        _save_cached_session(self.cache_key, {
            "sid": self.sid,
            "device_id": self.device_id,
            "synotoken": self.synotoken,
            "cached_at": time.time(),
        })

    def logout(self) -> None:
        """Explicitly terminate the session and clear cache if requested."""
        if not self.sid:
            return
        try:
            self._request(
                self.api_paths.get(AUTH_API, "/webapi/entry.cgi"),
                {
                    "api": AUTH_API,
                    "version": self._version_for(AUTH_API, 1),
                    "method": "logout",
                    "session": "FileStation",
                    "_sid": self.sid,
                },
            )
        except ExtensionRuntimeError:
            pass
        finally:
            self.sid = None
            _clear_cached_sid(self.cache_key)

    def call(self, api: str, method: str, params: dict[str, Any] | None = None) -> Any:
        self._ensure_api_paths()
        self.ensure_authenticated()
        request_params: dict[str, Any] = {
            "api": api,
            "version": self._version_for(api, 1),
            "method": method,
            "_sid": self.sid,
        }
        if params:
            request_params.update(params)

        path = self.api_paths.get(api, "/webapi/entry.cgi")
        response = self._request(path, request_params)

        if response.get("success") is not True:
            error = response.get("error") if isinstance(response.get("error"), dict) else {}
            code = error.get("code")

            # Check for session expiration codes: 119 (SID invalid), 105 (permission denied), 106 (session timeout)
            if code in (105, 106, 119):
                logger.info("Synology DSM session expired (DSM code %s). Re-authenticating with saved device token...", code)
                _clear_cached_sid(self.cache_key)
                self.sid = None
                self.login()

                # Retry the API call once with the refreshed session
                request_params["_sid"] = self.sid
                retry_response = self._request(path, request_params)
                return _success_data(retry_response, api)

            return _success_data(response, api)

        return response.get("data", {})

    def _discover_api_paths(self) -> None:
        self._discovery_done = True
        try:
            response = self._request(
                "/webapi/query.cgi",
                {"api": API_INFO, "version": 1, "method": "query", "query": "all"},
            )
            data = _success_data(response, "DSM API discovery")
        except ExtensionRuntimeError:
            return
        if not isinstance(data, dict):
            return
        for api in (AUTH_API, STORAGE_API, SYSTEM_API):
            item = data.get(api)
            path = item.get("path") if isinstance(item, dict) else None
            if isinstance(path, str) and path.startswith("/"):
                self.api_paths[api] = path
            max_version = item.get("maxVersion") if isinstance(item, dict) else None
            if isinstance(max_version, int) and max_version > 0:
                self.api_versions[api] = max_version

    def _version_for(self, api: str, fallback: int) -> int:
        return self.api_versions.get(api, fallback)

    def _request(self, path: str, params: dict[str, Any]) -> dict[str, Any]:
        context = None
        if self.base_url.startswith("https://") and not self.verify_tls:
            context = ssl._create_unverified_context()
        payload = urlencode(params).encode("utf-8")
        request = Request(
            f"{self.base_url}{path}",
            data=payload,
            headers={"Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        try:
            with urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS, context=context) as response:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
        except (HTTPError, URLError, TimeoutError, OSError, ssl.SSLError) as exc:
            raise _offline_error("Could not connect to Synology DSM.") from exc
        if len(raw) > MAX_RESPONSE_BYTES:
            raise _offline_error("DSM returned a response that is too large.")
        try:
            decoded = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise _offline_error("DSM returned an invalid JSON response.") from exc
        if not isinstance(decoded, dict):
            raise _offline_error("DSM returned an invalid response object.")
        return decoded


def _success_data(response: dict[str, Any], api_name: str) -> Any:
    if response.get("success") is True:
        return response.get("data", {})
    error = response.get("error")
    code = error.get("code") if isinstance(error, dict) else "unknown"
    raise _offline_error(f"{api_name} request failed (DSM error {code}).")


def _offline_error(message: str) -> ExtensionRuntimeError:
    return ExtensionRuntimeError(message, mark_offline=True, connection_failed=True)


def _extract_storage(data: Any) -> dict[str, Any] | None:
    volumes = data.get("volumes") if isinstance(data, dict) else None
    if not isinstance(volumes, list):
        volumes = data.get("volume") if isinstance(data, dict) else None
    candidates = volumes if isinstance(volumes, list) else [volumes] if isinstance(volumes, dict) else []

    total_bytes = 0
    used_bytes = 0
    volume_statuses: list[str] = []

    for volume in candidates:
        if not isinstance(volume, dict):
            continue
        size = volume.get("size") if isinstance(volume.get("size"), dict) else volume
        total = _as_non_negative_int(size.get("total"))
        used = _as_non_negative_int(size.get("used"))
        if total is not None and used is not None and used <= total:
            total_bytes += total
            used_bytes += used

        v_status = str(volume.get("status") or volume.get("summary_status") or "").lower()
        if v_status:
            volume_statuses.append(v_status)
        space_status = volume.get("space_status")
        if isinstance(space_status, dict):
            detail = str(space_status.get("detail") or space_status.get("status") or space_status.get("summary_status") or "").lower()
            if any(w in detail for w in ("degrade", "fail")):
                volume_statuses.append("degraded")
            elif any(w in detail for w in ("crash", "danger", "error")):
                volume_statuses.append("crashed")
            elif any(w in detail for w in ("warn", "attention")):
                volume_statuses.append("warning")

    pools = data.get("storagePools") if isinstance(data, dict) else None
    if isinstance(pools, list):
        for pool in pools:
            if isinstance(pool, dict):
                p_status = str(pool.get("status") or pool.get("summary_status") or "").lower()
                if p_status:
                    volume_statuses.append(p_status)

    if total_bytes == 0:
        return None

    if any(s in ("crashed", "danger", "error", "crash") for s in volume_statuses):
        dsm_status = "crashed"
    elif any(s in ("degraded", "degrade") for s in volume_statuses):
        dsm_status = "degraded"
    elif any(s in ("warning", "attention", "warn") for s in volume_statuses):
        dsm_status = "warning"
    elif any(s in ("repairing", "rebuilding", "resyncing") for s in volume_statuses):
        dsm_status = "repairing"
    else:
        dsm_status = "healthy"

    return {
        "total_bytes": total_bytes,
        "used_bytes": used_bytes,
        "free_bytes": total_bytes - used_bytes,
        "used_percent": round((used_bytes / total_bytes) * 100, 2),
        "status": dsm_status,
    }


def _extract_data_protection(storage_raw: Any, system_info: Any) -> dict[str, Any]:
    """Extract in-depth data protection metrics: RAID topology, Data Scrubbing status, Disks & SMART."""
    if not isinstance(storage_raw, dict):
        storage_raw = {}
    if not isinstance(system_info, dict):
        system_info = {}

    pools_data = storage_raw.get("storagePools") if isinstance(storage_raw.get("storagePools"), list) else []
    vols_data = storage_raw.get("volumes") if isinstance(storage_raw.get("volumes"), list) else []
    disks_data = storage_raw.get("disks") if isinstance(storage_raw.get("disks"), list) else []

    storage_pools: list[dict[str, Any]] = []
    for p in pools_data:
        if not isinstance(p, dict):
            continue
        dev_type = str(p.get("device_type") or "").strip()
        status = str(p.get("status") or p.get("summary_status") or "normal").lower()
        scrub_status = str(p.get("scrubbingStatus") or "").strip()
        p_size = p.get("size") if isinstance(p.get("size"), dict) else {}

        storage_pools.append({
            "id": p.get("id"),
            "name": p.get("desc") or p.get("id") or "Storage Pool 1",
            "device_type": dev_type,
            "status": status,
            "disk_failure_number": _as_non_negative_int(p.get("disk_failure_number")) or 0,
            "scrubbing_status": scrub_status,
            "last_done_time": _as_non_negative_int(p.get("last_done_time")),
            "next_schedule_time": _as_non_negative_int(p.get("next_schedule_time")),
            "total_bytes": _as_non_negative_int(p_size.get("total")),
            "used_bytes": _as_non_negative_int(p_size.get("used")),
        })

    volumes: list[dict[str, Any]] = []
    for v in vols_data:
        if not isinstance(v, dict):
            continue
        v_size = v.get("size") if isinstance(v.get("size"), dict) else {}
        volumes.append({
            "id": v.get("id"),
            "name": v.get("vol_desc") or v.get("id") or "Volume 1",
            "fs_type": str(v.get("fs_type") or "btrfs").lower(),
            "status": str(v.get("status") or v.get("summary_status") or "normal").lower(),
            "total_bytes": _as_non_negative_int(v_size.get("total")),
            "used_bytes": _as_non_negative_int(v_size.get("used")),
        })

    disks: list[dict[str, Any]] = []
    total_unc = 0
    healthy_disks_count = 0
    for idx, d in enumerate(disks_data):
        if not isinstance(d, dict):
            continue
        d_status = str(d.get("status") or "normal").lower()
        smart_status = str(d.get("smart_status") or "normal").lower()
        unc = _as_non_negative_int(d.get("unc")) or 0
        total_unc += unc

        is_healthy = d_status in ("normal", "healthy") and smart_status in ("normal", "healthy") and unc == 0
        if is_healthy:
            healthy_disks_count += 1

        disks.append({
            "id": d.get("id") or f"disk_{idx+1}",
            "name": d.get("longName") or d.get("name") or f"Drive {idx+1}",
            "vendor": str(d.get("vendor") or "").strip(),
            "model": str(d.get("model") or "").strip(),
            "serial": str(d.get("serial") or "").strip(),
            "size_total": _as_non_negative_int(d.get("size_total")),
            "status": d_status,
            "smart_status": smart_status,
            "unc": unc,
            "temp": _as_temperature(d.get("temp")),
            "slot_id": _as_non_negative_int(d.get("slot_id") or d.get("order")) or (idx + 1),
        })

    primary_pool = storage_pools[0] if storage_pools else {}
    primary_vol = volumes[0] if volumes else {}

    dev_type_str = primary_pool.get("device_type", "").lower()
    if "shr_with_1_disk_protect" in dev_type_str or "shr1" in dev_type_str:
        raid_name = "Synology Hybrid RAID (SHR)"
        fault_tolerance = "Chịu lỗi 1 ổ đĩa"
    elif "shr_with_2_disk_protect" in dev_type_str or "shr2" in dev_type_str:
        raid_name = "Synology Hybrid RAID (SHR-2)"
        fault_tolerance = "Chịu lỗi 2 ổ đĩa"
    elif "raid_1" in dev_type_str or "raid1" in dev_type_str:
        raid_name = "RAID 1 (Mirror)"
        fault_tolerance = "Chịu lỗi 1 ổ đĩa"
    elif "raid_5" in dev_type_str or "raid5" in dev_type_str:
        raid_name = "RAID 5"
        fault_tolerance = "Chịu lỗi 1 ổ đĩa"
    elif "raid_6" in dev_type_str or "raid6" in dev_type_str:
        raid_name = "RAID 6"
        fault_tolerance = "Chịu lỗi 2 ổ đĩa"
    elif "raid_0" in dev_type_str or "basic" in dev_type_str:
        raid_name = "Basic / RAID 0"
        fault_tolerance = "Không chịu lỗi"
    elif dev_type_str:
        raid_name = dev_type_str.upper()
        fault_tolerance = "Bảo vệ mảng RAID"
    else:
        raid_name = "SHR / RAID"
        fault_tolerance = "Bảo vệ dữ liệu"

    pool_status = primary_pool.get("status", "normal")
    has_failed_disks = any(d.get("status") in ("crashed", "danger", "error", "fail", "degraded") for d in disks)
    if pool_status in ("crashed", "danger", "error") or primary_pool.get("disk_failure_number", 0) > 0:
        overall = "crashed"
    elif pool_status in ("degraded", "warning") or has_failed_disks:
        overall = "degraded"
    elif total_unc > 0:
        overall = "warning"
    else:
        overall = "safe"

    summary = {
        "overall": overall,
        "raid_type": primary_pool.get("device_type", ""),
        "raid_name": raid_name,
        "fault_tolerance": fault_tolerance,
        "pool_status": pool_status,
        "total_drives": len(disks),
        "healthy_drives": healthy_disks_count,
        "total_bad_sectors": total_unc,
        "scrubbing_status": primary_pool.get("scrubbing_status", ""),
        "scrubbing_last_done": primary_pool.get("last_done_time"),
        "scrubbing_next_schedule": primary_pool.get("next_schedule_time"),
        "filesystem": primary_vol.get("fs_type", "btrfs"),
    }

    system = {
        "model": system_info.get("model"),
        "firmware_ver": system_info.get("firmware_ver"),
        "uptime": system_info.get("up_time"),
        "ram_mb": system_info.get("ram_size"),
    }

    return {
        "summary": summary,
        "storage_pools": storage_pools,
        "volumes": volumes,
        "disks": disks,
        "system": system,
    }


def _extract_temperature(data: Any) -> float | None:
    if not isinstance(data, dict):
        return None
    for key in ("sys_temp", "system_temperature", "temperature", "temp"):
        value = _find_value(data, key)
        numeric = _as_temperature(value)
        if numeric is not None:
            return numeric
    return None


def _find_value(data: Any, key: str) -> Any:
    if isinstance(data, dict):
        if key in data:
            return data[key]
        for value in data.values():
            found = _find_value(value, key)
            if found is not None:
                return found
    elif isinstance(data, list):
        for value in data:
            found = _find_value(value, key)
            if found is not None:
                return found
    return None


def _as_non_negative_int(value: Any) -> int | None:
    try:
        numeric = int(value)
    except (TypeError, ValueError):
        return None
    return numeric if numeric >= 0 else None


def _as_temperature(value: Any) -> float | None:
    try:
        temperature = float(value)
    except (TypeError, ValueError):
        return None
    return temperature if 0 <= temperature <= 120 else None
