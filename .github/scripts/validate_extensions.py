#!/usr/bin/env python3
# Copyright (c) 2026 E-Connect Project. All rights reserved.
"""
Extension Package Validator for E-Connect Marketplace.
Validates all *.zip extension packages against E-Connect standards.
"""

from __future__ import annotations

import ast
import hashlib
import io
import json
import re
import sys
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

MAX_ARCHIVE_BYTES = 5 * 1024 * 1024  # 5 MB
IDENTIFIER_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]{1,119}$")
CAPABILITY_PATTERN = re.compile(r"^[a-z][a-z0-9_]{0,59}$")
PYTHON_SYMBOL_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
SUPPORTED_CONFIG_FIELD_TYPES = {"string", "number", "boolean", "password"}
DEFAULT_PACKAGE_HOOKS = {
    "validate_command",
    "execute_command",
    "probe_state",
}
OPTIONAL_PACKAGE_HOOKS = {
    "discover_devices",
}
FORBIDDEN_NAME_PATTERNS = [
    (re.compile(r"(^|/)(__MACOSX)($|/)"), "macOS resource fork directory (__MACOSX)"),
    (re.compile(r"(^|/)\._"), "macOS AppleDouble hidden file (._*)"),
    (re.compile(r"(^|/)\.DS_Store$"), "macOS Desktop Services Store file (.DS_Store)"),
    (re.compile(r"(^|/)Thumbs\.db$", re.IGNORECASE), "Windows thumbnail cache (Thumbs.db)"),
    (re.compile(r"(^|/)__pycache__($|/)"), "Python bytecode cache directory (__pycache__)"),
    (re.compile(r"\.py[cod]$"), "Python compiled bytecode (*.pyc, *.pyo, *.pyd)"),
    (re.compile(r"(^|/)\.git($|/)"), "Git directory metadata"),
    (re.compile(r"(^|/)(\.vscode|\.idea)($|/)"), "Editor IDE workspace configuration"),
]


class ValidationError(Exception):
    pass


def validate_archive(zip_path: Path) -> dict[str, Any]:
    errors: list[str] = []
    warnings: list[str] = []

    file_bytes = zip_path.read_bytes()
    size_bytes = len(file_bytes)

    if size_bytes == 0:
        raise ValidationError(f"{zip_path.name}: Archive is empty (0 bytes).")
    if size_bytes > MAX_ARCHIVE_BYTES:
        raise ValidationError(
            f"{zip_path.name}: Archive exceeds maximum allowed size of 5 MB ({size_bytes} bytes)."
        )

    try:
        zf = zipfile.ZipFile(io.BytesIO(file_bytes))
    except zipfile.BadZipFile as exc:
        raise ValidationError(f"{zip_path.name}: Invalid or corrupted ZIP archive: {exc}")

    with zf:
        # Check integrity
        corrupt_member = zf.testzip()
        if corrupt_member:
            raise ValidationError(f"{zip_path.name}: Corrupted ZIP member: {corrupt_member}")

        infolist = zf.infolist()
        all_names = [info.filename for info in infolist]

        # Check for forbidden files (macOS junk, cache, etc.)
        for name in all_names:
            for pattern, desc in FORBIDDEN_NAME_PATTERNS:
                if pattern.search(name):
                    errors.append(f"Forbidden entry found: '{name}' ({desc}). Must be excluded during packaging.")

        # Locate manifest.json
        manifest_candidates: list[str] = []
        for info in infolist:
            if info.is_dir():
                continue
            path = PurePosixPath(info.filename)
            if path.name == "manifest.json":
                if len(path.parts) in (1, 2):
                    manifest_candidates.append(info.filename)

        if len(manifest_candidates) == 0:
            errors.append(
                "manifest.json was not found. ZIP must contain manifest.json at root or one folder level deep."
            )
            return {"errors": errors, "warnings": warnings}
        if len(manifest_candidates) > 1:
            errors.append(
                f"Multiple manifest.json candidates found: {manifest_candidates}. Exactly one is required."
            )
            return {"errors": errors, "warnings": warnings}

        manifest_member = manifest_candidates[0]
        manifest_path = PurePosixPath(manifest_member)
        package_root = None if len(manifest_path.parts) == 1 else manifest_path.parts[0]

        # Parse manifest JSON
        try:
            manifest_raw = zf.read(manifest_member).decode("utf-8")
        except UnicodeDecodeError as exc:
            errors.append(f"manifest.json must be UTF-8 encoded: {exc}")
            return {"errors": errors, "warnings": warnings}

        try:
            manifest_data = json.loads(manifest_raw)
        except json.JSONDecodeError as exc:
            errors.append(f"manifest.json contains invalid JSON syntax: {exc}")
            return {"errors": errors, "warnings": warnings}

        if not isinstance(manifest_data, dict):
            errors.append("manifest.json must be a JSON object.")
            return {"errors": errors, "warnings": warnings}

        # Validate manifest version
        if manifest_data.get("manifest_version") != "1.0":
            errors.append(
                f"Unsupported manifest_version: '{manifest_data.get('manifest_version')}'. Expected '1.0'."
            )

        # Validate extension_id
        ext_id = str(manifest_data.get("extension_id", "")).strip().lower()
        if not IDENTIFIER_PATTERN.fullmatch(ext_id):
            errors.append(
                f"Invalid extension_id '{ext_id}'. Must match lowercase slug pattern ^[a-z0-9][a-z0-9_-]{{1,119}}$."
            )

        # Validate name, version, description
        if not str(manifest_data.get("name", "")).strip():
            errors.append("Manifest field 'name' is required and cannot be empty.")
        if not str(manifest_data.get("version", "")).strip():
            errors.append("Manifest field 'version' is required and cannot be empty.")
        if not str(manifest_data.get("description", "")).strip():
            errors.append("Manifest field 'description' is required.")

        # Validate provider
        provider = manifest_data.get("provider")
        if not isinstance(provider, dict):
            errors.append("Manifest field 'provider' must be an object.")
        else:
            provider_key = str(provider.get("key", "")).strip().lower()
            if not IDENTIFIER_PATTERN.fullmatch(provider_key):
                errors.append(f"Invalid provider.key '{provider_key}'. Must match lowercase slug format.")
            if not str(provider.get("display_name", "")).strip():
                errors.append("provider.display_name is required and cannot be empty.")

        # Validate package & entrypoint
        package = manifest_data.get("package")
        if not isinstance(package, dict):
            errors.append("Manifest field 'package' must be an object.")
        else:
            runtime = str(package.get("runtime", "")).strip().lower()
            if runtime != "python":
                errors.append(f"Unsupported package.runtime '{runtime}'. Expected 'python'.")

            entrypoint = str(package.get("entrypoint", "")).strip()
            if not entrypoint or PurePosixPath(entrypoint).is_absolute() or ".." in PurePosixPath(entrypoint).parts:
                errors.append(f"Invalid package.entrypoint '{entrypoint}'. Must be a safe relative path.")
            else:
                entrypoint_member = entrypoint if package_root is None else f"{package_root}/{entrypoint}"
                try:
                    zf.getinfo(entrypoint_member)
                except KeyError:
                    errors.append(
                        f"Entrypoint file '{entrypoint}' (expected member '{entrypoint_member}') was not found in the ZIP."
                    )

            # Validate hooks
            raw_hooks = package.get("hooks") or {}
            if not isinstance(raw_hooks, dict):
                errors.append("package.hooks must be an object.")
            else:
                for req_hook in DEFAULT_PACKAGE_HOOKS:
                    fn_name = raw_hooks.get(req_hook, req_hook)
                    if not isinstance(fn_name, str) or not PYTHON_SYMBOL_PATTERN.fullmatch(fn_name.strip()):
                        errors.append(
                            f"package.hooks.{req_hook} ('{fn_name}') must be a valid Python function symbol."
                        )

        # Validate device_schemas
        schemas = manifest_data.get("device_schemas")
        if not isinstance(schemas, list) or len(schemas) == 0:
            errors.append("Manifest must declare at least one entry in 'device_schemas'.")
        else:
            seen_schema_ids = set()
            for idx, s in enumerate(schemas):
                if not isinstance(s, dict):
                    errors.append(f"device_schemas[{idx}] must be an object.")
                    continue
                sid = str(s.get("schema_id", "")).strip().lower()
                if not IDENTIFIER_PATTERN.fullmatch(sid):
                    errors.append(f"device_schemas[{idx}].schema_id '{sid}' must be a valid lowercase slug.")
                if sid in seen_schema_ids:
                    errors.append(f"Duplicate device schema_id '{sid}'.")
                seen_schema_ids.add(sid)

                if not str(s.get("name", "")).strip():
                    errors.append(f"device_schemas[{idx}] is missing 'name'.")

                display = s.get("display")
                if not isinstance(display, dict):
                    errors.append(f"device_schemas[{idx}] is missing 'display' object.")
                else:
                    card_type = str(display.get("card_type", "")).strip().lower()
                    if not IDENTIFIER_PATTERN.fullmatch(card_type):
                        errors.append(f"device_schemas[{idx}].display.card_type '{card_type}' is invalid.")

                    caps = display.get("capabilities")
                    if not isinstance(caps, list) or len(caps) == 0:
                        errors.append(f"device_schemas[{idx}].display.capabilities must be a non-empty list.")
                    else:
                        for cap in caps:
                            c = str(cap).strip().lower()
                            if not CAPABILITY_PATTERN.fullmatch(c):
                                errors.append(f"device_schemas[{idx}] invalid capability '{c}'.")

        # Validate Python syntax in all .py files
        for name in all_names:
            if name.endswith(".py"):
                try:
                    code = zf.read(name).decode("utf-8")
                    ast.parse(code, filename=name)
                except UnicodeDecodeError as exc:
                    errors.append(f"Python file '{name}' is not valid UTF-8: {exc}")
                except SyntaxError as exc:
                    errors.append(f"Python syntax error in '{name}' line {exc.lineno}: {exc.msg}")

    sha256 = hashlib.sha256(file_bytes).hexdigest()
    return {
        "extension_id": manifest_data.get("extension_id") if "manifest_data" in locals() else "unknown",
        "version": manifest_data.get("version") if "manifest_data" in locals() else "unknown",
        "sha256": sha256,
        "size_kb": round(size_bytes / 1024, 2),
        "package_root": package_root if "package_root" in locals() else None,
        "errors": errors,
        "warnings": warnings,
    }


def main() -> int:
    search_root = Path.cwd()
    if len(sys.argv) > 1:
        search_root = Path(sys.argv[1]).resolve()

    zip_files = sorted(search_root.glob("*.zip"))
    if not zip_files:
        print(f"⚠️  No *.zip extension files found in {search_root}.")
        return 0

    print(f"📦 Found {len(zip_files)} extension package(s) to validate in '{search_root}':")
    print("=" * 70)

    total_errors = 0
    total_warnings = 0

    for zip_path in zip_files:
        print(f"\n🔍 Checking: {zip_path.name} ...")
        try:
            res = validate_archive(zip_path)
            errs = res["errors"]
            warns = res["warnings"]

            if errs:
                total_errors += len(errs)
                print(f"  ❌ FAILED ({len(errs)} error(s)):")
                for err in errs:
                    print(f"     - [ERROR] {err}")
            else:
                ext_id = res["extension_id"]
                ver = res["version"]
                size_kb = res["size_kb"]
                sha_prefix = res["sha256"][:12]
                root_mode = f"folder '{res['package_root']}'" if res["package_root"] else "flat root"
                print(f"  ✅ PASS: id={ext_id} | version={ver} | size={size_kb} KB | sha={sha_prefix} | {root_mode}")

            if warns:
                total_warnings += len(warns)
                for w in warns:
                    print(f"     - [WARN] {w}")

        except Exception as exc:
            total_errors += 1
            print(f"  ❌ FATAL ERROR: {exc}")

    print("\n" + "=" * 70)
    if total_errors > 0:
        print(f"💥 Validation completed with {total_errors} error(s). Packaging check FAILED.")
        return 1
    else:
        print(f"🎉 All {len(zip_files)} extension package(s) PASSED validation! Ready for Marketplace.")
        return 0


if __name__ == "__main__":
    sys.exit(main())
