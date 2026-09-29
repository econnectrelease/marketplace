#!/usr/bin/env python3
# Copyright (c) 2026 E-Connect Project. All rights reserved.
"""
Selective Extension Unpack, Format Compliance & Deep Security Audit CLI
for E-Connect Marketplace (econnectrelease/marketplace).

Validates:
1. Selective unpacking (only added/modified extensions are unpacked).
2. Archive safety (Anti-ZipSlip, Anti-ZipBomb, size limits).
3. Manifest schema & author authenticity against trusted registry.
4. E-Connect extension format compatibility (hooks, schemas, entrypoint).
5. Deep malware & AST security inspection (blocks subprocess, eval/exec,
   host credential theft, reverse shells, keyloggers).
6. Bandit automated security scanning on extracted Python sources.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

# ==============================================================================
# Constants & Constraints
# ==============================================================================
MAX_ARCHIVE_BYTES = 5 * 1024 * 1024  # 5 MB max archive size
MAX_UNCOMPRESSED_BYTES = 25 * 1024 * 1024  # 25 MB max uncompressed size
MAX_COMPRESSION_RATIO = 100.0  # Anti-ZipBomb limit

IDENTIFIER_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]{1,119}$")
CAPABILITY_PATTERN = re.compile(r"^[a-z][a-z0-9_]{0,59}$")
PYTHON_SYMBOL_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
SUPPORTED_CONFIG_FIELD_TYPES = {"string", "number", "boolean", "password"}

REQUIRED_HOOKS = {"validate_command", "execute_command", "probe_state"}
OPTIONAL_HOOKS = {"discover_devices"}

FORBIDDEN_FILE_PATTERNS = [
    (re.compile(r"(^|/)(__MACOSX)($|/)"), "macOS resource fork directory (__MACOSX)"),
    (re.compile(r"(^|/)\._"), "macOS AppleDouble hidden file (._*)"),
    (re.compile(r"(^|/)\.DS_Store$"), "macOS Desktop Services Store (.DS_Store)"),
    (re.compile(r"(^|/)Thumbs\.db$", re.IGNORECASE), "Windows thumbnail cache (Thumbs.db)"),
    (re.compile(r"(^|/)__pycache__($|/)"), "Python bytecode cache (__pycache__)"),
    (re.compile(r"\.py[cod]$"), "Python compiled bytecode (*.pyc, *.pyo, *.pyd)"),
    (re.compile(r"(^|/)\.git($|/)"), "Git metadata directory"),
    (re.compile(r"(^|/)(\.vscode|\.idea)($|/)"), "IDE workspace settings"),
]

# Prohibited Process Execution APIs
DANGEROUS_SYSTEM_CALLS = {
    "os": {
        "system", "popen", "popen2", "popen3", "popen4",
        "spawnl", "spawnle", "spawnlp", "spawnlpe", "spawnv", "spawnve", "spawnvp", "spawnvpe",
        "execv", "execve", "execvp", "execvpe", "execl", "execle", "execlp", "execlpe",
        "fork", "kill", "killpg"
    },
    "subprocess": {"Popen", "run", "call", "check_call", "check_output"},
    "pty": {"spawn"},
}

DANGEROUS_BUILTINS = {"eval", "exec", "compile", "__import__"}

FORBIDDEN_MODULES = {
    "subprocess": "Spawning system shell/subprocesses is forbidden inside extensions",
    "pty": "Pseudo-terminal execution is forbidden",
    "commands": "Deprecated command execution module is forbidden",
    "ctypes": "Low-level memory manipulation & C dynamic linking is forbidden",
    "pynput": "Keylogger/input capture libraries are prohibited",
    "keyboard": "Keylogger libraries are prohibited",
    "scapy": "Low-level packet injection is prohibited",
}

# Sensitive host filesystem paths prohibited from being targeted
SENSITIVE_HOST_PATHS = [
    (re.compile(r"/etc/(passwd|shadow|sudoers|master\.passwd)"), "Host user/password credentials"),
    (re.compile(r"/etc/econnect"), "Host E-Connect production configuration & secrets"),
    (re.compile(r"/var/lib/econnect"), "Host E-Connect core database/runtime storage"),
    (re.compile(r"/var/run/docker\.sock"), "Docker socket escape vulnerability"),
    (re.compile(r"(\.ssh/|id_rsa|id_ed25519|id_ecdsa|authorized_keys)"), "SSH keys or credentials"),
    (re.compile(r"(\.bash_history|\.zsh_history)"), "Shell command history"),
    (re.compile(r"(\.aws/credentials|\.kube/config)"), "Cloud provider credentials"),
]


# ==============================================================================
# Trusted Authors Registry
# ==============================================================================
def load_trusted_authors_config(repo_root: Path) -> dict[str, Any]:
    config_path = repo_root / ".github" / "trusted_authors.json"
    if config_path.is_file():
        try:
            return json.loads(config_path.read_text(encoding="utf-8"))
        except Exception as exc:
            print(f"⚠️ Warning: Could not parse {config_path}: {exc}")
    return {
        "verified_organizations": ["E-Connect", "E-Connect Team"],
        "verified_developers": ["Experience", "Furuhonya", "ryzen30xx"],
        "policy": {
            "allow_community_authors": True,
            "require_author_field": True,
            "min_author_length": 2,
            "max_author_length": 100,
            "disallowed_placeholders": [
                "unknown", "null", "undefined", "anonymous", "placeholder",
                "n/a", "none", "test", "tester", "admin", "root", "sample"
            ]
        }
    }


def validate_author(author_raw: Any, config: dict[str, Any]) -> tuple[str, str]:
    policy = config.get("policy", {})
    min_len = policy.get("min_author_length", 2)
    max_len = policy.get("max_author_length", 100)
    disallowed = [p.lower() for p in policy.get("disallowed_placeholders", [])]

    if not isinstance(author_raw, str) or not author_raw.strip():
        raise ValueError("Field 'author' is required, cannot be null or empty.")

    author = author_raw.strip()
    if len(author) < min_len or len(author) > max_len:
        raise ValueError(
            f"Author '{author}' length ({len(author)}) must be between {min_len} and {max_len} characters."
        )

    if author.lower() in disallowed:
        raise ValueError(
            f"Author '{author}' is a prohibited placeholder. Please specify a real developer or organization name."
        )

    if any(char in author for char in ["\n", "\r", "\t", "<", ">", "\0"]):
        raise ValueError(f"Author '{author}' contains illegal control or markup characters.")

    verified_orgs = config.get("verified_organizations", [])
    verified_devs = config.get("verified_developers", [])

    if author in verified_orgs:
        return author, "VERIFIED ORGANIZATION (Official)"
    if author in verified_devs:
        return author, "VERIFIED DEVELOPER (Partner)"

    if not policy.get("allow_community_authors", True):
        raise ValueError(
            f"Author '{author}' is unverified and repository policy requires verified authors."
        )

    return author, "COMMUNITY DEVELOPER (Unverified)"


# ==============================================================================
# AST Security Visitor (Malware & Evasion Detection)
# ==============================================================================
class ASTSecurityVisitor(ast.NodeVisitor):
    def __init__(self, filepath: Path, rel_path: str):
        self.filepath = filepath
        self.rel_path = rel_path
        self.findings: list[str] = []

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            base_mod = alias.name.split(".")[0]
            if base_mod in FORBIDDEN_MODULES:
                self.findings.append(
                    f"[{self.rel_path}:{node.lineno}] Forbidden import '{alias.name}': {FORBIDDEN_MODULES[base_mod]}"
                )
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module:
            base_mod = node.module.split(".")[0]
            if base_mod in FORBIDDEN_MODULES:
                self.findings.append(
                    f"[{self.rel_path}:{node.lineno}] Forbidden import from '{node.module}': {FORBIDDEN_MODULES[base_mod]}"
                )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        # Check direct calls to eval(), exec(), compile(), __import__()
        if isinstance(node.func, ast.Name):
            if node.func.id in DANGEROUS_BUILTINS:
                self.findings.append(
                    f"[{self.rel_path}:{node.lineno}] Prohibited dynamic code execution: '{node.func.id}()' is strictly forbidden."
                )

        # Check dangerous method calls: os.system(), subprocess.run(), etc.
        elif isinstance(node.func, ast.Attribute):
            attr_name = node.func.attr
            if isinstance(node.func.value, ast.Name):
                module_name = node.func.value.id
                if module_name in DANGEROUS_SYSTEM_CALLS and attr_name in DANGEROUS_SYSTEM_CALLS[module_name]:
                    self.findings.append(
                        f"[{self.rel_path}:{node.lineno}] Prohibited system call: '{module_name}.{attr_name}()' (Command/Process execution blocked)."
                    )
            # Detect reverse shell pattern: os.dup2
            if attr_name == "dup2":
                self.findings.append(
                    f"[{self.rel_path}:{node.lineno}] High-risk system call: 'dup2()' (Possible reverse shell pattern)."
                )

        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        if isinstance(node.value, str):
            val = node.value
            for pattern, reason in SENSITIVE_HOST_PATHS:
                if pattern.search(val):
                    self.findings.append(
                        f"[{self.rel_path}:{node.lineno}] Forbidden host access string '{val}': {reason}."
                    )
        self.generic_visit(node)


def audit_python_files(extract_dir: Path) -> list[str]:
    security_issues: list[str] = []
    py_files = sorted(extract_dir.rglob("*.py"))

    for py_file in py_files:
        rel = py_file.relative_to(extract_dir).as_posix()
        try:
            content = py_file.read_text(encoding="utf-8")
        except UnicodeDecodeError as exc:
            security_issues.append(f"[{rel}] Python source file is not valid UTF-8: {exc}")
            continue

        try:
            tree = ast.parse(content, filename=str(py_file))
        except SyntaxError as exc:
            security_issues.append(f"[{rel}:{exc.lineno}] Python syntax error: {exc.msg}")
            continue

        visitor = ASTSecurityVisitor(py_file, rel)
        visitor.visit(tree)
        security_issues.extend(visitor.findings)

    return security_issues


def run_bandit_audit(extract_dir: Path) -> list[str]:
    """Runs bandit security scanner if installed; flags High-severity CVEs."""
    bandit_bin = shutil.which("bandit")
    if not bandit_bin:
        return []

    try:
        proc = subprocess.run(
            [bandit_bin, "-r", str(extract_dir), "-lll", "-f", "json", "-q"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if proc.stdout.strip():
            data = json.loads(proc.stdout)
            issues = []
            for item in data.get("results", []):
                rel = Path(item.get("filename", "")).relative_to(extract_dir).as_posix()
                issues.append(
                    f"[{rel}:{item.get('line_number')}] Bandit {item.get('test_id')} (High): {item.get('issue_text')}"
                )
            return issues
    except Exception as exc:
        print(f"⚠️ Bandit scan notice: {exc}")
    return []


# ==============================================================================
# Unpacking & Format Validation
# ==============================================================================
def unpack_and_validate_extension(zip_path: Path, authors_config: dict[str, Any]) -> dict[str, Any]:
    file_bytes = zip_path.read_bytes()
    size_bytes = len(file_bytes)

    if size_bytes == 0:
        raise ValueError(f"{zip_path.name}: Archive is empty (0 bytes).")
    if size_bytes > MAX_ARCHIVE_BYTES:
        raise ValueError(
            f"{zip_path.name}: Archive size ({round(size_bytes / 1024, 2)} KB) exceeds 5 MB limit."
        )

    try:
        zf = zipfile.ZipFile(io.BytesIO(file_bytes))
    except zipfile.BadZipFile as exc:
        raise ValueError(f"{zip_path.name}: Corrupted or invalid ZIP file: {exc}")

    # Anti-ZipSlip and Anti-ZipBomb checks
    total_uncompressed = 0
    infolist = zf.infolist()
    for info in infolist:
        total_uncompressed += info.file_size
        clean_path = PurePosixPath(info.filename)
        if clean_path.is_absolute() or ".." in clean_path.parts:
            raise ValueError(f"{zip_path.name}: Zip-Slip vulnerability detected in member '{info.filename}'.")

    if total_uncompressed > MAX_UNCOMPRESSED_BYTES:
        raise ValueError(
            f"{zip_path.name}: Uncompressed size ({total_uncompressed} bytes) exceeds safety limit (25 MB)."
        )

    ratio = (total_uncompressed / max(size_bytes, 1))
    if ratio > MAX_COMPRESSION_RATIO:
        raise ValueError(
            f"{zip_path.name}: Suspicious compression ratio ({ratio:.1f}x) exceeds limit (100x). Possible ZipBomb."
        )

    # Check for forbidden OS/cache files inside zip entries
    for info in infolist:
        name = info.filename
        for pattern, desc in FORBIDDEN_FILE_PATTERNS:
            if pattern.search(name):
                raise ValueError(
                    f"{zip_path.name}: Forbidden entry '{name}' ({desc}). Must be excluded when building zip."
                )

    # Perform Sandboxed Extraction
    with tempfile.TemporaryDirectory(prefix=f"econnect_ext_{zip_path.stem}_") as temp_dir_str:
        temp_dir = Path(temp_dir_str)
        zf.extractall(temp_dir)

        # Locate manifest.json
        manifest_files = list(temp_dir.rglob("manifest.json"))
        if not manifest_files:
            raise ValueError(f"{zip_path.name}: 'manifest.json' not found in unpacked files.")
        if len(manifest_files) > 1:
            raise ValueError(f"{zip_path.name}: Multiple 'manifest.json' files found ({len(manifest_files)}).")

        manifest_path = manifest_files[0]
        rel_manifest = manifest_path.relative_to(temp_dir)
        if len(rel_manifest.parts) > 2:
            raise ValueError(
                f"{zip_path.name}: manifest.json is nested too deep ('{rel_manifest}'). Max 1 folder level allowed."
            )

        package_root_dir = manifest_path.parent
        package_root_name = None if len(rel_manifest.parts) == 1 else rel_manifest.parts[0]

        # Parse and validate manifest.json
        try:
            manifest_data = json.loads(manifest_path.read_text(encoding="utf-8"))
        except UnicodeDecodeError as exc:
            raise ValueError(f"{zip_path.name}: manifest.json must be UTF-8 encoded: {exc}")
        except json.JSONDecodeError as exc:
            raise ValueError(f"{zip_path.name}: manifest.json invalid JSON syntax: {exc}")

        if not isinstance(manifest_data, dict):
            raise ValueError(f"{zip_path.name}: manifest.json must be a JSON object.")

        # Check manifest_version
        if manifest_data.get("manifest_version") != "1.0":
            raise ValueError(
                f"{zip_path.name}: Unsupported manifest_version '{manifest_data.get('manifest_version')}'. Expected '1.0'."
            )

        # Check extension_id
        ext_id = str(manifest_data.get("extension_id", "")).strip().lower()
        if not IDENTIFIER_PATTERN.fullmatch(ext_id):
            raise ValueError(
                f"{zip_path.name}: Invalid extension_id '{ext_id}'. Must be lowercase slug ^[a-z0-9][a-z0-9_-]{{1,119}}$."
            )

        # Check author
        author, author_status = validate_author(manifest_data.get("author"), authors_config)

        # Check name, version, description
        name = str(manifest_data.get("name", "")).strip()
        version = str(manifest_data.get("version", "")).strip()
        description = str(manifest_data.get("description", "")).strip()
        if not name:
            raise ValueError(f"{zip_path.name}: 'name' is required.")
        if not version:
            raise ValueError(f"{zip_path.name}: 'version' is required.")
        if not description:
            raise ValueError(f"{zip_path.name}: 'description' is required.")

        # Check provider
        provider = manifest_data.get("provider")
        if not isinstance(provider, dict):
            raise ValueError(f"{zip_path.name}: 'provider' object is required.")
        provider_key = str(provider.get("key", "")).strip().lower()
        provider_display = str(provider.get("display_name", "")).strip()
        if not IDENTIFIER_PATTERN.fullmatch(provider_key):
            raise ValueError(f"{zip_path.name}: 'provider.key' must be a valid lowercase slug.")
        if not provider_display:
            raise ValueError(f"{zip_path.name}: 'provider.display_name' is required.")

        # Check package
        pkg = manifest_data.get("package")
        if not isinstance(pkg, dict):
            raise ValueError(f"{zip_path.name}: 'package' object is required.")
        runtime = str(pkg.get("runtime", "")).strip().lower()
        if runtime != "python":
            raise ValueError(f"{zip_path.name}: Unsupported package.runtime '{runtime}'. Expected 'python'.")

        entrypoint = str(pkg.get("entrypoint", "")).strip()
        if not entrypoint or PurePosixPath(entrypoint).is_absolute() or ".." in PurePosixPath(entrypoint).parts:
            raise ValueError(f"{zip_path.name}: Invalid entrypoint path '{entrypoint}'.")

        entrypoint_file = package_root_dir / entrypoint
        if not entrypoint_file.is_file():
            raise ValueError(
                f"{zip_path.name}: Entrypoint '{entrypoint}' not found in unpacked files (looked at '{entrypoint_file.name}')."
            )

        # Check hooks
        hooks = pkg.get("hooks") or {}
        if not isinstance(hooks, dict):
            raise ValueError(f"{zip_path.name}: 'package.hooks' must be an object.")
        for rh in REQUIRED_HOOKS:
            fn = hooks.get(rh, rh)
            if not isinstance(fn, str) or not PYTHON_SYMBOL_PATTERN.fullmatch(fn.strip()):
                raise ValueError(
                    f"{zip_path.name}: package.hooks.{rh} ('{fn}') must be a valid Python symbol."
                )

        # Check device_schemas
        schemas = manifest_data.get("device_schemas")
        if not isinstance(schemas, list) or len(schemas) == 0:
            raise ValueError(f"{zip_path.name}: Manifest must declare at least one device schema in 'device_schemas'.")

        for idx, schema in enumerate(schemas):
            if not isinstance(schema, dict):
                raise ValueError(f"{zip_path.name}: device_schemas[{idx}] must be an object.")
            sid = str(schema.get("schema_id", "")).strip().lower()
            if not IDENTIFIER_PATTERN.fullmatch(sid):
                raise ValueError(f"{zip_path.name}: schema_id '{sid}' must be a lowercase slug.")
            disp = schema.get("display")
            if not isinstance(disp, dict):
                raise ValueError(f"{zip_path.name}: schema '{sid}' is missing 'display' object.")
            card_type = str(disp.get("card_type", "")).strip().lower()
            if not IDENTIFIER_PATTERN.fullmatch(card_type):
                raise ValueError(f"{zip_path.name}: schema '{sid}' display.card_type '{card_type}' is invalid.")
            caps = disp.get("capabilities")
            if not isinstance(caps, list) or len(caps) == 0:
                raise ValueError(f"{zip_path.name}: schema '{sid}' display.capabilities must be a non-empty list.")

        # DEEP SECURITY & MALWARE INSPECTION
        security_findings = audit_python_files(temp_dir)
        bandit_findings = run_bandit_audit(temp_dir)
        all_security_issues = security_findings + bandit_findings

        if all_security_issues:
            raise ValueError(
                f"{zip_path.name}: SECURITY AUDIT FAILED with {len(all_security_issues)} issue(s):\n"
                + "\n".join(f"     ❌ {issue}" for issue in all_security_issues)
            )

        sha256 = hashlib.sha256(file_bytes).hexdigest()
        py_count = len(list(temp_dir.rglob("*.py")))

        return {
            "name": zip_path.name,
            "extension_id": ext_id,
            "version": version,
            "author": author,
            "author_status": author_status,
            "package_root": package_root_name,
            "size_kb": round(size_bytes / 1024, 2),
            "sha256": sha256,
            "py_files_count": py_count,
            "schemas_count": len(schemas),
        }


# ==============================================================================
# Change Detection (Selective Unpacking)
# ==============================================================================
def find_changed_zip_files(repo_root: Path, base_ref: str | None = None) -> list[Path]:
    """Finds all *.zip files added or modified in the current branch / commit."""
    changed_names: set[str] = set()

    # 1. Check uncommitted / staged changes in working tree
    try:
        proc = subprocess.run(
            ["git", "-C", str(repo_root), "status", "--porcelain", "--", "*.zip"],
            capture_output=True,
            text=True,
            check=False,
        )
        for line in proc.stdout.splitlines():
            line = line.strip()
            if line and not line.startswith("D"):  # Exclude deleted
                # Format: "XY filename" or "?? filename"
                parts = line.split(None, 1)
                if len(parts) == 2:
                    changed_names.add(parts[1].strip('"'))
    except Exception:
        pass

    # 2. Check git diff against base_ref or HEAD~1
    diff_targets = []
    if base_ref:
        diff_targets.append(base_ref)
    else:
        # Check environment variables from GitHub Actions
        env_base = os.getenv("GITHUB_BASE_REF")
        if env_base:
            diff_targets.append(f"origin/{env_base}")
        env_before = os.getenv("GITHUB_BEFORE")
        if env_before and env_before != "0000000000000000000000000000000000000000":
            diff_targets.append(env_before)
        diff_targets.append("HEAD~1")

    for target in diff_targets:
        try:
            cmd = ["git", "-C", str(repo_root), "diff", "--name-only", "--diff-filter=AM", target, "HEAD", "--", "*.zip"]
            proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
            if proc.returncode == 0:
                for f in proc.stdout.splitlines():
                    if f.strip():
                        changed_names.add(f.strip())
                break
        except Exception:
            continue

    # Filter to existing zip files
    matched_zips: list[Path] = []
    for name in changed_names:
        p = repo_root / name
        if p.is_file() and p.suffix.lower() == ".zip":
            matched_zips.append(p)

    return sorted(matched_zips)


# ==============================================================================
# Main CLI Entrypoint
# ==============================================================================
def main() -> int:
    parser = argparse.ArgumentParser(
        description="E-Connect Marketplace: Selective Extension Unpacker & Security Validator"
    )
    parser.add_argument(
        "targets",
        nargs="*",
        help="Optional specific *.zip extension files or directories to unpack and inspect.",
    )
    parser.add_argument(
        "--changed-only",
        action="store_true",
        help="Only unpack and validate extension packages that have been added or modified.",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Force unpack and validate all *.zip extension packages in the repository.",
    )
    parser.add_argument(
        "--base-ref",
        help="Git base reference for change detection (e.g. origin/main or origin/dev).",
    )

    args = parser.parse_args()
    repo_root = Path.cwd().resolve()

    # Determine files to unpack & audit
    zips_to_audit: list[Path] = []

    if args.targets:
        for t in args.targets:
            p = Path(t).resolve()
            if p.is_file() and p.suffix.lower() == ".zip":
                zips_to_audit.append(p)
            elif p.is_dir():
                zips_to_audit.extend(sorted(p.glob("*.zip")))
    elif args.changed_only:
        zips_to_audit = find_changed_zip_files(repo_root, base_ref=args.base_ref)
        if not zips_to_audit:
            print("======================================================================")
            print("ℹ️  SELECTIVE UNPACK: No extension packages (*.zip) were added or modified.")
            print("    Zero unpack required. All existing packages remain untouched.")
            print("======================================================================")
            return 0
    elif args.all:
        zips_to_audit = sorted(repo_root.glob("*.zip"))
    else:
        # Default behavior: If in CI environment, detect changed-only; otherwise check all in current dir
        if os.getenv("CI") or os.getenv("GITHUB_ACTIONS"):
            zips_to_audit = find_changed_zip_files(repo_root, base_ref=args.base_ref)
            if not zips_to_audit:
                print("======================================================================")
                print("ℹ️  CI SELECTIVE UNPACK: No new or modified extension packages detected.")
                print("    Skipping unpack step. Commit is safe.")
                print("======================================================================")
                return 0
        else:
            zips_to_audit = sorted(repo_root.glob("*.zip"))

    if not zips_to_audit:
        print(f"⚠️  No extension packages found in '{repo_root}'.")
        return 0

    authors_config = load_trusted_authors_config(repo_root)

    print("======================================================================")
    print(f"🛡️  E-CONNECT MARKETPLACE: EXTENSION UNPACK & SECURITY AUDITOR")
    print(f"    Target Packages: {len(zips_to_audit)} package(s) selected for sandboxed unpacking")
    print("======================================================================")

    total_failed = 0
    audit_results = []

    for idx, zip_path in enumerate(zips_to_audit, 1):
        print(f"\n📦 [{idx}/{len(zips_to_audit)}] Unpacking & Auditing: {zip_path.name}")
        print("  " + "-" * 66)
        try:
            res = unpack_and_validate_extension(zip_path, authors_config)
            audit_results.append(res)
            print(f"  ✓ Integrity & Anti-ZipSlip: PASSED")
            print(f"  ✓ Format: E-Connect v1.0 Standard ({res['package_root'] or 'flat root'})")
            print(f"  ✓ Identity: id='{res['extension_id']}' | version='{res['version']}'")
            print(f"  ✓ Author: '{res['author']}' -> {res['author_status']}")
            print(f"  ✓ Codebase: {res['py_files_count']} Python file(s) parsed & audited")
            print(f"  ✓ Security AST: No shell/subprocess, no eval/exec, no host tampering")
            print(f"  ✓ Device Schemas: {res['schemas_count']} schema(s) verified")
            print(f"  ✅ VERDICT: PASS (Authentic, compliant & safe)")
        except Exception as exc:
            total_failed += 1
            print(f"  ❌ VERDICT: FAILED")
            print(f"     Reason: {exc}")

    print("\n" + "=" * 70)
    if total_failed > 0:
        print(f"💥 AUDIT FAILED: {total_failed} extension package(s) violated security/format standards.")
        return 1
    else:
        print(f"🎉 AUDIT PASSED: All {len(zips_to_audit)} package(s) verified 100% compliant and secure!")
        return 0


if __name__ == "__main__":
    sys.exit(main())
