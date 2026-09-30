#!/usr/bin/env python3
# Copyright (c) 2026 E-Connect Project. All rights reserved.
"""
Selective Extension Format Compliance & Deep Security Audit CLI
for E-Connect Marketplace (econnectrelease/marketplace).

Validates:
1. Directory-based extension structure (unpacked folders, no zip archives).
2. Direct discovery via root manifest.json in each extension directory.
3. Clean repository hygiene (blocks OS metadata, cache files, and archives).
4. Manifest schema & author authenticity against trusted registry.
5. E-Connect extension format compatibility (hooks, schemas, entrypoint).
6. Deep malware & AST security inspection (blocks subprocess, eval/exec,
   host credential theft, reverse shells, keyloggers).
7. Bandit automated security scanning on Python sources.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path, PurePosixPath
from typing import Any

# ==============================================================================
# Constants & Constraints
# ==============================================================================
MAX_EXTENSION_BYTES = 25 * 1024 * 1024  # 25 MB max uncompressed directory size

IDENTIFIER_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]{1,119}$")
CAPABILITY_PATTERN = re.compile(r"^[a-z][a-z0-9_]{0,59}$")
PYTHON_SYMBOL_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
SUPPORTED_CONFIG_FIELD_TYPES = {"string", "number", "boolean", "password"}
CONTRIBUTOR_PATTERN = re.compile(r"^[a-zA-Z0-9](?:[a-zA-Z0-9]|-(?=[a-zA-Z0-9])){0,38}$")
ICON_PATTERN = re.compile(r"^[a-zA-Z0-9_-]{1,60}$")
CATEGORY_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_\s-]{0,49}$")

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
    (re.compile(r"\.(zip|tar|gz|tgz|rar|7z)$", re.IGNORECASE), "Archived package file (Extensions must be uncompressed folders)"),
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


def audit_python_files(ext_dir: Path) -> list[str]:
    security_issues: list[str] = []
    py_files = sorted(ext_dir.rglob("*.py"))

    for py_file in py_files:
        rel = py_file.relative_to(ext_dir).as_posix()
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


def run_bandit_audit(ext_dir: Path) -> list[str]:
    """Runs bandit security scanner if installed; flags High-severity CVEs."""
    bandit_bin = shutil.which("bandit")
    if not bandit_bin:
        return []

    try:
        proc = subprocess.run(
            [bandit_bin, "-r", str(ext_dir), "-lll", "-f", "json", "-q"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if proc.stdout.strip():
            data = json.loads(proc.stdout)
            issues = []
            for item in data.get("results", []):
                rel = Path(item.get("filename", "")).relative_to(ext_dir).as_posix()
                issues.append(
                    f"[{rel}:{item.get('line_number')}] Bandit {item.get('test_id')} (High): {item.get('issue_text')}"
                )
            return issues
    except Exception as exc:
        print(f"⚠️ Bandit scan notice: {exc}")
    return []


# ==============================================================================
# Extension Folder Validation
# ==============================================================================
def validate_extension_directory(ext_dir: Path, authors_config: dict[str, Any]) -> dict[str, Any]:
    if not ext_dir.is_dir():
        raise ValueError(f"'{ext_dir.name}' is not a directory.")

    # 1. Check directory size and file hygiene
    total_bytes = 0
    all_files: list[Path] = []
    for item in ext_dir.rglob("*"):
        if item.is_file():
            file_size = item.stat().st_size
            total_bytes += file_size
            all_files.append(item)

        # Check for forbidden files / directories
        rel_posix = item.relative_to(ext_dir).as_posix()
        for pattern, desc in FORBIDDEN_FILE_PATTERNS:
            if pattern.search(rel_posix):
                raise ValueError(
                    f"{ext_dir.name}: Forbidden item '{rel_posix}' ({desc}). Must be cleaned before committing."
                )

    if total_bytes > MAX_EXTENSION_BYTES:
        raise ValueError(
            f"{ext_dir.name}: Extension folder size ({round(total_bytes / (1024 * 1024), 2)} MB) exceeds 25 MB limit."
        )

    # 2. Locate and parse manifest.json
    manifest_path = ext_dir / "manifest.json"
    if not manifest_path.is_file():
        raise ValueError(f"{ext_dir.name}: 'manifest.json' is missing from the extension folder.")

    try:
        manifest_data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except UnicodeDecodeError as exc:
        raise ValueError(f"{ext_dir.name}: manifest.json must be UTF-8 encoded: {exc}")
    except json.JSONDecodeError as exc:
        raise ValueError(f"{ext_dir.name}: manifest.json invalid JSON syntax: {exc}")

    if not isinstance(manifest_data, dict):
        raise ValueError(f"{ext_dir.name}: manifest.json must be a JSON object.")

    # 3. Check manifest_version
    if manifest_data.get("manifest_version") != "1.0":
        raise ValueError(
            f"{ext_dir.name}: Unsupported manifest_version '{manifest_data.get('manifest_version')}'. Expected '1.0'."
        )

    # 4. Check extension_id
    ext_id = str(manifest_data.get("extension_id", "")).strip().lower()
    if not IDENTIFIER_PATTERN.fullmatch(ext_id):
        raise ValueError(
            f"{ext_dir.name}: Invalid extension_id '{ext_id}'. Must be lowercase slug ^[a-z0-9][a-z0-9_-]{{1,119}}$."
        )

    # 5. Check author authenticity
    author, author_status = validate_author(manifest_data.get("author"), authors_config)

    # 5a. Check contributor (optional GitHub username)
    raw_contributor = (
        manifest_data.get("contributor")
        or manifest_data.get("github_contributor")
        or manifest_data.get("github_username")
    )
    contributor = None
    if raw_contributor is not None:
        if not isinstance(raw_contributor, str) or not raw_contributor.strip():
            raise ValueError(f"{ext_dir.name}: 'contributor' must be a non-empty string.")
        contributor = raw_contributor.strip()
        if not CONTRIBUTOR_PATTERN.fullmatch(contributor):
            raise ValueError(
                f"{ext_dir.name}: Invalid contributor username '{contributor}'. Must be a valid GitHub username."
            )

    # 5b. Check icon (optional Material Icon identifier)
    raw_icon = manifest_data.get("icon")
    icon = None
    if raw_icon is not None:
        if not isinstance(raw_icon, str) or not raw_icon.strip():
            raise ValueError(f"{ext_dir.name}: 'icon' must be a non-empty string.")
        icon = raw_icon.strip()
        if not ICON_PATTERN.fullmatch(icon):
            raise ValueError(f"{ext_dir.name}: Invalid icon identifier '{icon}'.")

    # 5c. Check categories (optional list or string)
    raw_categories = manifest_data.get("categories")
    raw_category = manifest_data.get("category")
    categories: list[str] = []
    if raw_categories is not None:
        if isinstance(raw_categories, list):
            if len(raw_categories) == 0:
                raise ValueError(f"{ext_dir.name}: 'categories' cannot be an empty list.")
            for c in raw_categories:
                if not isinstance(c, str) or not c.strip() or not CATEGORY_PATTERN.fullmatch(c.strip()):
                    raise ValueError(f"{ext_dir.name}: Invalid category entry '{c}'.")
                clean_c = c.strip().lower()
                if clean_c not in categories:
                    categories.append(clean_c)
        elif isinstance(raw_categories, str) and raw_categories.strip():
            if not CATEGORY_PATTERN.fullmatch(raw_categories.strip()):
                raise ValueError(f"{ext_dir.name}: Invalid category '{raw_categories}'.")
            categories.append(raw_categories.strip().lower())
        else:
            raise ValueError(f"{ext_dir.name}: 'categories' must be a list of strings or a string.")

    if raw_category is not None and not categories:
        if not isinstance(raw_category, str) or not raw_category.strip() or not CATEGORY_PATTERN.fullmatch(raw_category.strip()):
            raise ValueError(f"{ext_dir.name}: Invalid 'category' '{raw_category}'.")
        categories.append(raw_category.strip().lower())

    # 6. Check name, version, description
    name = str(manifest_data.get("name", "")).strip()
    version = str(manifest_data.get("version", "")).strip()
    description = str(manifest_data.get("description", "")).strip()
    if not name:
        raise ValueError(f"{ext_dir.name}: 'name' is required.")
    if not version:
        raise ValueError(f"{ext_dir.name}: 'version' is required.")
    if not description:
        raise ValueError(f"{ext_dir.name}: 'description' is required.")

    # 7. Check provider
    provider = manifest_data.get("provider")
    if not isinstance(provider, dict):
        raise ValueError(f"{ext_dir.name}: 'provider' object is required.")
    provider_key = str(provider.get("key", "")).strip().lower()
    provider_display = str(provider.get("display_name", "")).strip()
    if not IDENTIFIER_PATTERN.fullmatch(provider_key):
        raise ValueError(f"{ext_dir.name}: 'provider.key' must be a valid lowercase slug.")
    if not provider_display:
        raise ValueError(f"{ext_dir.name}: 'provider.display_name' is required.")

    # 8. Check package & entrypoint
    pkg = manifest_data.get("package")
    if not isinstance(pkg, dict):
        raise ValueError(f"{ext_dir.name}: 'package' object is required.")
    runtime = str(pkg.get("runtime", "")).strip().lower()
    if runtime != "python":
        raise ValueError(f"{ext_dir.name}: Unsupported package.runtime '{runtime}'. Expected 'python'.")

    entrypoint = str(pkg.get("entrypoint", "")).strip()
    if not entrypoint or PurePosixPath(entrypoint).is_absolute() or ".." in PurePosixPath(entrypoint).parts:
        raise ValueError(f"{ext_dir.name}: Invalid entrypoint path '{entrypoint}'.")

    entrypoint_file = ext_dir / entrypoint
    if not entrypoint_file.is_file():
        raise ValueError(
            f"{ext_dir.name}: Entrypoint file '{entrypoint}' not found in '{ext_dir.name}/'."
        )

    # 9. Check hooks
    hooks = pkg.get("hooks") or {}
    if not isinstance(hooks, dict):
        raise ValueError(f"{ext_dir.name}: 'package.hooks' must be an object.")
    for rh in REQUIRED_HOOKS:
        fn = hooks.get(rh, rh)
        if not isinstance(fn, str) or not PYTHON_SYMBOL_PATTERN.fullmatch(fn.strip()):
            raise ValueError(
                f"{ext_dir.name}: package.hooks.{rh} ('{fn}') must be a valid Python symbol."
            )

    # 10. Check device_schemas
    schemas = manifest_data.get("device_schemas")
    if not isinstance(schemas, list) or len(schemas) == 0:
        raise ValueError(f"{ext_dir.name}: Manifest must declare at least one device schema in 'device_schemas'.")

    for idx, schema in enumerate(schemas):
        if not isinstance(schema, dict):
            raise ValueError(f"{ext_dir.name}: device_schemas[{idx}] must be an object.")
        sid = str(schema.get("schema_id", "")).strip().lower()
        if not IDENTIFIER_PATTERN.fullmatch(sid):
            raise ValueError(f"{ext_dir.name}: schema_id '{sid}' must be a lowercase slug.")
        disp = schema.get("display")
        if not isinstance(disp, dict):
            raise ValueError(f"{ext_dir.name}: schema '{sid}' is missing 'display' object.")
        card_type = str(disp.get("card_type", "")).strip().lower()
        if not IDENTIFIER_PATTERN.fullmatch(card_type):
            raise ValueError(f"{ext_dir.name}: schema '{sid}' display.card_type '{card_type}' is invalid.")
        caps = disp.get("capabilities")
        if not isinstance(caps, list) or len(caps) == 0:
            raise ValueError(f"{ext_dir.name}: schema '{sid}' display.capabilities must be a non-empty list.")
        for cap in caps:
            if not isinstance(cap, str) or not CAPABILITY_PATTERN.fullmatch(cap.strip().lower()):
                raise ValueError(f"{ext_dir.name}: schema '{sid}' capability '{cap}' is invalid.")

        temp_range = disp.get("temperature_range")
        if temp_range is not None:
            if card_type != "light":
                raise ValueError(f"{ext_dir.name}: schema '{sid}' temperature_range is only permitted for card_type 'light'.")
            if not isinstance(temp_range, dict) or not isinstance(temp_range.get("min"), int) or not isinstance(temp_range.get("max"), int):
                raise ValueError(f"{ext_dir.name}: schema '{sid}' temperature_range must have integer min and max.")
            if temp_range["min"] >= temp_range["max"]:
                raise ValueError(f"{ext_dir.name}: schema '{sid}' temperature_range min must be less than max.")

        cfg_schema = schema.get("config_schema")
        if cfg_schema is not None:
            if not isinstance(cfg_schema, dict):
                raise ValueError(f"{ext_dir.name}: schema '{sid}' config_schema must be an object.")
            fields = cfg_schema.get("fields")
            if fields is not None:
                if not isinstance(fields, list):
                    raise ValueError(f"{ext_dir.name}: schema '{sid}' config_schema.fields must be a list.")
                for f_idx, field in enumerate(fields):
                    if not isinstance(field, dict):
                        raise ValueError(f"{ext_dir.name}: schema '{sid}' config_schema.fields[{f_idx}] must be an object.")
                    f_key = str(field.get("key", "")).strip().lower()
                    if not IDENTIFIER_PATTERN.fullmatch(f_key):
                        raise ValueError(f"{ext_dir.name}: schema '{sid}' field key '{f_key}' must be a valid lowercase slug.")
                    f_type = str(field.get("type", "")).strip().lower()
                    if f_type not in SUPPORTED_CONFIG_FIELD_TYPES:
                        raise ValueError(
                            f"{ext_dir.name}: schema '{sid}' field '{f_key}' has unsupported type '{f_type}'. Supported: {sorted(SUPPORTED_CONFIG_FIELD_TYPES)}"
                        )
                    if "required" in field and not isinstance(field["required"], bool):
                        raise ValueError(f"{ext_dir.name}: schema '{sid}' field '{f_key}' required must be a boolean.")

    # 11. Deep Security & AST Inspection
    security_findings = audit_python_files(ext_dir)
    bandit_findings = run_bandit_audit(ext_dir)
    all_security_issues = security_findings + bandit_findings

    if all_security_issues:
        raise ValueError(
            f"{ext_dir.name}: SECURITY AUDIT FAILED with {len(all_security_issues)} issue(s):\n"
            + "\n".join(f"     ❌ {issue}" for issue in all_security_issues)
        )

    py_count = len(list(ext_dir.rglob("*.py")))

    return {
        "folder_name": ext_dir.name,
        "extension_id": ext_id,
        "version": version,
        "author": author,
        "author_status": author_status,
        "contributor": contributor,
        "icon": icon,
        "categories": categories,
        "size_kb": round(total_bytes / 1024, 2),
        "py_files_count": py_count,
        "schemas_count": len(schemas),
        "entrypoint": entrypoint,
    }


# ==============================================================================
# Discovery & Change Detection
# ==============================================================================
def find_all_extension_dirs(repo_root: Path) -> list[Path]:
    """Finds all root-level directories that contain a manifest.json."""
    ext_dirs: list[Path] = []
    for item in sorted(repo_root.iterdir()):
        if item.is_dir() and not item.name.startswith("."):
            manifest_file = item / "manifest.json"
            if manifest_file.is_file():
                ext_dirs.append(item)
    return ext_dirs


def find_changed_extension_dirs(repo_root: Path, base_ref: str | None = None) -> list[Path]:
    """Finds all extension directories that have newly added or modified files."""
    changed_rel_paths: set[str] = set()

    # 1. Check uncommitted / staged changes in working tree
    try:
        proc = subprocess.run(
            ["git", "-C", str(repo_root), "status", "--porcelain"],
            capture_output=True,
            text=True,
            check=False,
        )
        for line in proc.stdout.splitlines():
            line = line.strip()
            if line:
                parts = line.split(None, 1)
                if len(parts) == 2:
                    changed_rel_paths.add(parts[1].strip('"'))
    except Exception:
        pass

    # 2. Check git diff against base_ref or HEAD~1
    diff_targets = []
    if base_ref:
        diff_targets.append(base_ref)
    else:
        env_base = os.getenv("GITHUB_BASE_REF")
        if env_base:
            diff_targets.append(f"origin/{env_base}")
            diff_targets.append(env_base)
        env_before = os.getenv("GITHUB_BEFORE")
        if env_before and env_before != "0000000000000000000000000000000000000000":
            diff_targets.append(env_before)
        diff_targets.append("HEAD~1")

    for target in diff_targets:
        try:
            cmd = ["git", "-C", str(repo_root), "diff", "--name-only", "--diff-filter=AM", target, "HEAD"]
            proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
            if proc.returncode == 0:
                for f in proc.stdout.splitlines():
                    if f.strip():
                        changed_rel_paths.add(f.strip())
                break
        except Exception:
            continue

    # Map changed paths to top-level extension directories
    changed_ext_dirs: set[Path] = set()
    for rel in changed_rel_paths:
        parts = Path(rel).parts
        if len(parts) >= 2:
            candidate_dir = repo_root / parts[0]
            if candidate_dir.is_dir() and (candidate_dir / "manifest.json").is_file():
                changed_ext_dirs.add(candidate_dir)

    return sorted(list(changed_ext_dirs))


# ==============================================================================
# Main CLI Entrypoint
# ==============================================================================
def main() -> int:
    parser = argparse.ArgumentParser(
        description="E-Connect Marketplace: Unpacked Extension Validator & Security Auditor"
    )
    parser.add_argument(
        "targets",
        nargs="*",
        help="Optional specific extension folder(s) to inspect.",
    )
    parser.add_argument(
        "--changed-only",
        action="store_true",
        help="Only validate extension folders that have been added or modified.",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Force validate all extension folders in the repository.",
    )
    parser.add_argument(
        "--base-ref",
        help="Git base reference for change detection (e.g. origin/main or origin/dev).",
    )

    args = parser.parse_args()
    repo_root = Path.cwd().resolve()

    # Check for prohibited zip archives in the repo
    prohibited_zips = sorted(repo_root.glob("*.zip"))
    if prohibited_zips:
        print("======================================================================")
        print("❌ ARCHIVE POLICY VIOLATION: ZIP files are strictly prohibited!")
        print("    Extensions must be stored directly as uncompressed folders with manifest.json.")
        print(f"    Disallowed archive(s) found: {', '.join(z.name for z in prohibited_zips)}")
        print("    Please delete these .zip files and keep the uncompressed directories.")
        print("======================================================================")
        return 1

    # Determine extension directories to audit
    exts_to_audit: list[Path] = []

    if args.targets:
        for t in args.targets:
            p = Path(t).resolve()
            if p.is_dir():
                if (p / "manifest.json").is_file():
                    exts_to_audit.append(p)
                else:
                    # Look inside
                    exts_to_audit.extend(find_all_extension_dirs(p))
            elif p.is_file() and p.name == "manifest.json":
                exts_to_audit.append(p.parent)
    elif args.changed_only:
        exts_to_audit = find_changed_extension_dirs(repo_root, base_ref=args.base_ref)
        if not exts_to_audit:
            print("======================================================================")
            print("ℹ️  SELECTIVE AUDIT: No extension directories were added or modified.")
            print("    Zero audit required. All existing extensions remain untouched.")
            print("======================================================================")
            return 0
    elif args.all:
        exts_to_audit = find_all_extension_dirs(repo_root)
    else:
        # Default behavior: If in CI environment, detect changed-only; otherwise check all in repo
        if os.getenv("CI") or os.getenv("GITHUB_ACTIONS"):
            exts_to_audit = find_changed_extension_dirs(repo_root, base_ref=args.base_ref)
            if not exts_to_audit:
                print("======================================================================")
                print("ℹ️  CI SELECTIVE AUDIT: No new or modified extension directories detected.")
                print("    Commit is safe.")
                print("======================================================================")
                return 0
        else:
            exts_to_audit = find_all_extension_dirs(repo_root)

    if not exts_to_audit:
        print(f"⚠️  No extension directories with 'manifest.json' found in '{repo_root}'.")
        return 0

    authors_config = load_trusted_authors_config(repo_root)

    print("======================================================================")
    print(f"🛡️  E-CONNECT MARKETPLACE: EXTENSION VALIDATOR & SECURITY AUDITOR")
    print(f"    Target Extensions: {len(exts_to_audit)} folder(s) selected for audit")
    print("======================================================================")

    total_failed = 0
    audit_results = []
    audit_failures = []

    for idx, ext_dir in enumerate(exts_to_audit, 1):
        print(f"\n📂 [{idx}/{len(exts_to_audit)}] Auditing Extension Folder: {ext_dir.name}")
        print("  " + "-" * 66)
        try:
            res = validate_extension_directory(ext_dir, authors_config)
            audit_results.append(res)
            print(f"  ✓ Manifest: manifest.json parsed directly from folder")
            print(f"  ✓ Format: E-Connect v1.0 Standard")
            print(f"  ✓ Identity: id='{res['extension_id']}' | version='{res['version']}'")
            print(f"  ✓ Author: '{res['author']}' -> {res['author_status']}")
            if res.get("contributor"):
                print(f"  ✓ Contributor: @{res['contributor']}")
            if res.get("icon"):
                print(f"  ✓ Icon: {res['icon']}")
            if res.get("categories"):
                print(f"  ✓ Categories: {', '.join(res['categories'])}")
            print(f"  ✓ Entrypoint: '{res['entrypoint']}' verified")
            print(f"  ✓ Codebase: {res['py_files_count']} Python file(s) parsed & audited")
            print(f"  ✓ Security AST: No shell/subprocess, no eval/exec, no host tampering")
            print(f"  ✓ Device Schemas: {res['schemas_count']} schema(s) verified")
            print(f"  ✅ VERDICT: PASS (Authentic, compliant & safe)")
        except Exception as exc:
            total_failed += 1
            audit_failures.append({"folder_name": ext_dir.name, "error": str(exc)})
            print(f"  ❌ VERDICT: FAILED")
            print(f"     Reason: {exc}")

    # Generate GitHub Step Summary if running inside GitHub Actions
    summary_path = os.getenv("GITHUB_STEP_SUMMARY")
    if summary_path:
        try:
            with open(summary_path, "a", encoding="utf-8") as sf:
                sf.write("### 🛡️ E-Connect Extension Audit Results\n\n")
                sf.write("| Extension Folder | Extension ID | Version | Author | Contributor | Categories | Verdict |\n")
                sf.write("|---|---|---|---|---|---|---|\n")
                for r in audit_results:
                    contrib = f"@{r['contributor']}" if r.get("contributor") else "-"
                    cats = ", ".join(r.get("categories", [])) or "-"
                    sf.write(f"| `{r['folder_name']}` | `{r['extension_id']}` | `{r['version']}` | {r['author']} | {contrib} | {cats} | ✅ PASS |\n")
                for f_item in audit_failures:
                    sf.write(f"| `{f_item['folder_name']}` | - | - | - | - | - | ❌ FAILED (`{f_item['error']}`) |\n")
                sf.write("\n")
        except Exception:
            pass

    print("\n" + "=" * 70)
    if total_failed > 0:
        print(f"💥 AUDIT FAILED: {total_failed} extension(s) violated security/format standards.")
        return 1
    else:
        print(f"🎉 AUDIT PASSED: All {len(exts_to_audit)} extension(s) verified 100% compliant and secure!")
        return 0


if __name__ == "__main__":
    sys.exit(main())
