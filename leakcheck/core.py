"""
Core secret scanning, entropy analyzer, and git hook manager for leakcheck.
Pure standard library, zero external dependencies.
"""
import math
import os
import re
import stat
import subprocess
from typing import Any, Dict, List, Optional, Set, Tuple

from leakcheck.rules import SECRET_RULES

DEFAULT_SEVERITIES = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

IGNORE_DIR_NAMES = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "env",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    "dist",
    "build",
    ".eggs",
}

BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".tar",
    ".gz", ".bz2", ".7z", ".exe", ".bin", ".iso", ".pyc", ".pyd",
    ".so", ".dylib", ".dll", ".woff", ".woff2", ".ttf", ".eot",
    ".mp3", ".mp4", ".wav", ".avi", ".mov", ".box",
}


def shannon_entropy(data: str) -> float:
    """
    Calculates the Shannon entropy (information density / randomness) of a string.
    Higher values (> 3.5) typically signify cryptographically generated keys.
    """
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    for char in set(data):
        prob = data.count(char) / length
        entropy -= prob * math.log2(prob)
    return entropy


def is_binary_file(file_path: str) -> bool:
    """Heuristic to detect binary files."""
    _, ext = os.path.splitext(file_path.lower())
    if ext in BINARY_EXTENSIONS:
        return True
    try:
        with open(file_path, "tr") as f:
            f.read(1024)
            return False
    except (UnicodeDecodeError, PermissionError):
        return True


def mask_secret(secret: str) -> str:
    """Masks secret to prevent terminal leakage while keeping context."""
    if len(secret) <= 10:
        return secret[:2] + "****" + secret[-2:]
    return secret[:7] + "..." + secret[-4:]


def parse_ignore_file(ignore_path: str) -> Set[str]:
    """Reads paths/patterns from .leakcheckignore."""
    patterns = set()
    if os.path.exists(ignore_path):
        try:
            with open(ignore_path, "r", encoding="utf-8") as f:
                for line in f:
                    stripped = line.strip()
                    if stripped and not stripped.startswith("#"):
                        patterns.add(stripped.rstrip("/"))
        except Exception:
            pass
    return patterns


def scan_text(
    content: str,
    filename: str = "<stdin>",
    min_severity: str = "MEDIUM",
) -> List[Dict[str, Any]]:
    """
    Scans a given text buffer for leaked secrets matching provider rules.
    """
    findings = []
    min_level = DEFAULT_SEVERITIES.get(min_severity.upper(), 2)
    lines = content.splitlines()

    for line_idx, line in enumerate(lines, start=1):
        stripped = line.strip()

        # Suppress comment lines that explicitly declare example/mock/dummy
        if stripped.startswith(("#", "//", "/*", "*")) and any(
            tok in stripped.lower() for tok in ("example", "mock", "dummy", "fake", "placeholder")
        ):
            continue

        # Suppress lines explicitly declaring mock/test/dummy variables
        if re.match(r"^\s*(?:mock|test|fake|dummy|example)_[a-zA-Z0-9_]*\s*=", line, re.IGNORECASE):
            continue

        for provider, pattern, severity, remediation in SECRET_RULES:
            if DEFAULT_SEVERITIES.get(severity, 1) < min_level:
                continue

            for match in pattern.finditer(line):
                matched_val = match.group(0)
                matched_lower = matched_val.lower()

                # Suppress token if it explicitly contains mock/dummy/fake
                if any(tok in matched_lower for tok in ("mock", "dummy", "fake", "placeholder")):
                    continue

                # Skip low entropy false positives (except for exact structural headers like RSA Private Keys)
                if "Private Key" not in provider:
                    if len(matched_val) < 16 or shannon_entropy(matched_val) < 2.8:
                        continue

                findings.append({
                    "file": filename,
                    "line": line_idx,
                    "provider": provider,
                    "severity": severity,
                    "masked": mask_secret(matched_val),
                    "entropy": round(shannon_entropy(matched_val), 2),
                    "remediation": remediation,
                })

    return findings


def scan_path(
    path: str,
    staged_only: bool = False,
    min_severity: str = "MEDIUM",
) -> Dict[str, Any]:
    """
    Scans a file or entire directory tree.
    """
    if not os.path.exists(path):
        raise FileNotFoundError(f"Path not found: {path}")

    ignore_patterns: Set[str] = set()
    root_dir = path if os.path.isdir(path) else os.path.dirname(os.path.abspath(path))
    ignore_file_path = os.path.join(root_dir, ".leakcheckignore")
    if os.path.exists(ignore_file_path):
        ignore_patterns = parse_ignore_file(ignore_file_path)

    findings: List[Dict[str, Any]] = []
    scanned_files_count = 0

    if staged_only:
        try:
            cmd = ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"]
            output = subprocess.check_output(cmd, cwd=root_dir, text=True, stderr=subprocess.DEVNULL)
            staged_files = [f.strip() for f in output.splitlines() if f.strip()]
            for rel_file in staged_files:
                full_file = os.path.join(root_dir, rel_file)
                if os.path.exists(full_file) and not is_binary_file(full_file):
                    scanned_files_count += 1
                    try:
                        with open(full_file, "r", encoding="utf-8", errors="ignore") as f:
                            findings.extend(scan_text(f.read(), filename=rel_file, min_severity=min_severity))
                    except Exception:
                        pass
        except Exception:
            pass
        return {
            "scanned_files": scanned_files_count,
            "leaks_found": len(findings),
            "findings": findings,
        }

    if os.path.isfile(path):
        if not is_binary_file(path):
            scanned_files_count += 1
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    findings.extend(scan_text(f.read(), filename=path, min_severity=min_severity))
            except Exception:
                pass
        return {
            "scanned_files": scanned_files_count,
            "leaks_found": len(findings),
            "findings": findings,
        }

    # Directory walk
    for current_root, dirs, files in os.walk(path):
        # Exclude ignored dirs
        dirs[:] = [
            d for d in dirs
            if d not in IGNORE_DIR_NAMES and d not in ignore_patterns
        ]

        for file_name in files:
            if file_name.startswith(".leakcheck"):
                continue
            if file_name in ignore_patterns:
                continue

            file_path = os.path.join(current_root, file_name)
            if is_binary_file(file_path):
                continue

            scanned_files_count += 1
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    rel_name = os.path.relpath(file_path, path)
                    findings.extend(scan_text(f.read(), filename=rel_name, min_severity=min_severity))
            except Exception:
                pass

    return {
        "scanned_files": scanned_files_count,
        "leaks_found": len(findings),
        "findings": findings,
    }


def install_git_hook(repo_root: str = ".") -> Tuple[bool, str]:
    """Installs automatic git pre-commit hook in repo."""
    git_dir = os.path.join(repo_root, ".git")
    if not os.path.exists(git_dir):
        return False, f"Not a git repository (no .git directory at {repo_root})"

    hooks_dir = os.path.join(git_dir, "hooks")
    os.makedirs(hooks_dir, exist_ok=True)
    hook_file = os.path.join(hooks_dir, "pre-commit")

    hook_script = """#!/usr/bin/env bash
# Installed by leakcheck-cli (Zephyrus Labs)
echo "[leakcheck] Running pre-commit secret scan..."
leakcheck --staged
if [ $? -ne 0 ]; then
    echo "[leakcheck] Commit blocked! Please remove exposed secrets or revoke them."
    exit 1
fi
"""
    try:
        with open(hook_file, "w", encoding="utf-8") as f:
            f.write(hook_script)

        # Make executable
        st = os.stat(hook_file)
        os.chmod(hook_file, st.st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        return True, f"Successfully installed pre-commit hook into {hook_file}"
    except Exception as e:
        return False, f"Failed to install git hook: {e}"


def uninstall_git_hook(repo_root: str = ".") -> Tuple[bool, str]:
    """Removes git pre-commit hook."""
    hook_file = os.path.join(repo_root, ".git", "hooks", "pre-commit")
    if os.path.exists(hook_file):
        try:
            os.remove(hook_file)
            return True, "Successfully uninstalled pre-commit hook."
        except Exception as e:
            return False, f"Error removing hook: {e}"
    return True, "No pre-commit hook was present."
