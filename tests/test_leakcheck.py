"""
Comprehensive test suite for leakcheck-cli.
TDD coverage: Shannon entropy analysis, secret detection rules,
false-positive suppression, git pre-commit hook installer,
file traversal, CLI exit codes, and interactive mode.
"""
import json
import os
import stat
import subprocess
import tempfile
import pytest

from leakcheck.core import (
    shannon_entropy,
    scan_text,
    scan_path,
    install_git_hook,
    uninstall_git_hook,
    DEFAULT_SEVERITIES,
)
from leakcheck.cli import main

# Dynamically construct test credentials so GitHub Push Protection doesn't false-positive on git commit
TEST_OPENAI = "sk-" + "proj-" + "9mN87zQ1vA4bC2dE8fG9hI3jK4lM5nO6pQ7rS8tU9vW0xY1z"
TEST_ANTHROPIC = "sk-" + "ant-" + "api03-abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890AA"
TEST_AWS = "AKIA" + "IOSFODNN7EXAMPLE"
TEST_GITHUB = "ghp_" + "1234567890abcdefghijklmnopqrstuvwxyzAB"
TEST_STRIPE = "sk_" + "live_" + "51AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"


# ---------------------------------------------------------------------------
# Shannon Entropy Tests
# ---------------------------------------------------------------------------

def test_shannon_entropy_calculation():
    # Empty string
    assert shannon_entropy("") == 0.0

    # Low entropy (monotonous / repeated)
    low_ent = shannon_entropy("aaaaaaaaaaaaaaaa")
    assert low_ent == 0.0

    # Medium entropy
    med_ent = shannon_entropy("Hello World 12345")
    assert 3.0 < med_ent < 4.5

    # High entropy (random base64/hex token)
    high_ent = shannon_entropy("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
    assert high_ent > 4.2


# ---------------------------------------------------------------------------
# Secret Detection Rules Tests
# ---------------------------------------------------------------------------

def test_detect_openai_api_key():
    sample = f'OPENAI_KEY = "{TEST_OPENAI}"'
    findings = scan_text(sample, filename="config.py")
    assert len(findings) == 1
    assert findings[0]["provider"] == "OpenAI API Key"
    assert findings[0]["severity"] == "CRITICAL"
    assert "sk-proj" in findings[0]["masked"]
    assert "9mN87zQ1vA4bC2dE8fG9hI3jK4lM5nO6pQ7rS8tU9vW0xY1z" not in findings[0]["masked"]


def test_detect_anthropic_api_key():
    sample = f'ANTHROPIC_KEY = "{TEST_ANTHROPIC}"'
    findings = scan_text(sample, filename="keys.env")
    assert len(findings) == 1
    assert findings[0]["provider"] == "Anthropic API Key"
    assert findings[0]["severity"] == "CRITICAL"


def test_detect_aws_access_key():
    sample = f'AWS_ACCESS_KEY_ID = "{TEST_AWS}"'
    findings = scan_text(sample, filename="aws.json")
    assert len(findings) == 1
    assert findings[0]["provider"] == "AWS Access Key"
    assert findings[0]["severity"] == "HIGH"


def test_detect_github_token():
    sample = f'git_pat = "{TEST_GITHUB}"'
    findings = scan_text(sample, filename="deploy.sh")
    assert len(findings) == 1
    assert findings[0]["provider"] == "GitHub Token"
    assert findings[0]["severity"] == "CRITICAL"


def test_detect_stripe_secret_key():
    sample = f'STRIPE_SECRET = "{TEST_STRIPE}"'
    findings = scan_text(sample, filename="billing.py")
    assert len(findings) == 1
    assert findings[0]["provider"] == "Stripe Secret Key"
    assert findings[0]["severity"] == "HIGH"


def test_detect_generic_private_key():
    sample = """
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Y3y1a2b...
-----END RSA PRIVATE KEY-----
"""
    findings = scan_text(sample, filename="id_rsa")
    assert len(findings) >= 1
    assert findings[0]["provider"] == "Private Key Header"
    assert findings[0]["severity"] == "CRITICAL"


def test_false_positive_suppression():
    # Lines with 'mock', 'example', or low entropy should be ignored or pruned
    sample = """
# Example key for documentation:
test_token = "ghp_mock_token_1234567890abcdefghijklm"
fake_openai = "sk-test-example-dummy-key-not-a-real-one"
normal_var = "just a normal string with some text"
"""
    findings = scan_text(sample, filename="test_sample.py")
    assert len(findings) == 0


def test_severity_filtering():
    sample = f"""
aws_key = "{TEST_AWS}"
openai_key = "{TEST_OPENAI}"
"""
    # Min severity CRITICAL should only return OpenAI key (AWS is HIGH)
    findings = scan_text(sample, min_severity="CRITICAL")
    assert len(findings) == 1
    assert findings[0]["provider"] == "OpenAI API Key"

    # Min severity HIGH should return both
    findings_all = scan_text(sample, min_severity="HIGH")
    assert len(findings_all) == 2


# ---------------------------------------------------------------------------
# Directory Traversal & Ignore Files Tests
# ---------------------------------------------------------------------------

def test_scan_path_with_ignore(tmp_path):
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()

    # Leaking file in source
    src_file = repo_dir / "app.py"
    src_file.write_text(f'key = "{TEST_AWS}"', encoding="utf-8")

    # Ignored directory
    git_dir = repo_dir / ".git"
    git_dir.mkdir()
    (git_dir / "git_key.py").write_text(f'key = "{TEST_AWS}"', encoding="utf-8")

    # .leakcheckignore file
    ignore_file = repo_dir / ".leakcheckignore"
    ignore_file.write_text("ignored_folder/\n", encoding="utf-8")

    ignored_dir = repo_dir / "ignored_folder"
    ignored_dir.mkdir()
    (ignored_dir / "secret.py").write_text(f'key = "{TEST_AWS}"', encoding="utf-8")

    report = scan_path(str(repo_dir))
    assert report["scanned_files"] == 1  # only app.py scanned
    assert report["leaks_found"] == 1
    assert "app.py" in report["findings"][0]["file"]


# ---------------------------------------------------------------------------
# Git Pre-Commit Hook Tests
# ---------------------------------------------------------------------------

def test_git_hook_lifecycle(tmp_path):
    repo_dir = tmp_path / "mock_git_repo"
    repo_dir.mkdir()
    git_dir = repo_dir / ".git"
    git_dir.mkdir()

    # 1. Install hook
    success, msg = install_git_hook(str(repo_dir))
    assert success is True
    hook_path = git_dir / "hooks" / "pre-commit"
    assert hook_path.exists()

    # Verify executable bit
    mode = os.stat(hook_path).st_mode
    assert bool(mode & stat.S_IXUSR)

    # Content check
    hook_content = hook_path.read_text(encoding="utf-8")
    assert "leakcheck" in hook_content

    # 2. Uninstall hook
    success_un, msg_un = uninstall_git_hook(str(repo_dir))
    assert success_un is True
    assert not hook_path.exists()


# ---------------------------------------------------------------------------
# CLI Argument and Interactive Tests
# ---------------------------------------------------------------------------

def test_cli_clean_scan(tmp_path, capsys):
    clean_file = tmp_path / "clean.py"
    clean_file.write_text("print('All clean here!')\n", encoding="utf-8")

    exit_code = main([str(clean_file)])
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "0 leaks found" in captured.out or "CLEAN" in captured.out


def test_cli_leak_detected(tmp_path, capsys):
    leaky_file = tmp_path / "leaky.py"
    leaky_file.write_text(f'secret = "{TEST_AWS}"\n', encoding="utf-8")

    exit_code = main([str(leaky_file)])
    assert exit_code == 1
    captured = capsys.readouterr()
    assert "AWS Access Key" in captured.out


def test_cli_json_output(tmp_path, capsys):
    leaky_file = tmp_path / "leaky.py"
    leaky_file.write_text(f'secret = "{TEST_AWS}"\n', encoding="utf-8")

    exit_code = main([str(leaky_file), "--json"])
    assert exit_code == 1
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["leaks_found"] == 1
    assert data["findings"][0]["provider"] == "AWS Access Key"


def test_cli_interactive_wizard(tmp_path, monkeypatch, capsys):
    clean_file = tmp_path / "clean_wizard.py"
    clean_file.write_text("print('Clean')\n", encoding="utf-8")

    # Interactive inputs:
    # 1. Action: 2 (Scan specific directory or file)
    # 2. Path: str(clean_file)
    # 3. Min severity: 2 (MEDIUM)
    inputs = iter([
        "2",
        str(clean_file),
        "2",
    ])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(inputs))

    exit_code = main(["--interactive"])
    assert exit_code == 0
