# leakcheck-cli

[![PyPI version](https://img.shields.io/pypi/v/leakcheck-cli.svg)](https://pypi.org/project/leakcheck-cli/)
[![Python versions](https://img.shields.io/pypi/pyversions/leakcheck-cli.svg)](https://pypi.org/project/leakcheck-cli/)
[![GitHub stars](https://img.shields.io/github/stars/uchiha-fire/leakcheck-cli?style=social)](https://github.com/uchiha-fire/leakcheck-cli)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Zephyrus Labs](https://img.shields.io/badge/Developed%20by-Zephyrus%20Labs-6366f1.svg)](https://zephyrus-labs.tech/)

A high-speed, zero-dependency local secret scanner and Git pre-commit guard with Shannon entropy analysis by **[Zephyrus Labs](https://zephyrus-labs.tech/)** for Linux, macOS, and Windows.

---

## Features

- ⚡ **Zero External Dependencies**: 100% pure Python standard library (`re`, `math`, `os`, `sys`).
- 🛡️ **50+ Secret Detection Signatures**: Detects keys for OpenAI, Anthropic, AWS, GitHub, Stripe, Google Cloud, Slack, Discord, Telegram, DB URLs, and SSH Private Keys.
- 📐 **Shannon Entropy Verification**: Measures cryptographic randomness to filter out false positives and mock strings.
- 🪝 **One-Click Git Pre-Commit Hook**: Install a local `.git/hooks/pre-commit` guard with `leakcheck --install-hook` to block secrets from entering git history.
- 🔒 **Git Staged Scanning**: Scan only files staged in git index with `--staged`.
- 🤖 **CI/CD & Machine Ready**: Formatted interactive terminal UI or `--json` output with standard exit codes (0 for clean, 1 for leaks).
- 🧙 **Interactive Security Wizard**: Launch an intuitive terminal wizard to inspect findings, configure thresholds, and install hooks.

---

## Installation

```bash
pip install leakcheck-cli
```

Or install the development build directly:

```bash
pip install git+https://github.com/uchiha-fire/leakcheck-cli.git
```

---

## Interactive Mode

Run `leakcheck` with `--interactive` or invoke it without arguments to launch the wizard:

```bash
leakcheck --interactive
```

```text
╔══════════════════════════════════════════════════════════════╗
║               leakcheck-cli  v0.1.0                          ║
║     High-Speed Local Secret Scanner & Git Hook Guard         ║
║     Zephyrus Labs (https://zephyrus-labs.tech/)              ║
╚══════════════════════════════════════════════════════════════╝

Welcome to the leakcheck Interactive Security Wizard!

Select Action:
  [1] Scan current repository (.)
  [2] Scan specific directory or file
  [3] Scan git staged changes only
  [4] Install Git Pre-Commit Hook (blocks commits on leak)
  [5] Uninstall Git Pre-Commit Hook
Choose [1/2/3/4/5] (default: 1): 1

Select Minimum Severity Threshold:
  [1] LOW
  [2] MEDIUM (Recommended)
  [3] HIGH
  [4] CRITICAL
Choose [1/2/3/4] (default: 2): 2

Scanning for secret leaks (min severity: MEDIUM)...

Scan Complete: 38 files inspected.
✓ CLEAN: 0 leaks found. Your codebase is safe to commit!
```

---

## CLI Usage & Options

```bash
# Scan current workspace
leakcheck

# Scan only git staged files before commit
leakcheck --staged

# Install automatic git pre-commit hook in local repo
leakcheck --install-hook

# Scan specific folder with high severity filter
leakcheck ./services --min-severity HIGH

# Generate machine-readable JSON for CI/CD pipelines
leakcheck --json > security-report.json
```

### Options Reference

| Flag | Long Option | Default | Description |
| :--- | :--- | :--- | :--- |
| `path` | *(positional)* | `.` | Target path or file to scan |
| | `--staged` | `False` | Scan only git staged files (pre-commit check) |
| | `--install-hook` | `False` | Install pre-commit hook into `.git/hooks/` |
| | `--uninstall-hook` | `False` | Remove pre-commit hook from `.git/hooks/` |
| | `--min-severity` | `medium` | Severity threshold: `low`, `medium`, `high`, `critical` |
| | `--json` | `False` | Output structured machine-readable JSON |
| `-i` | `--interactive` | `False` | Launch interactive terminal wizard |
| `-v` | `--version` | — | Display package version |

### Exit Codes

- `0`: Scan passed clean. No leaks detected.
- `1`: One or more security leaks detected (aborts commit if used as git hook).
- `2`: Runtime error or invalid target path.

---

## Git Pre-Commit Hook

Protect your repository from accidental token leaks:

```bash
leakcheck --install-hook
```

This creates an executable script at `.git/hooks/pre-commit`. Whenever you run `git commit`, `leakcheck` will scan staged diffs before the commit is finalized.

To uninstall:
```bash
leakcheck --uninstall-hook
```

---

## Python API Reference

```python
from leakcheck import scan_text, scan_path

# Scan in-memory content
content = 'OPENAI_KEY = "sk-proj-" + "ab1234567890abcdefghijklmnopqrstuvwxyz"'
findings = scan_text(content, filename="app.py", min_severity="MEDIUM")

for f in findings:
    print(f"[{f['severity']}] {f['provider']} in {f['file']}:{f['line']}")
    print(f"Masked: {f['masked']} (Entropy: {f['entropy']})")
    print(f"Action: {f['remediation']}")

# Scan filesystem directory
report = scan_path("./src", min_severity="HIGH")
print(f"Scanned {report['scanned_files']} files, found {report['leaks_found']} leaks.")
```

---

## Developed & Maintained by Zephyrus Labs

Built and maintained by **[Zephyrus Labs](https://zephyrus-labs.tech/)**.

- 🌐 Website: [zephyrus-labs.tech](https://zephyrus-labs.tech/)
- 💻 GitHub: [@uchiha-fire](https://github.com/uchiha-fire)
- ✉️ Contact: [zephyrus.labs@gmail.com](mailto:zephyrus.labs@gmail.com)

If you find this tool helpful, please give it a ⭐️ on [GitHub](https://github.com/uchiha-fire/leakcheck-cli)!

---

## Acknowledgements & Attributions

`leakcheck-cli` is implemented entirely using Python's standard library. No external runtime dependencies are required.

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

<p align="right">
  <sub>Lead Developer: <a href="https://www.linkedin.com/in/shubham-sharma-28487819b/">Shubham Sharma</a> (<a href="https://github.com/uchiha-fire">@uchiha-fire</a>) &bull; <a href="mailto:sharmashubham25962@gmail.com">sharmashubham25962@gmail.com</a></sub>
</p>
