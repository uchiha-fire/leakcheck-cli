"""
CLI interface and interactive wizard for leakcheck.
Zephyrus Labs (https://zephyrus-labs.tech/)
Lead Developer: Shubham Sharma
"""
import argparse
import json
import os
import sys
from typing import List, Optional

from leakcheck import __version__
from leakcheck.core import (
    scan_path,
    install_git_hook,
    uninstall_git_hook,
    DEFAULT_SEVERITIES,
)

CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
RESET = "\033[0m"


def print_banner():
    banner = f"""{CYAN}{BOLD}
╔══════════════════════════════════════════════════════════════╗
║               leakcheck-cli  v{__version__}                         ║
║     High-Speed Local Secret Scanner & Git Hook Guard         ║
║     Zephyrus Labs (https://zephyrus-labs.tech/)              ║
╚══════════════════════════════════════════════════════════════╝{RESET}"""
    print(banner)


def display_findings_table(report: dict):
    scanned = report.get("scanned_files", 0)
    leaks = report.get("leaks_found", 0)
    findings = report.get("findings", [])

    print(f"\n{BOLD}Scan Complete:{RESET} {scanned} files inspected.")

    if leaks == 0:
        print(f"{GREEN}{BOLD}✓ CLEAN: 0 leaks found. Your codebase is safe to commit!{RESET}\n")
        return

    print(f"{RED}{BOLD}🚨 SECURITY ALERT: {leaks} secret leak(s) detected!{RESET}\n")
    print("=" * 80)
    for idx, f in enumerate(findings, start=1):
        sev_color = RED if f["severity"] == "CRITICAL" else YELLOW
        print(f"{BOLD}[{idx}] {sev_color}{f['severity']}{RESET} - {BOLD}{f['provider']}{RESET}")
        print(f"    Location:    {f['file']}:{f['line']}")
        print(f"    Secret:      {CYAN}{f['masked']}{RESET} (Entropy: {f.get('entropy', 'N/A')})")
        print(f"    Remediation: {f['remediation']}")
        print("-" * 80)


def run_interactive_wizard() -> int:
    print_banner()
    print(f"\n{BOLD}Welcome to the leakcheck Interactive Security Wizard!{RESET}\n")

    print(f"{BOLD}Select Action:{RESET}")
    print("  [1] Scan current repository (.)")
    print("  [2] Scan specific directory or file")
    print("  [3] Scan git staged changes only")
    print("  [4] Install Git Pre-Commit Hook (blocks commits on leak)")
    print("  [5] Uninstall Git Pre-Commit Hook")

    choice = input(f"{BOLD}Choose [1/2/3/4/5] (default: 1):{RESET} ").strip() or "1"

    if choice == "4":
        ok, msg = install_git_hook(".")
        color = GREEN if ok else RED
        print(f"\n{color}{msg}{RESET}\n")
        return 0 if ok else 1

    if choice == "5":
        ok, msg = uninstall_git_hook(".")
        color = GREEN if ok else RED
        print(f"\n{color}{msg}{RESET}\n")
        return 0 if ok else 1

    target_path = "."
    staged_only = False

    if choice == "2":
        target_path = input(f"{BOLD}Enter path to scan:{RESET} ").strip()
        if not target_path or not os.path.exists(target_path):
            print(f"{RED}Invalid path: '{target_path}'{RESET}")
            return 1
    elif choice == "3":
        staged_only = True

    # Severity selection
    print(f"\n{BOLD}Select Minimum Severity Threshold:{RESET}")
    print("  [1] LOW")
    print("  [2] MEDIUM (Recommended)")
    print("  [3] HIGH")
    print("  [4] CRITICAL")
    sev_choice = input(f"{BOLD}Choose [1/2/3/4] (default: 2):{RESET} ").strip() or "2"
    sev_map = {"1": "LOW", "2": "MEDIUM", "3": "HIGH", "4": "CRITICAL"}
    min_severity = sev_map.get(sev_choice, "MEDIUM")

    print(f"\n{CYAN}Scanning for secret leaks (min severity: {min_severity})...{RESET}")
    report = scan_path(target_path, staged_only=staged_only, min_severity=min_severity)
    display_findings_table(report)

    return 1 if report["leaks_found"] > 0 else 0


def main(argv: Optional[List[str]] = None) -> int:
    if argv is None:
        argv = sys.argv[1:]

    parser = argparse.ArgumentParser(
        prog="leakcheck",
        description="High-Speed Local Secret Scanner & Git Pre-Commit Guard by Zephyrus Labs",
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=None,
        help="Path to file or directory to scan (defaults to current directory)",
    )
    parser.add_argument(
        "--staged",
        action="store_true",
        help="Scan only git staged changes",
    )
    parser.add_argument(
        "--install-hook",
        action="store_true",
        help="Install git pre-commit hook into local repository",
    )
    parser.add_argument(
        "--uninstall-hook",
        action="store_true",
        help="Uninstall git pre-commit hook from local repository",
    )
    parser.add_argument(
        "--min-severity",
        choices=["low", "medium", "high", "critical", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
        default="medium",
        help="Minimum severity threshold (default: medium)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output machine-readable JSON format",
    )
    parser.add_argument(
        "-i",
        "--interactive",
        action="store_true",
        help="Launch interactive security wizard",
    )
    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"leakcheck-cli {__version__} by Zephyrus Labs",
    )

    args = parser.parse_args(argv)

    if args.install_hook:
        ok, msg = install_git_hook(".")
        print(msg)
        return 0 if ok else 1

    if args.uninstall_hook:
        ok, msg = uninstall_git_hook(".")
        print(msg)
        return 0 if ok else 1

    if args.interactive:
        return run_interactive_wizard()

    target_path = args.path or "."
    if not os.path.exists(target_path):
        print(f"{RED}Error: Path '{target_path}' does not exist.{RESET}", file=sys.stderr)
        return 2

    min_sev = args.min_severity.upper()
    try:
        report = scan_path(target_path, staged_only=args.staged, min_severity=min_sev)
    except Exception as e:
        print(f"{RED}Error scanning path: {e}{RESET}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        display_findings_table(report)

    return 1 if report["leaks_found"] > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
