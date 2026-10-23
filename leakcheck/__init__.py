"""
leakcheck-cli
High-Speed Local Secret Scanner & Git Pre-Commit Guard
"""

__version__ = "0.1.0"
__author__ = "Zephyrus Labs"
__maintainer__ = "Shubham Sharma"
__email__ = "zephyrus.labs@gmail.com"
__developer_email__ = "sharmashubham25962@gmail.com"

from .core import scan_text, scan_path, install_git_hook, uninstall_git_hook

__all__ = [
    "scan_text",
    "scan_path",
    "install_git_hook",
    "uninstall_git_hook",
    "__version__",
    "__author__",
    "__maintainer__",
    "__email__",
    "__developer_email__",
]
