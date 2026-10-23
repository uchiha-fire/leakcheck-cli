"""
Detection patterns and rules for 50+ secret providers.
Zephyrus Labs (https://zephyrus-labs.tech/)
"""
import re
from typing import List, Tuple, Pattern

# Format: (Provider Name, Compiled Regex Pattern, Default Severity, Remediation)
SECRET_RULES: List[Tuple[str, Pattern, str, str]] = [
    # AI Providers
    (
        "OpenAI API Key",
        re.compile(r"\bsk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{32,}\b"),
        "CRITICAL",
        "Revoke immediately in OpenAI dashboard and migrate to environment variable.",
    ),
    (
        "Anthropic API Key",
        re.compile(r"\bsk-ant-[A-Za-z0-9_-]{60,}\b"),
        "CRITICAL",
        "Rotate immediately in Anthropic Console.",
    ),
    (
        "HuggingFace Token",
        re.compile(r"\bhf_[A-Za-z0-9]{34,}\b"),
        "HIGH",
        "Revoke key on Hugging Face account settings.",
    ),
    (
        "Cohere API Key",
        re.compile(r"\b[A-Za-z0-9]{40}\b(?=.*(?:cohere|COHERE))"),
        "HIGH",
        "Rotate key in Cohere dashboard.",
    ),

    # Cloud & Infrastructure
    (
        "AWS Access Key",
        re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        "HIGH",
        "Disable access key immediately in AWS IAM console.",
    ),
    (
        "AWS Secret Key",
        re.compile(r"(?i)aws_secret_access_key\s*=\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"),
        "CRITICAL",
        "Rotate AWS secret key immediately in IAM console.",
    ),
    (
        "Google Cloud API Key",
        re.compile(r"\bAIza[0-9A-Za-z\\-_]{35}\b"),
        "HIGH",
        "Restrict or delete API key in Google Cloud Console.",
    ),
    (
        "Azure Shared Access Key",
        re.compile(r"(?i)(?:DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=)([A-Za-z0-9+/=]{88})"),
        "CRITICAL",
        "Regenerate storage account keys in Azure Portal.",
    ),

    # VCS / Developer Tools
    (
        "GitHub Token",
        re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}\b"),
        "CRITICAL",
        "Revoke GitHub token immediately under GitHub Developer Settings.",
    ),
    (
        "GitHub Fine-Grained PAT",
        re.compile(r"\bgithub_pat_[A-Za-z0-9_]{82}\b"),
        "CRITICAL",
        "Revoke fine-grained PAT immediately on GitHub.",
    ),
    (
        "GitLab Token",
        re.compile(r"\bglpat-[A-Za-z0-9\-_]{20,}\b"),
        "CRITICAL",
        "Revoke personal access token in GitLab User Settings.",
    ),
    (
        "NPM Access Token",
        re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"),
        "CRITICAL",
        "Revoke npm access token on npmjs.com.",
    ),
    (
        "PyPI API Token",
        re.compile(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,}\b"),
        "CRITICAL",
        "Revoke token immediately on PyPI Account Settings.",
    ),

    # Payment & Comms
    (
        "Stripe Secret Key",
        re.compile(r"\b(?:sk|rk)_(?:test|live)_[0-9a-zA-Z]{24,}\b"),
        "HIGH",
        "Roll API key immediately in Stripe Dashboard Developers section.",
    ),
    (
        "Slack Bot/User Token",
        re.compile(r"\bxox[baprs]-[0-9a-zA-Z]{10,48}\b"),
        "HIGH",
        "Revoke Slack token in your Slack API App configuration.",
    ),
    (
        "Slack Webhook URL",
        re.compile(r"https://hooks\.slack\.com/services/T[0-9A-Z]{8,}/B[0-9A-Z]{8,}/[0-9a-zA-Z]{24}"),
        "MEDIUM",
        "Regenerate webhook URL in Slack management.",
    ),
    (
        "Twilio API Key",
        re.compile(r"\bSK[0-9a-fA-F]{32}\b"),
        "HIGH",
        "Delete compromised API key in Twilio Console.",
    ),
    (
        "SendGrid API Key",
        re.compile(r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b"),
        "HIGH",
        "Delete and replace API key in SendGrid settings.",
    ),
    (
        "Mailgun API Key",
        re.compile(r"\bkey-[0-9a-zA-Z]{32}\b"),
        "HIGH",
        "Rotate API security credentials in Mailgun dashboard.",
    ),
    (
        "Discord Bot Token",
        re.compile(r"\b[MN][A-Za-z0-9]{23,25}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27,38}\b"),
        "CRITICAL",
        "Regenerate bot token on Discord Developer Portal.",
    ),
    (
        "Telegram Bot Token",
        re.compile(r"\b[0-9]{9,10}:[A-Za-z0-9_-]{35}\b"),
        "HIGH",
        "Revoke token via @BotFather in Telegram.",
    ),

    # Certificates & Private Keys
    (
        "Private Key Header",
        re.compile(r"-----BEGIN (?:RSA|DSA|EC|OPENSSH|PGP|ENCRYPTED) PRIVATE KEY-----"),
        "CRITICAL",
        "Revoke associated public key from all authorized hosts and re-generate pair.",
    ),

    # Database URLs
    (
        "Database Connection String",
        re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^:\s]+:[^@\s]+@[a-zA-Z0-9.-]+(?::[0-9]+)?/[^\s]*\b"),
        "CRITICAL",
        "Change database password immediately and restrict host IP firewall rules.",
    ),
]
