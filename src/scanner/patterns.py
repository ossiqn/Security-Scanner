"""
ScanLine - OSINT Security Scanner
Module  : Leak Detection Patterns
Author  : OSSiqn Team
GitHub  : https://github.com/ossiqn
License : MIT © 2024 OSSiqn

Açıklama (TR): Bu modül, API anahtarları, şifreler, token'lar ve
diğer hassas bilgilerin tespiti için kullanılan regex kalıplarını içerir.
OSSiqn tarafından InfoSec topluluğu için geliştirilmiştir.

Description (EN): This module contains regex patterns used for detecting
API keys, passwords, tokens and other sensitive information leaks.
Developed by OSSiqn for the InfoSec community.

This file was produced by OSSiqn — github.com/ossiqn
"""

import re
import math
from typing import Dict, List

PRODUCER = "OSSiqn"
PRODUCER_URL = "https://github.com/ossiqn"
VERSION = "1.0.0"

LEAK_PATTERNS: Dict[str, Dict] = {
    "aws_access_key": {
        "pattern": r"(?:AKIA|AIPA|AIIA|AROA|AIDA|AGPA|ANPA|ANVA|ASIA)[0-9A-Z]{16}",
        "severity": "critical",
        "category": "cloud_credentials",
        "description": "AWS Access Key ID detected",
        "entropy_check": True
    },
    "aws_secret_key": {
        "pattern": r"(?i)aws.{0,20}secret.{0,20}['\"]([0-9a-zA-Z/+]{40})['\"]",
        "severity": "critical",
        "category": "cloud_credentials",
        "description": "AWS Secret Access Key detected",
        "entropy_check": True
    },
    "github_token": {
        "pattern": r"gh[pousr]_[0-9a-zA-Z]{36,255}",
        "severity": "critical",
        "category": "vcs_tokens",
        "description": "GitHub Personal Access Token detected"
    },
    "github_oauth": {
        "pattern": r"gho_[0-9a-zA-Z]{36}",
        "severity": "critical",
        "category": "vcs_tokens",
        "description": "GitHub OAuth Token detected"
    },
    "stripe_secret": {
        "pattern": r"sk_live_[0-9a-zA-Z]{24,34}",
        "severity": "critical",
        "category": "payment",
        "description": "Stripe Secret Key detected"
    },
    "stripe_restricted": {
        "pattern": r"rk_live_[0-9a-zA-Z]{24,34}",
        "severity": "high",
        "category": "payment",
        "description": "Stripe Restricted Key detected"
    },
    "telegram_bot_token": {
        "pattern": r"[0-9]{8,10}:[a-zA-Z0-9_-]{35}",
        "severity": "high",
        "category": "messaging",
        "description": "Telegram Bot Token detected"
    },
    "discord_token": {
        "pattern": r"[MNO][a-zA-Z0-9]{23}\.[a-zA-Z0-9_-]{6}\.[a-zA-Z0-9_-]{27}",
        "severity": "high",
        "category": "messaging",
        "description": "Discord Bot Token detected"
    },
    "discord_webhook": {
        "pattern": r"https://discord(?:app)?\.com/api/webhooks/[0-9]{17,19}/[a-zA-Z0-9_-]{68}",
        "severity": "medium",
        "category": "messaging",
        "description": "Discord Webhook URL detected"
    },
    "google_api_key": {
        "pattern": r"AIza[0-9A-Za-z_-]{35}",
        "severity": "high",
        "category": "cloud_credentials",
        "description": "Google API Key detected"
    },
    "google_oauth": {
        "pattern": r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com",
        "severity": "medium",
        "category": "cloud_credentials",
        "description": "Google OAuth Client ID detected"
    },
    "firebase_url": {
        "pattern": r"https://[a-z0-9-]+\.firebaseio\.com",
        "severity": "medium",
        "category": "cloud_credentials",
        "description": "Firebase Database URL detected"
    },
    "jwt_token": {
        "pattern": r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}",
        "severity": "medium",
        "category": "auth_tokens",
        "description": "JWT Token detected"
    },
    "private_key_rsa": {
        "pattern": r"-----BEGIN RSA PRIVATE KEY-----",
        "severity": "critical",
        "category": "cryptographic",
        "description": "RSA Private Key detected"
    },
    "private_key_ec": {
        "pattern": r"-----BEGIN EC PRIVATE KEY-----",
        "severity": "critical",
        "category": "cryptographic",
        "description": "EC Private Key detected"
    },
    "private_key_openssh": {
        "pattern": r"-----BEGIN OPENSSH PRIVATE KEY-----",
        "severity": "critical",
        "category": "cryptographic",
        "description": "OpenSSH Private Key detected"
    },
    "pgp_private": {
        "pattern": r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
        "severity": "critical",
        "category": "cryptographic",
        "description": "PGP Private Key Block detected"
    },
    "mongodb_url": {
        "pattern": r"mongodb(?:\+srv)?://[a-zA-Z0-9_-]+:[^@\s]+@[^\s]+",
        "severity": "critical",
        "category": "database",
        "description": "MongoDB Connection String with credentials detected"
    },
    "postgresql_url": {
        "pattern": r"postgresql://[a-zA-Z0-9_-]+:[^@\s]+@[^\s]+",
        "severity": "critical",
        "category": "database",
        "description": "PostgreSQL Connection String with credentials detected"
    },
    "mysql_url": {
        "pattern": r"mysql://[a-zA-Z0-9_-]+:[^@\s]+@[^\s]+",
        "severity": "critical",
        "category": "database",
        "description": "MySQL Connection String with credentials detected"
    },
    "redis_url": {
        "pattern": r"redis://:[^@\s]+@[^\s]+",
        "severity": "high",
        "category": "database",
        "description": "Redis Connection String with credentials detected"
    },
    "slack_token": {
        "pattern": r"xox[baprs]-[0-9a-zA-Z]{10,48}",
        "severity": "high",
        "category": "messaging",
        "description": "Slack Token detected"
    },
    "slack_webhook": {
        "pattern": r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8,}/[a-zA-Z0-9_]{24}",
        "severity": "medium",
        "category": "messaging",
        "description": "Slack Webhook URL detected"
    },
    "twilio_sid": {
        "pattern": r"AC[a-zA-Z0-9]{32}",
        "severity": "high",
        "category": "communication",
        "description": "Twilio Account SID detected"
    },
    "sendgrid_key": {
        "pattern": r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}",
        "severity": "high",
        "category": "email",
        "description": "SendGrid API Key detected"
    },
    "mailgun_key": {
        "pattern": r"key-[0-9a-zA-Z]{32}",
        "severity": "high",
        "category": "email",
        "description": "Mailgun API Key detected"
    },
    "npm_token": {
        "pattern": r"npm_[a-zA-Z0-9]{36}",
        "severity": "high",
        "category": "package_registry",
        "description": "NPM Access Token detected"
    },
    "pypi_token": {
        "pattern": r"pypi-[a-zA-Z0-9_-]{40,}",
        "severity": "high",
        "category": "package_registry",
        "description": "PyPI API Token detected"
    },
    "docker_auth": {
        "pattern": r'"auth"\s*:\s*"[a-zA-Z0-9+/]{40,}={0,2}"',
        "severity": "high",
        "category": "container",
        "description": "Docker Registry Auth Token detected"
    },
    "shopify_key": {
        "pattern": r"shpat_[a-fA-F0-9]{32}",
        "severity": "high",
        "category": "ecommerce",
        "description": "Shopify Access Token detected"
    },
    "openai_key": {
        "pattern": r"sk-[a-zA-Z0-9]{48}",
        "severity": "high",
        "category": "ai_services",
        "description": "OpenAI API Key detected"
    },
    "anthropic_key": {
        "pattern": r"sk-ant-[a-zA-Z0-9_-]{93}",
        "severity": "high",
        "category": "ai_services",
        "description": "Anthropic API Key detected"
    },
    "azure_storage": {
        "pattern": r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[a-zA-Z0-9+/]{86}==",
        "severity": "critical",
        "category": "cloud_credentials",
        "description": "Azure Storage Connection String detected"
    },
    "basic_auth_url": {
        "pattern": r"https?://[a-zA-Z0-9_-]+:[a-zA-Z0-9_!@#$%^&*()-]+@[a-zA-Z0-9.-]+",
        "severity": "high",
        "category": "auth_tokens",
        "description": "URL with embedded credentials detected"
    },
    "password_assignment": {
        "pattern": r"(?i)(?:password|passwd|pwd|secret)\s*[=:]\s*['\"]([^'\"]{8,})['\"]",
        "severity": "medium",
        "category": "credentials",
        "description": "Hardcoded password assignment detected"
    },
    "api_key_assignment": {
        "pattern": r"(?i)(?:api_key|apikey|api-key)\s*[=:]\s*['\"]([a-zA-Z0-9_-]{16,})['\"]",
        "severity": "medium",
        "category": "api_keys",
        "description": "Hardcoded API key assignment detected"
    },
    "secret_assignment": {
        "pattern": r"(?i)(?:secret|token)\s*[=:]\s*['\"]([a-zA-Z0-9_-]{16,})['\"]",
        "severity": "medium",
        "category": "credentials",
        "description": "Hardcoded secret or token assignment detected"
    },
    "facebook_token": {
        "pattern": r"EAACEdEose0cBA[0-9A-Za-z]+",
        "severity": "high",
        "category": "social_media",
        "description": "Facebook Access Token detected"
    },
    "twitter_bearer": {
        "pattern": r"AAAAAAAAAAAAAAAAAAAAAA[a-zA-Z0-9%]{30,}",
        "severity": "high",
        "category": "social_media",
        "description": "Twitter Bearer Token detected"
    }
}

GITHUB_SEARCH_QUERIES: List[str] = [
    "AWS_SECRET_ACCESS_KEY",
    "AWS_ACCESS_KEY_ID AKIA",
    "BEGIN RSA PRIVATE KEY",
    "BEGIN OPENSSH PRIVATE KEY",
    "BEGIN EC PRIVATE KEY",
    "stripe_secret_key sk_live",
    "github_token ghp_",
    "TELEGRAM_BOT_TOKEN",
    "discord_token bot",
    "firebase_api_key AIza",
    "mongodb+srv password",
    "postgresql:// password",
    "redis:// password",
    "slack_token xoxb",
    "sendgrid_api_key SG.",
    "twilio_auth_token",
    "openai_api_key sk-",
    "shopify_access_token shpat",
    "npm_token npm_",
    "azure_client_secret",
    "google_api_key AIza",
    "mailgun_api_key",
    "docker_password registry",
    "database_url SECRET",
    "smtp_password email",
    "ssh_private_key password",
    "heroku api_key",
    "jenkins password api_token",
    "pypi_token pypi-",
    "anthropic_api_key sk-ant"
]

HIGH_ENTROPY_THRESHOLD = 3.5


def calculate_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    entropy = 0.0
    length = len(text)
    for count in freq.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)
    return entropy


def is_likely_placeholder(value: str) -> bool:
    placeholders = [
        "your_api_key", "YOUR_API_KEY", "xxx", "XXX", "placeholder",
        "example", "test", "dummy", "fake", "changeme", "todo",
        "your_token", "YOUR_TOKEN", "insert_here", "replace_me",
        "your_secret", "YOUR_SECRET", "xxxxxxxx", "00000000",
        "11111111", "abcdefgh", "12345678", "your_key_here",
        "enter_your", "put_your", "add_your"
    ]
    value_lower = value.lower()
    for placeholder in placeholders:
        if placeholder.lower() in value_lower:
            return True
    if len(set(value)) < 3:
        return True
    return False


def compile_patterns() -> Dict[str, re.Pattern]:
    compiled = {}
    for name, config in LEAK_PATTERNS.items():
        try:
            compiled[name] = re.compile(config["pattern"], re.MULTILINE | re.IGNORECASE)
        except re.error:
            pass
    return compiled