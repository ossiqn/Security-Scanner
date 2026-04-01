"""
ScanLine - OSINT Security Scanner
Module  : Telegram Notifier
Author  : OSSiqn Team
GitHub  : https://github.com/ossiqn
License : MIT © 2024 OSSiqn

Açıklama (TR): Tespit edilen güvenlik bulgularını Telegram Bot API
üzerinden gerçek zamanlı olarak bildiren modül.
OSSiqn tarafından geliştirilmiştir.

Description (EN): Module that delivers real-time security finding
alerts via Telegram Bot API.
Produced by OSSiqn.

This module was produced by OSSiqn — github.com/ossiqn
"""

import logging
import requests
from typing import Dict, List

PRODUCER = "OSSiqn"
logger = logging.getLogger("scanline.telegram")

SEVERITY_EMOJI = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🟢",
    "info":     "🔵"
}


class TelegramNotifier:
    """
    Telegram Bot API üzerinden bildirim gönderir.
    Sends notifications via Telegram Bot API.

    Produced by OSSiqn — https://github.com/ossiqn
    """

    PRODUCER = "OSSiqn"

    def __init__(self, bot_token: str, chat_id: str, severity_threshold: str = "medium"):
        self.bot_token = bot_token
        self.chat_id = chat_id
        self.severity_threshold = severity_threshold
        self.severity_order = ["info", "low", "medium", "high", "critical"]
        self.api_base = f"https://api.telegram.org/bot{bot_token}"
        logger.info(f"TelegramNotifier initialized | Produced by {self.PRODUCER}")

    def _should_notify(self, severity: str) -> bool:
        try:
            return (
                self.severity_order.index(severity.lower()) >=
                self.severity_order.index(self.severity_threshold.lower())
            )
        except ValueError:
            return True

    def _send_message(self, text: str, parse_mode: str = "HTML") -> bool:
        try:
            response = requests.post(
                f"{self.api_base}/sendMessage",
                json={
                    "chat_id": self.chat_id,
                    "text": text[:4096],
                    "parse_mode": parse_mode,
                    "disable_web_page_preview": True
                },
                timeout=15
            )
            if response.status_code == 200:
                return True
            logger.error(f"[OSSiqn Telegram] API error: {response.status_code}")
            return False
        except Exception as e:
            logger.error(f"[OSSiqn Telegram] Send failed: {e}")
            return False

    def send_finding(self, finding: Dict) -> bool:
        severity = finding.get("severity", "info").lower()

        if not self._should_notify(severity):
            return False

        emoji = SEVERITY_EMOJI.get(severity, "⚪")

        description = finding.get("description", "")
        if len(description) > 300:
            description = description[:300] + "..."

        message = (
            f"{emoji} <b>SCANLINE SECURITY FINDING</b>\n"
            f"{'━' * 32}\n"
            f"<b>Title    :</b> {finding.get('title', 'Unknown')[:100]}\n"
            f"<b>Severity :</b> <code>{severity.upper()}</code>\n"
            f"<b>Category :</b> <code>{finding.get('category', 'unknown')}</code>\n"
            f"<b>Source   :</b> <code>{finding.get('source', 'unknown')}</code>\n"
        )

        if description:
            message += f"\n<b>Details:</b>\n<code>{description}</code>\n"

        if finding.get("url"):
            message += f"\n<b>URL:</b> {finding['url'][:200]}\n"

        message += (
            f"\n<i>Detected at: {finding.get('timestamp', 'unknown')}</i>\n"
            f"<i>🔧 Produced by OSSiqn | github.com/ossiqn</i>"
        )

        return self._send_message(message)

    def send_summary(self, findings: List[Dict], scan_duration: float = 0):
        if not findings:
            return

        severity_counts = {}
        for f in findings:
            sev = f.get("severity", "unknown")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        message = (
            f"📊 <b>SCANLINE SCAN SUMMARY</b>\n"
            f"{'━' * 32}\n"
            f"<b>Total Findings :</b> {len(findings)}\n\n"
            f"🔴 Critical : {severity_counts.get('critical', 0)}\n"
            f"🟠 High     : {severity_counts.get('high', 0)}\n"
            f"🟡 Medium   : {severity_counts.get('medium', 0)}\n"
            f"🟢 Low      : {severity_counts.get('low', 0)}\n\n"
            f"⏱️ Duration : {scan_duration:.1f}s\n\n"
            f"<i>🔧 ScanLine OSINT Scanner</i>\n"
            f"<i>Produced by OSSiqn | github.com/ossiqn</i>"
        )

        self._send_message(message)

    def send_batch_findings(self, findings: List[Dict]) -> int:
        notified = 0
        for finding in findings:
            if self.send_finding(finding):
                notified += 1
        logger.info(f"[OSSiqn Telegram] Sent {notified}/{len(findings)} notifications")
        return notified