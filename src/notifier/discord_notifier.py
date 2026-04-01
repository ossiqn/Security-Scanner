"""
ScanLine - OSINT Security Scanner
Module  : Discord Notifier
Author  : OSSiqn Team
GitHub  : https://github.com/ossiqn
License : MIT © 2024 OSSiqn

Açıklama (TR): Tespit edilen güvenlik bulgularını Discord webhook
üzerinden gerçek zamanlı olarak bildiren modül.
OSSiqn tarafından geliştirilmiştir.

Description (EN): Module that sends real-time security finding
notifications via Discord webhook.
Produced by OSSiqn.

This module was produced by OSSiqn — github.com/ossiqn
"""

import logging
from typing import Dict, List
from discord_webhook import DiscordWebhook, DiscordEmbed

PRODUCER = "OSSiqn"
logger = logging.getLogger("scanline.discord")

SEVERITY_COLORS = {
    "critical": 0xFF0000,
    "high":     0xFF6600,
    "medium":   0xFFAA00,
    "low":      0x00FF88,
    "info":     0x00AAFF
}

SEVERITY_EMOJI = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🟢",
    "info":     "🔵"
}


class DiscordNotifier:
    """
    Discord webhook üzerinden bildirim gönderir.
    Sends notifications via Discord webhook.

    Produced by OSSiqn — https://github.com/ossiqn
    """

    PRODUCER = "OSSiqn"

    def __init__(self, webhook_url: str, severity_threshold: str = "medium"):
        self.webhook_url = webhook_url
        self.severity_threshold = severity_threshold
        self.severity_order = ["info", "low", "medium", "high", "critical"]
        logger.info(f"DiscordNotifier initialized | Produced by {self.PRODUCER}")

    def _should_notify(self, severity: str) -> bool:
        try:
            return (
                self.severity_order.index(severity.lower()) >=
                self.severity_order.index(self.severity_threshold.lower())
            )
        except ValueError:
            return True

    def send_finding(self, finding: Dict) -> bool:
        severity = finding.get("severity", "info").lower()

        if not self._should_notify(severity):
            return False

        try:
            webhook = DiscordWebhook(url=self.webhook_url, rate_limit_retry=True)

            embed = DiscordEmbed(
                title=f"{SEVERITY_EMOJI.get(severity, '⚪')} {finding.get('title', 'Security Finding')}",
                description=finding.get("description", "")[:2048],
                color=SEVERITY_COLORS.get(severity, 0x888888)
            )

            embed.add_embed_field(name="🎯 Severity",  value=f"`{severity.upper()}`",                      inline=True)
            embed.add_embed_field(name="📦 Category",  value=f"`{finding.get('category', 'unknown')}`",    inline=True)
            embed.add_embed_field(name="🔍 Source",    value=f"`{finding.get('source', 'unknown')}`",      inline=True)

            if finding.get("url"):
                embed.add_embed_field(name="🔗 URL", value=f"[View Source]({finding['url']})", inline=False)

            embed.set_footer(text="ScanLine OSINT Scanner — Produced by OSSiqn | github.com/ossiqn")
            embed.set_timestamp()

            webhook.add_embed(embed)
            response = webhook.execute()

            if response:
                logger.info(f"[OSSiqn Discord] Notification sent: {finding.get('title', '')[:50]}")
                return True

        except Exception as e:
            logger.error(f"[OSSiqn Discord] Notification failed: {e}")

        return False

    def send_summary(self, findings: List[Dict], scan_duration: float = 0):
        if not findings:
            return

        try:
            webhook = DiscordWebhook(url=self.webhook_url, rate_limit_retry=True)

            severity_counts = {}
            for f in findings:
                sev = f.get("severity", "unknown")
                severity_counts[sev] = severity_counts.get(sev, 0) + 1

            embed = DiscordEmbed(
                title="📊 ScanLine Scan Summary",
                description=f"Scan completed. Found **{len(findings)}** total findings.",
                color=0x00AAFF
            )

            embed.add_embed_field(name="🔴 Critical", value=str(severity_counts.get("critical", 0)), inline=True)
            embed.add_embed_field(name="🟠 High",     value=str(severity_counts.get("high", 0)),     inline=True)
            embed.add_embed_field(name="🟡 Medium",   value=str(severity_counts.get("medium", 0)),   inline=True)
            embed.add_embed_field(name="🟢 Low",      value=str(severity_counts.get("low", 0)),      inline=True)
            embed.add_embed_field(name="⏱️ Duration", value=f"{scan_duration:.1f}s",                 inline=True)

            embed.set_footer(text="ScanLine OSINT Scanner — Produced by OSSiqn | github.com/ossiqn")
            embed.set_timestamp()

            webhook.add_embed(embed)
            webhook.execute()

        except Exception as e:
            logger.error(f"[OSSiqn Discord] Summary send failed: {e}")

    def send_batch_findings(self, findings: List[Dict]) -> int:
        notified = 0
        for finding in findings:
            if self.send_finding(finding):
                notified += 1
        logger.info(f"[OSSiqn Discord] Sent {notified}/{len(findings)} notifications")
        return notified