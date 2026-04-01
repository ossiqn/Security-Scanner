"""
ScanLine — OSINT Security Scanner
Module  : Main Entry Point
Author  : OSSiqn Team
GitHub  : https://github.com/ossiqn
License : MIT © 2024 OSSiqn

Açıklama (TR):
ScanLine'ın ana giriş noktası. Tüm tarayıcıları, bildirim
sistemlerini ve web arayüzünü başlatır, yönetir ve koordine eder.
OSSiqn tarafından InfoSec topluluğu için geliştirilmiştir.

Description (EN):
Main entry point for ScanLine. Initializes, manages and
coordinates all scanners, notification systems and the
web dashboard.
Developed by OSSiqn for the InfoSec community.

This file was produced by OSSiqn — github.com/ossiqn
"""

import os
import sys
import time
import yaml
import signal
import logging
import threading
import schedule
from datetime import datetime
from dotenv import load_dotenv
from rich.console import Console

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.logger import setup_logger, print_banner, console
from utils.db import Database
from scanner.github_scanner import GitHubScanner
from scanner.leak_scanner import LeakScanner
from scanner.vuln_scanner import VulnScanner
from notifier.discord_notifier import DiscordNotifier
from notifier.telegram_notifier import TelegramNotifier
from web.app import init_web, run_web, broadcast_finding, broadcast_status

load_dotenv()

PRODUCER    = "OSSiqn"
TOOL_NAME   = "ScanLine"
TOOL_VERSION = "1.0.0"
GITHUB_URL  = "https://github.com/ossiqn"

shutdown_event = threading.Event()


def load_config(config_path: str = "config.yml") -> dict:
    config_paths = [
        config_path,
        os.path.join(os.path.dirname(__file__), "..", config_path),
        "/app/config.yml"
    ]

    for path in config_paths:
        if os.path.exists(path):
            with open(path, "r") as f:
                config = yaml.safe_load(f)

            env_overrides = {
                "GITHUB_TOKEN":        ("github", "token"),
                "DISCORD_WEBHOOK_URL": ("notifications.discord", "webhook_url"),
                "TELEGRAM_BOT_TOKEN":  ("notifications.telegram", "bot_token"),
                "TELEGRAM_CHAT_ID":    ("notifications.telegram", "chat_id"),
            }

            for env_key, (section, field) in env_overrides.items():
                val = os.environ.get(env_key)
                if not val:
                    continue
                parts = section.split(".")
                node  = config
                for part in parts:
                    node.setdefault(part, {})
                    node = node[part]
                node[field] = val
                if "webhook_url" in field or "bot_token" in field:
                    node["enabled"] = True

            return config

    return {}


def send_notifications(findings: list, discord_notifier, telegram_notifier, db):
    for finding in findings:
        finding_id = finding.get("id")
        try:
            if discord_notifier:
                discord_notifier.send_finding(finding)
            if telegram_notifier:
                telegram_notifier.send_finding(finding)
            if finding_id:
                db.mark_notified(finding_id)
        except Exception as e:
            logging.getLogger("scanline").error(f"[{PRODUCER}] Notification error #{finding_id}: {e}")

        try:
            broadcast_finding(finding)
        except Exception:
            pass


def run_github_scan(scanner: GitHubScanner, discord_notifier, telegram_notifier, db, scanner_status: dict):
    logger = logging.getLogger("scanline.main")

    scanner_status.update({
        "running":      True,
        "current_task": "GitHub Code Search",
        "scan_start":   datetime.utcnow().isoformat(),
        "produced_by":  PRODUCER
    })

    try:
        broadcast_status(scanner_status)
    except Exception:
        pass

    console.print(f"[bold cyan]▶ [{PRODUCER}] Starting GitHub Code Search scan...[/bold cyan]")
    logger.info(f"[{PRODUCER}] Starting GitHub scan...")

    findings = scanner.scan_all_queries()

    if findings:
        send_notifications(findings, discord_notifier, telegram_notifier, db)
        console.print(f"[bold green]✓ [{PRODUCER}] GitHub scan complete — {len(findings)} findings[/bold green]")
    else:
        console.print(f"[cyan]✓ [{PRODUCER}] GitHub scan complete — No findings[/cyan]")

    logger.info(f"[{PRODUCER}] GitHub scan complete. {len(findings)} findings.")

    scanner_status.update({
        "running":        False,
        "current_task":   f"Last scan: {datetime.utcnow().strftime('%H:%M:%S')}",
        "total_findings": scanner.findings_count
    })

    try:
        broadcast_status(scanner_status)
    except Exception:
        pass

    return findings


def run_leak_scan(scanner: LeakScanner, github_token: str, discord_notifier, telegram_notifier, db, scanner_status: dict):
    logger = logging.getLogger("scanline.main")
    all_findings = []

    scanner_status.update({"running": True, "current_task": "Pastebin Scan"})
    try:
        broadcast_status(scanner_status)
    except Exception:
        pass

    console.print(f"[bold cyan]▶ [{PRODUCER}] Starting Pastebin scan...[/bold cyan]")
    pastebin_findings = scanner.scan_pastebin_recent()
    all_findings.extend(pastebin_findings)
    if pastebin_findings:
        send_notifications(pastebin_findings, discord_notifier, telegram_notifier, db)

    if github_token:
        scanner_status["current_task"] = "GitHub Gist Scan"
        try:
            broadcast_status(scanner_status)
        except Exception:
            pass

        console.print(f"[bold cyan]▶ [{PRODUCER}] Starting GitHub Gist scan...[/bold cyan]")
        gist_findings = scanner.scan_github_gists(github_token)
        all_findings.extend(gist_findings)
        if gist_findings:
            send_notifications(gist_findings, discord_notifier, telegram_notifier, db)

    scanner_status.update({
        "running":      False,
        "current_task": f"Last leak scan: {datetime.utcnow().strftime('%H:%M:%S')}"
    })

    try:
        broadcast_status(scanner_status)
    except Exception:
        pass

    if all_findings:
        console.print(f"[bold green]✓ [{PRODUCER}] Leak scan complete — {len(all_findings)} findings[/bold green]")
    else:
        console.print(f"[cyan]✓ [{PRODUCER}] Leak scan complete — No findings[/cyan]")

    logger.info(f"[{PRODUCER}] Leak scan complete. {len(all_findings)} findings.")
    return all_findings


def signal_handler(signum, frame):
    logger = logging.getLogger("scanline.main")
    logger.info(f"[{PRODUCER}] Shutdown signal received.")
    console.print(f"\n[bold red]⚠ [{PRODUCER}] Shutdown signal received. Stopping ScanLine...[/bold red]")
    shutdown_event.set()


def run_scheduler(github_scanner, leak_scanner, github_token,
                  discord_notifier, telegram_notifier, db, scanner_status, config):
    logger = logging.getLogger("scanline.main")

    github_config = config.get("scanner", {}).get("github", {})
    leak_config   = config.get("scanner", {}).get("leak", {})

    github_interval = github_config.get("scan_interval_minutes", 60)
    leak_interval   = leak_config.get("check_interval", 300)

    if github_config.get("enabled", True) and github_scanner:
        schedule.every(github_interval).minutes.do(
            run_github_scan, github_scanner, discord_notifier, telegram_notifier, db, scanner_status
        )
        logger.info(f"[{PRODUCER}] GitHub scan scheduled every {github_interval} minutes")

    if leak_config.get("enabled", True):
        schedule.every(leak_interval).seconds.do(
            run_leak_scan, leak_scanner, github_token, discord_notifier, telegram_notifier, db, scanner_status
        )
        logger.info(f"[{PRODUCER}] Leak scan scheduled every {leak_interval} seconds")

    while not shutdown_event.is_set():
        schedule.run_pending()
        time.sleep(1)

    logger.info(f"[{PRODUCER}] Scheduler stopped.")


def main():
    signal.signal(signal.SIGINT,  signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    print_banner()

    config = load_config()

    log_config = config.get("logging", {})
    logger = setup_logger(
        "scanline",
        log_file=log_config.get("file", "data/scanline.log"),
        level=log_config.get("level", "INFO")
    )

    logger.info(f"{TOOL_NAME} v{TOOL_VERSION} starting... | Produced by {PRODUCER} | {GITHUB_URL}")

    db = Database(config.get("database", {}).get("path", "data/results.db"))
    logger.info(f"[{PRODUCER}] Database initialized")

    github_token = (
        config.get("github", {}).get("token") or
        os.environ.get("GITHUB_TOKEN", "")
    )

    github_scanner = None
    github_config  = config.get("scanner", {}).get("github", {})

    if github_config.get("enabled", True) and github_token:
        github_scanner = GitHubScanner(github_token, github_config, db)
        console.print(f"[bold green]✓ [{PRODUCER}] GitHub scanner ready[/bold green]")
    elif not github_token:
        console.print(f"[yellow]⚠ [{PRODUCER}] GitHub token not set — GitHub scanning disabled[/yellow]")

    leak_scanner = LeakScanner(config.get("scanner", {}).get("leak", {}), db)
    console.print(f"[bold green]✓ [{PRODUCER}] Leak scanner ready[/bold green]")

    vuln_scanner = VulnScanner(config.get("scanner", {}).get("vuln", {}), db)
    console.print(f"[bold green]✓ [{PRODUCER}] Vulnerability scanner ready[/bold green]")

    discord_notifier  = None
    telegram_notifier = None

    discord_config = config.get("notifications", {}).get("discord", {})
    if discord_config.get("enabled") and discord_config.get("webhook_url"):
        discord_notifier = DiscordNotifier(
            webhook_url=discord_config["webhook_url"],
            severity_threshold=discord_config.get("severity_threshold", "medium")
        )
        console.print(f"[bold green]✓ [{PRODUCER}] Discord notifications ready[/bold green]")

    telegram_config = config.get("notifications", {}).get("telegram", {})
    if (telegram_config.get("enabled") and
        telegram_config.get("bot_token") and
        telegram_config.get("chat_id")):
        telegram_notifier = TelegramNotifier(
            bot_token=telegram_config["bot_token"],
            chat_id=telegram_config["chat_id"],
            severity_threshold=telegram_config.get("severity_threshold", "medium")
        )
        console.print(f"[bold green]✓ [{PRODUCER}] Telegram notifications ready[/bold green]")

    scanner_status = {
        "running":        False,
        "current_task":   "Initializing",
        "total_findings": 0,
        "scan_start":     None,
        "produced_by":    PRODUCER,
        "tool":           f"{TOOL_NAME} v{TOOL_VERSION}"
    }

    web_config = config.get("web", {})
    if web_config.get("enabled", True):
        init_web(db, scanner_status)
        threading.Thread(
            target=run_web,
            kwargs={"host": web_config.get("host", "0.0.0.0"), "port": web_config.get("port", 5000), "debug": False},
            daemon=True,
            name="WebServer"
        ).start()
        console.print(f"[bold green]✓ [{PRODUCER}] Web dashboard at http://localhost:{web_config.get('port', 5000)}[/bold green]")

    console.print(f"\n[bold cyan]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/bold cyan]")
    console.print(f"[bold green]✓ All systems ready. Starting initial scan... | {PRODUCER}[/bold green]\n")

    if github_scanner:
        threading.Thread(
            target=run_github_scan,
            args=(github_scanner, discord_notifier, telegram_notifier, db, scanner_status),
            daemon=True, name="InitialGitHubScan"
        ).start()

    threading.Thread(
        target=run_leak_scan,
        args=(leak_scanner, github_token, discord_notifier, telegram_notifier, db, scanner_status),
        daemon=True, name="InitialLeakScan"
    ).start()

    threading.Thread(
        target=run_scheduler,
        args=(github_scanner, leak_scanner, github_token, discord_notifier,
              telegram_notifier, db, scanner_status, config),
        daemon=True, name="Scheduler"
    ).start()

    logger.info(f"[{PRODUCER}] {TOOL_NAME} fully operational. Press Ctrl+C to stop.")
    console.print(f"[bold cyan]{TOOL_NAME} is running. Produced by {PRODUCER} · {GITHUB_URL} · Press Ctrl+C to stop.[/bold cyan]\n")

    shutdown_event.wait()

    logger.info(f"[{PRODUCER}] {TOOL_NAME} shutdown complete.")
    console.print(f"\n[bold red]{TOOL_NAME} stopped. | Produced by {PRODUCER}[/bold red]")
    sys.exit(0)


if __name__ == "__main__":
    main()