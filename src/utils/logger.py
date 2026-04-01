"""
ScanLine - OSINT Security Scanner
Developed by OSSiqn | https://github.com/ossiqn
© 2024 OSSiqn. All rights reserved.

Bu dosya OSSiqn tarafından üretilmiştir.
This file was produced by OSSiqn.
"""

import logging
import os
from rich.console import Console
from rich.theme import Theme
from rich.logging import RichHandler
from colorama import init

init(autoreset=True)

custom_theme = Theme({
    "info": "cyan",
    "warning": "yellow",
    "error": "bold red",
    "critical": "bold white on red",
    "success": "bold green",
    "scan": "bold magenta",
    "find": "bold yellow",
})

console = Console(theme=custom_theme)

SCANLINE_BANNER = """
[bold cyan]
╔══════════════════════════════════════════════════════════════════════╗
║                                                                      ║
║   ███████╗ ██████╗ █████╗ ███╗   ██╗██╗     ██╗███╗   ██╗███████╗  ║
║   ██╔════╝██╔════╝██╔══██╗████╗  ██║██║     ██║████╗  ██║██╔════╝  ║
║   ███████╗██║     ███████║██╔██╗ ██║██║     ██║██╔██╗ ██║█████╗    ║
║   ╚════██║██║     ██╔══██║██║╚██╗██║██║     ██║██║╚██╗██║██╔══╝    ║
║   ███████║╚██████╗██║  ██║██║ ╚████║███████╗██║██║ ╚████║███████╗  ║
║   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝╚═╝╚═╝  ╚═══╝╚══════╝  ║
║                                                                      ║
║              OSINT Security Scanner v1.0.0                           ║
║         [ Open Source Intelligence & Leak Detection ]                ║
║                                                                      ║
║   ┌─────────────────────────────────────────────────────────────┐   ║
║   │   Developed & Maintained by  ► OSSiqn Team                  │   ║
║   │   GitHub                     ► github.com/ossiqn            │   ║
║   │   License                    ► MIT © 2024 OSSiqn            │   ║
║   │   Build                      ► v1.0.0 stable                │   ║
║   └─────────────────────────────────────────────────────────────┘   ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
[/bold cyan]
"""

OSSIQN_WATERMARK = "Produced by OSSiqn | github.com/ossiqn | © 2024 OSSiqn"


def setup_logger(name: str, log_file: str = None, level: str = "INFO") -> logging.Logger:
    os.makedirs(os.path.dirname(log_file) if log_file and os.path.dirname(log_file) else "data", exist_ok=True)

    handlers = [RichHandler(console=console, rich_tracebacks=True, markup=True)]

    if log_file:
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(
            logging.Formatter(
                f"%(asctime)s | %(name)s | %(levelname)s | %(message)s | [{OSSIQN_WATERMARK}]"
            )
        )
        handlers.append(file_handler)

    logging.basicConfig(
        level=getattr(logging, level.upper()),
        format="%(message)s",
        datefmt="[%X]",
        handlers=handlers,
        force=True
    )

    return logging.getLogger(name)


def print_banner():
    console.print(SCANLINE_BANNER)
    console.print("[bold cyan]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/bold cyan]")
    console.print(
        "[cyan]  Status : [bold green]ONLINE[/bold green]  │  "
        "Mode   : [bold yellow]PASSIVE OSINT[/bold yellow]  │  "
        "Owner  : [bold magenta]OSSiqn[/bold magenta][/cyan]"
    )
    console.print(
        "[cyan]  Target : [bold red]PUBLIC SOURCES[/bold red]  │  "
        "Build  : [bold white]v1.0.0[/bold white]  │  "
        "License: [bold white]MIT © 2024 OSSiqn[/bold white][/cyan]"
    )
    console.print("[bold cyan]━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━[/bold cyan]\n")