"""
ScanLine - OSINT Security Scanner
Module  : Leak Scanner (Pastebin / Gist)
Author  : OSSiqn Team
GitHub  : https://github.com/ossiqn
License : MIT © 2024 OSSiqn

Açıklama (TR): Pastebin ve GitHub Gist gibi açık kaynaklarda
yayınlanan veri sızıntılarını gerçek zamanlı olarak tespit eden
modül. OSSiqn tarafından geliştirilmiştir.

Description (EN): Module that detects data leaks published on
open platforms like Pastebin and GitHub Gist in real time.
Produced by OSSiqn.

This module was produced by OSSiqn — github.com/ossiqn
"""

import re
import time
import logging
import requests
from datetime import datetime
from typing import List, Dict
from bs4 import BeautifulSoup
from .patterns import compile_patterns, LEAK_PATTERNS, is_likely_placeholder

PRODUCER = "OSSiqn"
logger = logging.getLogger("scanline.leak")


class LeakScanner:
    """
    Pastebin ve GitHub Gist üzerindeki sızıntıları tarar.
    Scans Pastebin and GitHub Gist for leaked credentials.

    Produced by OSSiqn — https://github.com/ossiqn
    """

    PRODUCER = "OSSiqn"
    VERSION = "1.0.0"

    def __init__(self, config: Dict, db):
        self.config = config
        self.db = db
        self.patterns = compile_patterns()
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            )
        })
        logger.info(f"LeakScanner initialized | Produced by {self.PRODUCER}")

    def _analyze_text(self, text: str, source_url: str, source_type: str) -> List[Dict]:
        findings = []
        if not text or len(text) < 20:
            return findings

        found_patterns = set()

        for pattern_name, compiled_pattern in self.patterns.items():
            pattern_config = LEAK_PATTERNS.get(pattern_name, {})

            try:
                matches = compiled_pattern.findall(text)
            except Exception:
                continue

            for match in matches:
                match_value = match if isinstance(match, str) else (match[0] if match else "")

                if not match_value or len(match_value) < 8:
                    continue

                if is_likely_placeholder(match_value):
                    continue

                dedup_key = f"{pattern_name}:{match_value[:30]}"
                if dedup_key in found_patterns:
                    continue
                found_patterns.add(dedup_key)

                finding = {
                    "timestamp": datetime.utcnow().isoformat(),
                    "source": source_type,
                    "category": pattern_config.get("category", "unknown"),
                    "severity": pattern_config.get("severity", "low"),
                    "title": f"[{source_type.title()}] {pattern_config.get('description', pattern_name)}",
                    "description": (
                        f"Potential leak found in {source_type}\n"
                        f"URL: {source_url}\n"
                        f"Pattern: {pattern_name}\n"
                        f"Preview: {match_value[:80]}...\n"
                        f"Detected by ScanLine — Produced by OSSiqn"
                    ),
                    "url": source_url,
                    "raw_data": {
                        "pattern_name": pattern_name,
                        "source_type": source_type,
                        "match_preview": match_value[:100],
                        "produced_by": "OSSiqn",
                        "tool": "ScanLine"
                    }
                }
                findings.append(finding)

        return findings

    def scan_pastebin_recent(self) -> List[Dict]:
        findings = []
        logger.info("[OSSiqn LeakScanner] Scanning Pastebin recent pastes...")

        try:
            response = self.session.get("https://pastebin.com/archive", timeout=15)

            if response.status_code != 200:
                logger.warning(f"[OSSiqn LeakScanner] Pastebin returned {response.status_code}")
                return findings

            soup = BeautifulSoup(response.text, "html.parser")
            paste_links = []

            table = soup.find("table", class_="maintable")
            if table:
                for row in table.find_all("tr")[1:21]:
                    link = row.find("a")
                    if link and link.get("href"):
                        href = link["href"]
                        if href.startswith("/") and len(href) > 1 and "archive" not in href:
                            paste_links.append(f"https://pastebin.com/raw{href}")

            for paste_url in paste_links:
                try:
                    time.sleep(1)
                    paste_response = self.session.get(paste_url, timeout=10)

                    if paste_response.status_code == 200:
                        paste_findings = self._analyze_text(paste_response.text, paste_url, "pastebin")

                        for finding in paste_findings:
                            finding_id = self.db.insert_finding(finding)
                            finding["id"] = finding_id
                            findings.append(finding)
                            logger.warning(
                                f"[OSSiqn FIND] PASTEBIN | {finding['severity'].upper()} | {finding['title']}"
                            )

                except requests.RequestException as e:
                    logger.error(f"[OSSiqn LeakScanner] Error fetching paste {paste_url}: {e}")
                    continue

        except Exception as e:
            logger.error(f"[OSSiqn LeakScanner] Pastebin scan error: {e}")

        logger.info(f"[OSSiqn LeakScanner] Pastebin scan complete — {len(findings)} findings")
        return findings

    def scan_github_gists(self, github_token: str = None) -> List[Dict]:
        findings = []
        logger.info("[OSSiqn LeakScanner] Scanning GitHub Gists...")

        headers = {"Accept": "application/vnd.github.v3+json"}
        if github_token:
            headers["Authorization"] = f"token {github_token}"

        try:
            response = self.session.get(
                "https://api.github.com/gists/public",
                headers=headers,
                params={"per_page": 30},
                timeout=15
            )

            if response.status_code != 200:
                logger.warning(f"[OSSiqn LeakScanner] Gist API returned {response.status_code}")
                return findings

            gists = response.json()

            for gist in gists:
                try:
                    time.sleep(0.5)
                    gist_response = self.session.get(gist["url"], headers=headers, timeout=10)

                    if gist_response.status_code != 200:
                        continue

                    gist_data = gist_response.json()

                    for filename, file_data in gist_data.get("files", {}).items():
                        content = file_data.get("content", "")
                        if content:
                            gist_findings = self._analyze_text(
                                content,
                                gist_data.get("html_url", gist["html_url"]),
                                "github_gist"
                            )

                            for finding in gist_findings:
                                finding["raw_data"]["gist_filename"] = filename
                                finding_id = self.db.insert_finding(finding)
                                finding["id"] = finding_id
                                findings.append(finding)
                                logger.warning(
                                    f"[OSSiqn FIND] GIST | {finding['severity'].upper()} | {finding['title']}"
                                )

                except Exception as e:
                    logger.error(f"[OSSiqn LeakScanner] Error processing gist: {e}")
                    continue

        except Exception as e:
            logger.error(f"[OSSiqn LeakScanner] Gist scan error: {e}")

        logger.info(f"[OSSiqn LeakScanner] Gist scan complete — {len(findings)} findings")
        return findings