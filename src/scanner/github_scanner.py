"""
ScanLine - OSINT Security Scanner
Module  : GitHub Code Scanner
Author  : OSSiqn Team
GitHub  : https://github.com/ossiqn
License : MIT © 2024 OSSiqn

Açıklama (TR): GitHub Code Search API kullanarak açık kaynak
depolardaki sızdırılmış API anahtarlarını, şifreleri ve hassas
bilgileri tespit eden tarayıcı modülü.
OSSiqn tarafından geliştirilmiştir.

Description (EN): Scanner module that detects leaked API keys,
passwords and sensitive information in public repositories using
the GitHub Code Search API.
Produced by OSSiqn.

This module was produced by OSSiqn — github.com/ossiqn
"""

import time
import base64
import logging
from datetime import datetime
from typing import List, Dict, Optional
from github import Github, GithubException, RateLimitExceededException
from .patterns import (
    LEAK_PATTERNS,
    GITHUB_SEARCH_QUERIES,
    compile_patterns,
    is_likely_placeholder,
    calculate_entropy,
    HIGH_ENTROPY_THRESHOLD
)

PRODUCER = "OSSiqn"
logger = logging.getLogger("scanline.github")


class GitHubScanner:
    """
    GitHub Code Search tabanlı sızıntı tarayıcısı.
    GitHub-based leak scanner for public repositories.

    Produced by OSSiqn — https://github.com/ossiqn
    """

    PRODUCER = "OSSiqn"
    VERSION = "1.0.0"

    def __init__(self, token: str, config: Dict, db):
        self.github = Github(token)
        self.config = config
        self.db = db
        self.patterns = compile_patterns()
        self.scan_count = 0
        self.findings_count = 0
        logger.info(f"GitHubScanner initialized | Produced by {self.PRODUCER}")

    def _wait_for_rate_limit(self):
        try:
            rate_limit = self.github.get_rate_limit()
            core = rate_limit.search
            if core.remaining < 5:
                reset_time = core.reset
                wait_seconds = (reset_time - datetime.utcnow()).total_seconds() + 10
                if wait_seconds > 0:
                    logger.warning(f"GitHub rate limit reached. Waiting {wait_seconds:.0f}s | OSSiqn Scanner")
                    time.sleep(wait_seconds)
        except Exception as e:
            logger.error(f"Rate limit check failed: {e} | OSSiqn Scanner")
            time.sleep(60)

    def _decode_file_content(self, file_content) -> Optional[str]:
        try:
            if hasattr(file_content, 'content') and file_content.content:
                return base64.b64decode(file_content.content).decode('utf-8', errors='ignore')
        except Exception:
            pass
        return None

    def _analyze_content(self, content: str, url: str, filename: str) -> List[Dict]:
        findings = []
        if not content or len(content) > 500000:
            return findings

        found_in_file = set()

        for pattern_name, compiled_pattern in self.patterns.items():
            pattern_config = LEAK_PATTERNS.get(pattern_name, {})
            matches = compiled_pattern.findall(content)

            if not matches:
                continue

            for match in matches:
                match_value = match if isinstance(match, str) else (match[0] if match else "")

                if not match_value or len(match_value) < 8:
                    continue

                if is_likely_placeholder(match_value):
                    continue

                if pattern_config.get("entropy_check"):
                    if calculate_entropy(match_value) < HIGH_ENTROPY_THRESHOLD:
                        continue

                dedup_key = f"{pattern_name}:{match_value[:20]}"
                if dedup_key in found_in_file:
                    continue
                found_in_file.add(dedup_key)

                finding = {
                    "timestamp": datetime.utcnow().isoformat(),
                    "source": "github",
                    "category": pattern_config.get("category", "unknown"),
                    "severity": pattern_config.get("severity", "low"),
                    "title": f"[GitHub] {pattern_config.get('description', pattern_name)}",
                    "description": (
                        f"Pattern '{pattern_name}' found in file '{filename}'\n"
                        f"URL: {url}\n"
                        f"Match preview: {match_value[:50]}...\n"
                        f"Detected by ScanLine — Produced by OSSiqn"
                    ),
                    "url": url,
                    "raw_data": {
                        "pattern_name": pattern_name,
                        "filename": filename,
                        "match_preview": match_value[:100],
                        "severity": pattern_config.get("severity", "low"),
                        "category": pattern_config.get("category", "unknown"),
                        "produced_by": "OSSiqn",
                        "tool": "ScanLine"
                    }
                }
                findings.append(finding)

        return findings

    def scan_query(self, query: str) -> List[Dict]:
        findings = []
        self.scan_count += 1

        logger.info(f"[OSSiqn Scanner] Scanning GitHub for: '{query}'")

        try:
            self._wait_for_rate_limit()

            results = self.github.search_code(query, sort="indexed", order="desc")
            processed = 0
            max_results = self.config.get("max_results_per_query", 50)

            for code_result in results:
                if processed >= max_results:
                    break

                try:
                    time.sleep(self.config.get("rate_limit_delay", 2))

                    file_content = code_result.repository.get_contents(code_result.path)
                    content = self._decode_file_content(file_content)

                    if content:
                        file_findings = self._analyze_content(
                            content,
                            code_result.html_url,
                            code_result.name
                        )

                        for finding in file_findings:
                            finding_id = self.db.insert_finding(finding)
                            finding["id"] = finding_id
                            findings.append(finding)
                            self.findings_count += 1

                            logger.warning(
                                f"[OSSiqn FIND] {finding['severity'].upper()} | "
                                f"{finding['title']} | {finding['url']}"
                            )

                    processed += 1

                except RateLimitExceededException:
                    logger.warning("[OSSiqn Scanner] Rate limit hit, waiting...")
                    self._wait_for_rate_limit()

                except GithubException as e:
                    if e.status != 403:
                        logger.error(f"[OSSiqn Scanner] GitHub API error: {e}")
                    continue

                except Exception as e:
                    logger.error(f"[OSSiqn Scanner] Error processing file: {e}")
                    continue

            self.db.add_scan_history(
                scan_type="github_code_search",
                query=query,
                results_count=len(findings),
                duration=0
            )

        except RateLimitExceededException:
            logger.warning(f"[OSSiqn Scanner] Rate limit exceeded for query: {query}")
            self._wait_for_rate_limit()

        except Exception as e:
            logger.error(f"[OSSiqn Scanner] Unexpected error for query '{query}': {e}")

        return findings

    def scan_all_queries(self) -> List[Dict]:
        all_findings = []
        queries = self.config.get("search_queries", GITHUB_SEARCH_QUERIES)

        logger.info(f"[OSSiqn Scanner] Starting full GitHub scan — {len(queries)} queries")

        for i, query in enumerate(queries, 1):
            logger.info(f"[OSSiqn Scanner] Query {i}/{len(queries)}: {query}")
            query_findings = self.scan_query(query)
            all_findings.extend(query_findings)
            time.sleep(self.config.get("rate_limit_delay", 2))

        logger.info(f"[OSSiqn Scanner] Full scan complete. Total findings: {len(all_findings)}")
        return all_findings

    def scan_repository(self, repo_name: str) -> List[Dict]:
        findings = []
        logger.info(f"[OSSiqn Scanner] Deep scanning repository: {repo_name}")

        sensitive_extensions = [
            '.env', '.yml', '.yaml', '.json', '.xml', '.conf',
            '.cfg', '.ini', '.properties', '.toml', '.py',
            '.js', '.ts', '.rb', '.php', '.go', '.java',
            '.cs', '.cpp', '.sh', '.bash', '.zsh'
        ]

        try:
            repo = self.github.get_repo(repo_name)
            contents = repo.get_contents("")
            files_to_check = []

            while contents:
                file_content = contents.pop(0)
                if file_content.type == "dir":
                    try:
                        contents.extend(repo.get_contents(file_content.path))
                    except GithubException:
                        pass
                else:
                    if any(file_content.name.endswith(ext) for ext in sensitive_extensions):
                        files_to_check.append(file_content)
                if len(files_to_check) > 200:
                    break

            for file_obj in files_to_check:
                try:
                    time.sleep(0.5)
                    full_content = repo.get_contents(file_obj.path)
                    content = self._decode_file_content(full_content)
                    if content:
                        file_findings = self._analyze_content(content, file_obj.html_url, file_obj.name)
                        for finding in file_findings:
                            finding_id = self.db.insert_finding(finding)
                            finding["id"] = finding_id
                            findings.append(finding)
                except Exception as e:
                    logger.error(f"[OSSiqn Scanner] Error scanning {file_obj.path}: {e}")
                    continue

        except Exception as e:
            logger.error(f"[OSSiqn Scanner] Error accessing repo {repo_name}: {e}")

        return findings