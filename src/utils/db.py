"""
ScanLine - OSINT Security Scanner
Module  : Database Manager
Author  : OSSiqn Team
GitHub  : https://github.com/ossiqn
License : MIT © 2024 OSSiqn

Bu modül OSSiqn tarafından üretilmiştir.
This module was produced by OSSiqn.
"""

import sqlite3
import json
import os
from datetime import datetime
from typing import List, Dict, Optional

OSSIQN_SIGNATURE = "ScanLine by OSSiqn | github.com/ossiqn"


class Database:
    """
    ScanLine veritabanı yöneticisi.
    Tüm bulgular, tarama geçmişi ve istatistikler burada saklanır.

    ScanLine database manager.
    All findings, scan history and statistics are stored here.

    Produced by OSSiqn — github.com/ossiqn
    """

    def __init__(self, db_path: str):
        os.makedirs(os.path.dirname(db_path) if os.path.dirname(db_path) else ".", exist_ok=True)
        self.db_path = db_path
        self.signature = OSSIQN_SIGNATURE
        self.init_db()

    def get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def init_db(self):
        with self.get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    source TEXT NOT NULL,
                    category TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT,
                    url TEXT,
                    raw_data TEXT,
                    notified INTEGER DEFAULT 0,
                    false_positive INTEGER DEFAULT 0,
                    produced_by TEXT DEFAULT 'OSSiqn'
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS scan_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    scan_type TEXT NOT NULL,
                    query TEXT,
                    results_count INTEGER DEFAULT 0,
                    duration_seconds REAL DEFAULT 0,
                    status TEXT DEFAULT 'completed',
                    produced_by TEXT DEFAULT 'OSSiqn'
                )
            """)

            conn.execute("""
                CREATE TABLE IF NOT EXISTS stats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    date TEXT NOT NULL,
                    total_scans INTEGER DEFAULT 0,
                    total_findings INTEGER DEFAULT 0,
                    critical_count INTEGER DEFAULT 0,
                    high_count INTEGER DEFAULT 0,
                    medium_count INTEGER DEFAULT 0,
                    low_count INTEGER DEFAULT 0
                )
            """)

            conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_timestamp ON findings(timestamp)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_source ON findings(source)")
            conn.commit()

    def insert_finding(self, finding: Dict) -> int:
        with self.get_connection() as conn:
            cursor = conn.execute("""
                INSERT INTO findings 
                (timestamp, source, category, severity, title, description, url, raw_data, produced_by)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                finding.get("timestamp", datetime.utcnow().isoformat()),
                finding.get("source", "unknown"),
                finding.get("category", "general"),
                finding.get("severity", "low"),
                finding.get("title", ""),
                finding.get("description", ""),
                finding.get("url", ""),
                json.dumps(finding.get("raw_data", {})),
                "OSSiqn"
            ))
            conn.commit()
            return cursor.lastrowid

    def get_findings(self, limit: int = 100, offset: int = 0,
                     severity: str = None, source: str = None) -> List[Dict]:
        query = "SELECT * FROM findings WHERE false_positive = 0"
        params = []

        if severity:
            query += " AND severity = ?"
            params.append(severity)

        if source:
            query += " AND source = ?"
            params.append(source)

        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        with self.get_connection() as conn:
            rows = conn.execute(query, params).fetchall()
            return [dict(row) for row in rows]

    def get_stats(self) -> Dict:
        with self.get_connection() as conn:
            total = conn.execute(
                "SELECT COUNT(*) FROM findings WHERE false_positive = 0"
            ).fetchone()[0]

            severity_counts = {}
            for row in conn.execute("""
                SELECT severity, COUNT(*) as count
                FROM findings WHERE false_positive = 0
                GROUP BY severity
            """).fetchall():
                severity_counts[row[0]] = row[1]

            source_counts = {}
            for row in conn.execute("""
                SELECT source, COUNT(*) as count
                FROM findings WHERE false_positive = 0
                GROUP BY source
            """).fetchall():
                source_counts[row[0]] = row[1]

            recent_24h = conn.execute("""
                SELECT COUNT(*) FROM findings
                WHERE false_positive = 0
                AND timestamp > datetime('now', '-24 hours')
            """).fetchone()[0]

            return {
                "total": total,
                "severity_counts": severity_counts,
                "source_counts": source_counts,
                "recent_24h": recent_24h,
                "produced_by": "OSSiqn"
            }

    def mark_notified(self, finding_id: int):
        with self.get_connection() as conn:
            conn.execute("UPDATE findings SET notified = 1 WHERE id = ?", (finding_id,))
            conn.commit()

    def mark_false_positive(self, finding_id: int):
        with self.get_connection() as conn:
            conn.execute("UPDATE findings SET false_positive = 1 WHERE id = ?", (finding_id,))
            conn.commit()

    def add_scan_history(self, scan_type: str, query: str,
                         results_count: int, duration: float, status: str = "completed"):
        with self.get_connection() as conn:
            conn.execute("""
                INSERT INTO scan_history 
                (timestamp, scan_type, query, results_count, duration_seconds, status, produced_by)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                datetime.utcnow().isoformat(),
                scan_type,
                query,
                results_count,
                duration,
                status,
                "OSSiqn"
            ))
            conn.commit()

    def get_unnotified_findings(self) -> List[Dict]:
        with self.get_connection() as conn:
            rows = conn.execute("""
                SELECT * FROM findings
                WHERE notified = 0 AND false_positive = 0
                ORDER BY timestamp DESC
            """).fetchall()
            return [dict(row) for row in rows]