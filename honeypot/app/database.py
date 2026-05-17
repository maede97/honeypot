import os
import sqlite3
import threading
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta

class Database:
    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute("PRAGMA synchronous=NORMAL;")

    def initialize(self) -> None:
        with self._lock:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TEXT NOT NULL,
                    method TEXT NOT NULL,
                    path TEXT NOT NULL,
                    query_string TEXT NOT NULL,
                    client_ip TEXT,
                    user_agent TEXT,
                    body_size INTEGER NOT NULL,
                    headers_json TEXT NOT NULL DEFAULT '{}'
                );
                """
            )

            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_scans_ts ON scans(ts);"
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_scans_path ON scans(path);"
            )

            scan_columns = self._conn.execute("PRAGMA table_info(scans);").fetchall()
            has_body_text = any(str(row["name"]) == "body_text" for row in scan_columns)
            if not has_body_text:
                self._conn.execute(
                    "ALTER TABLE scans ADD COLUMN body_text TEXT NOT NULL DEFAULT ''"
                )

            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS scan_daily_method_counts (
                    day TEXT NOT NULL,
                    method TEXT NOT NULL,
                    hits INTEGER NOT NULL,
                    PRIMARY KEY (day, method)
                );
                """
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_scan_daily_method_day ON scan_daily_method_counts(day);"
            )
            self._conn.commit()

    def log_scan(
        self,
        method: str,
        path: str,
        query_string: str,
        client_ip: str | None,
        user_agent: str | None,
        body_size: int,
        body_text: str,
        headers_json: str,
    ) -> None:
        timestamp = datetime.utcnow().isoformat(timespec="seconds")
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO scans(
                    ts,
                    method,
                    path,
                    query_string,
                    client_ip,
                    user_agent,
                    body_size,
                    body_text,
                    headers_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    timestamp,
                    method,
                    path,
                    query_string,
                    client_ip,
                    user_agent,
                    body_size,
                    body_text,
                    headers_json,
                ),
            )
            self._conn.commit()

    def rollup_and_prune_old_scans(self, retention_days: int) -> tuple[int, int]:
        if retention_days < 1:
            raise ValueError("retention_days must be >= 1")

        cutoff = (datetime.utcnow() - timedelta(days=retention_days)).isoformat(timespec="seconds")

        with self._lock:
            self._conn.execute("BEGIN")
            try:
                archived_rows = self._conn.execute(
                    """
                    SELECT substr(ts, 1, 10) AS day, method, COUNT(*) AS cnt
                    FROM scans
                    WHERE ts < ?
                    GROUP BY day, method
                    """,
                    (cutoff,),
                ).fetchall()

                for row in archived_rows:
                    self._conn.execute(
                        """
                        INSERT INTO scan_daily_method_counts(day, method, hits)
                        VALUES (?, ?, ?)
                        ON CONFLICT(day, method) DO UPDATE SET hits = hits + excluded.hits
                        """,
                        (str(row["day"]), str(row["method"]), int(row["cnt"])),
                    )

                deleted_rows = self._conn.execute(
                    "DELETE FROM scans WHERE ts < ?",
                    (cutoff,),
                ).rowcount

                self._conn.commit()
                return int(len(archived_rows)), int(deleted_rows)
            except Exception:
                self._conn.rollback()
                raise


def db_from_env() -> Database:
    db_path = os.getenv("HONEYPOT_DB_PATH", "/data/honeypot.db")
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    return Database(db_path)
