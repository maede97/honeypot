import json
import sqlite3
from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta


@dataclass
class ScanRow:
    id: int
    ts: str
    method: str
    path: str
    query_string: str
    client_ip: str | None
    user_agent: str | None
    body_size: int


class Database:
    def __init__(self, db_path: str) -> None:
        self._uri = f"file:{db_path}?mode=ro"

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._uri, uri=True)
        conn.row_factory = sqlite3.Row
        return conn

    def list_scans(
        self,
        *,
        page: int,
        page_size: int,
        path_filter: str,
        ip_filter: str,
        method_filter: str,
        from_ts: str,
        to_ts: str,
        sort_by: str,
        sort_dir: str,
    ) -> tuple[Sequence[ScanRow], int]:
        where = []
        params: list[str] = []

        if path_filter:
            where.append("path LIKE ?")
            params.append(f"%{path_filter}%")
        if ip_filter:
            where.append("COALESCE(client_ip, '') LIKE ?")
            params.append(f"%{ip_filter}%")
        if method_filter:
            where.append("method = ?")
            params.append(method_filter.upper())
        if from_ts:
            where.append("ts >= ?")
            params.append(from_ts)
        if to_ts:
            where.append("ts <= ?")
            params.append(to_ts)

        where_sql = ""
        if where:
            where_sql = "WHERE " + " AND ".join(where)

        order_map = {
            "ts": "ts",
            "method": "method",
            "path": "path",
            "ip": "COALESCE(client_ip, '')",
            "ua": "COALESCE(user_agent, '')",
            "body": "body_size",
        }
        order_column = order_map.get(sort_by, "ts")
        direction = "ASC" if sort_dir.lower() == "asc" else "DESC"
        if order_column == "ts":
            order_sql = f"{order_column} {direction}, id {direction}"
        else:
            order_sql = f"{order_column} {direction}, ts DESC, id DESC"

        offset = (page - 1) * page_size

        with self._connect() as conn:
            total_row = conn.execute(
                f"SELECT COUNT(*) AS cnt FROM scans {where_sql}",
                params,
            ).fetchone()
            rows = conn.execute(
                f"""
                SELECT id, ts, method, path, query_string, client_ip, user_agent, body_size
                FROM scans
                {where_sql}
                ORDER BY {order_sql}
                LIMIT ? OFFSET ?
                """,
                [*params, page_size, offset],
            ).fetchall()

        scans = [
            ScanRow(
                id=int(r["id"]),
                ts=str(r["ts"]),
                method=str(r["method"]),
                path=str(r["path"]),
                query_string=str(r["query_string"]),
                client_ip=str(r["client_ip"]) if r["client_ip"] else None,
                user_agent=str(r["user_agent"]) if r["user_agent"] else None,
                body_size=int(r["body_size"]),
            )
            for r in rows
        ]

        return scans, int(total_row["cnt"] if total_row else 0)

    def get_scan(self, scan_id: int) -> dict | None:
        with self._connect() as conn:
            try:
                row = conn.execute(
                    """
                    SELECT id, ts, method, path, query_string, client_ip, user_agent, body_size, body_text, headers_json
                    FROM scans
                    WHERE id = ?
                    """,
                    (scan_id,),
                ).fetchone()
            except sqlite3.OperationalError:
                row = conn.execute(
                    """
                    SELECT id, ts, method, path, query_string, client_ip, user_agent, body_size, headers_json
                    FROM scans
                    WHERE id = ?
                    """,
                    (scan_id,),
                ).fetchone()

        if row is None:
            return None

        headers: dict[str, str]
        try:
            headers = json.loads(row["headers_json"])
        except Exception:
            headers = {}

        return {
            "id": int(row["id"]),
            "ts": str(row["ts"]),
            "method": str(row["method"]),
            "path": str(row["path"]),
            "query_string": str(row["query_string"]),
            "client_ip": str(row["client_ip"]) if row["client_ip"] else None,
            "user_agent": str(row["user_agent"]) if row["user_agent"] else None,
            "body_size": int(row["body_size"]),
            "body_text": str(row["body_text"]) if "body_text" in row.keys() else "",
            "headers": headers,
        }

    def dashboard_stats(self) -> dict:
        since = (datetime.utcnow() - timedelta(hours=24)).isoformat(timespec="seconds")

        with self._connect() as conn:
            last_24h = conn.execute(
                "SELECT COUNT(*) AS cnt FROM scans WHERE ts >= ?",
                (since,),
            ).fetchone()
            unique_paths = conn.execute(
                "SELECT COUNT(DISTINCT path) AS cnt FROM scans"
            ).fetchone()
            top_paths = conn.execute(
                """
                SELECT path, COUNT(*) AS cnt
                FROM scans
                GROUP BY path
                ORDER BY cnt DESC, path ASC
                LIMIT 10
                """
            ).fetchall()
            daily_buckets = conn.execute(
                """
                SELECT substr(ts, 1, 10) AS day, COUNT(*) AS cnt
                FROM scans
                GROUP BY day
                ORDER BY day DESC
                LIMIT 84
                """
            ).fetchall()

            recent_methods = conn.execute(
                """
                SELECT method, COUNT(*) AS cnt
                FROM scans
                GROUP BY method
                """
            ).fetchall()

            rolled_daily: Sequence[sqlite3.Row] = []
            rolled_methods: Sequence[sqlite3.Row] = []
            try:
                rolled_daily = conn.execute(
                    """
                    SELECT day, SUM(hits) AS cnt
                    FROM scan_daily_method_counts
                    GROUP BY day
                    """
                ).fetchall()
                rolled_methods = conn.execute(
                    """
                    SELECT method, SUM(hits) AS cnt
                    FROM scan_daily_method_counts
                    GROUP BY method
                    """
                ).fetchall()
            except sqlite3.OperationalError:
                # Older databases do not have rollup tables until honeypot migrates.
                pass

        daily_counts: dict[str, int] = defaultdict(int)
        for row in rolled_daily:
            daily_counts[str(row["day"])] += int(row["cnt"])
        for row in daily_buckets:
            daily_counts[str(row["day"])] += int(row["cnt"])

        method_counts: dict[str, int] = defaultdict(int)
        for row in rolled_methods:
            method_counts[str(row["method"])] += int(row["cnt"])
        for row in recent_methods:
            method_counts[str(row["method"])] += int(row["cnt"])

        total = sum(method_counts.values())
        sorted_daily = sorted(daily_counts.items(), key=lambda item: item[0])

        return {
            "total": int(total),
            "last_24h": int(last_24h["cnt"] if last_24h else 0),
            "unique_paths": int(unique_paths["cnt"] if unique_paths else 0),
            "top_paths": [{"path": str(r["path"]), "count": int(r["cnt"])} for r in top_paths],
            "daily": [
                {"day": str(day), "count": int(count)}
                for day, count in sorted_daily
            ],
            "method_counts": [
                {"method": method, "count": count}
                for method, count in sorted(method_counts.items(), key=lambda item: (-item[1], item[0]))
            ],
        }
