import json
import os
import sqlite3
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

import httpx
from jinja2 import StrictUndefined
from jinja2.sandbox import SandboxedEnvironment


ALLOWED_FILTER_FIELDS = {
    "path": "path",
    "client_ip": "client_ip",
    "user_agent": "user_agent",
    "query_string": "query_string",
    "body_text": "body_text",
}
ALLOWED_HTTP_METHODS = {"", "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
ALLOWED_FILTER_OPERATORS = {"equals", "contains"}


@dataclass
class WebhookRow:
    id: int
    name: str
    target_url: str
    enabled: bool
    interval_seconds: int
    filter_method: str
    body_size_gt_zero: bool
    burst_packets: int
    burst_window_seconds: int
    filter_field: str
    filter_operator: str
    filter_value: str
    payload_template: str
    last_scan_id: int
    last_run_at: str | None
    last_response_status: int | None
    last_error: str | None
    created_at: str
    updated_at: str


def _utc_now_iso() -> str:
    return datetime.utcnow().isoformat(timespec="seconds")


def _parse_iso_or_none(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


class WebhookStore:
    def __init__(self, db_path: str) -> None:
        self._db_path = db_path
        self._lock = threading.Lock()
        parent = os.path.dirname(db_path)
        if parent:
            os.makedirs(parent, exist_ok=True)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    def initialize(self) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS webhooks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    target_url TEXT NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    interval_seconds INTEGER NOT NULL,
                    filter_method TEXT NOT NULL DEFAULT '',
                    body_size_gt_zero INTEGER NOT NULL DEFAULT 0,
                    burst_packets INTEGER NOT NULL DEFAULT 0,
                    burst_window_seconds INTEGER NOT NULL DEFAULT 0,
                    filter_field TEXT NOT NULL DEFAULT '',
                    filter_operator TEXT NOT NULL DEFAULT 'equals',
                    filter_value TEXT NOT NULL DEFAULT '',
                    payload_template TEXT NOT NULL,
                    last_scan_id INTEGER NOT NULL DEFAULT 0,
                    last_run_at TEXT,
                    last_response_status INTEGER,
                    last_error TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_webhooks_enabled ON webhooks(enabled)")
            columns = conn.execute("PRAGMA table_info(webhooks)").fetchall()
            has_filter_method = any(str(row["name"]) == "filter_method" for row in columns)
            has_body_size_gt_zero = any(str(row["name"]) == "body_size_gt_zero" for row in columns)
            has_burst_packets = any(str(row["name"]) == "burst_packets" for row in columns)
            has_burst_window_seconds = any(str(row["name"]) == "burst_window_seconds" for row in columns)
            has_filter_operator = any(str(row["name"]) == "filter_operator" for row in columns)
            if not has_filter_method:
                conn.execute("ALTER TABLE webhooks ADD COLUMN filter_method TEXT NOT NULL DEFAULT ''")
            if not has_body_size_gt_zero:
                conn.execute("ALTER TABLE webhooks ADD COLUMN body_size_gt_zero INTEGER NOT NULL DEFAULT 0")
            if not has_burst_packets:
                conn.execute("ALTER TABLE webhooks ADD COLUMN burst_packets INTEGER NOT NULL DEFAULT 0")
            if not has_burst_window_seconds:
                conn.execute("ALTER TABLE webhooks ADD COLUMN burst_window_seconds INTEGER NOT NULL DEFAULT 0")
            if not has_filter_operator:
                conn.execute("ALTER TABLE webhooks ADD COLUMN filter_operator TEXT NOT NULL DEFAULT 'equals'")
            conn.commit()

    def _row_to_webhook(self, row: sqlite3.Row) -> WebhookRow:
        return WebhookRow(
            id=int(row["id"]),
            name=str(row["name"]),
            target_url=str(row["target_url"]),
            enabled=bool(row["enabled"]),
            interval_seconds=int(row["interval_seconds"]),
            filter_method=str(row["filter_method"]) if "filter_method" in row.keys() else "",
            body_size_gt_zero=bool(row["body_size_gt_zero"]) if "body_size_gt_zero" in row.keys() else False,
            burst_packets=int(row["burst_packets"]) if "burst_packets" in row.keys() else 0,
            burst_window_seconds=int(row["burst_window_seconds"]) if "burst_window_seconds" in row.keys() else 0,
            filter_field=str(row["filter_field"]),
            filter_operator=str(row["filter_operator"]) if "filter_operator" in row.keys() else "equals",
            filter_value=str(row["filter_value"]),
            payload_template=str(row["payload_template"]),
            last_scan_id=int(row["last_scan_id"]),
            last_run_at=str(row["last_run_at"]) if row["last_run_at"] else None,
            last_response_status=int(row["last_response_status"]) if row["last_response_status"] is not None else None,
            last_error=str(row["last_error"]) if row["last_error"] else None,
            created_at=str(row["created_at"]),
            updated_at=str(row["updated_at"]),
        )

    def list_webhooks(self) -> list[WebhookRow]:
        with self._lock, self._connect() as conn:
            rows = conn.execute(
                """
                  SELECT id, name, target_url, enabled, interval_seconds, filter_field, filter_value,
                                            filter_method, body_size_gt_zero, burst_packets, burst_window_seconds, filter_operator,
                       payload_template, last_scan_id, last_run_at, last_response_status, last_error,
                       created_at, updated_at
                FROM webhooks
                ORDER BY id ASC
                """
            ).fetchall()
        return [self._row_to_webhook(row) for row in rows]

    def get_webhook(self, webhook_id: int) -> WebhookRow | None:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                """
                  SELECT id, name, target_url, enabled, interval_seconds, filter_field, filter_value,
                                            filter_method, body_size_gt_zero, burst_packets, burst_window_seconds, filter_operator,
                       payload_template, last_scan_id, last_run_at, last_response_status, last_error,
                       created_at, updated_at
                FROM webhooks
                WHERE id = ?
                """,
                (webhook_id,),
            ).fetchone()
        if row is None:
            return None
        return self._row_to_webhook(row)

    def create_webhook(
        self,
        *,
        name: str,
        target_url: str,
        enabled: bool,
        interval_seconds: int,
        filter_method: str,
        body_size_gt_zero: bool,
        burst_packets: int,
        burst_window_seconds: int,
        filter_field: str,
        filter_operator: str,
        filter_value: str,
        payload_template: str,
    ) -> int:
        now = _utc_now_iso()
        with self._lock, self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO webhooks(
                    name,
                    target_url,
                    enabled,
                    interval_seconds,
                    filter_method,
                    body_size_gt_zero,
                    burst_packets,
                    burst_window_seconds,
                    filter_field,
                    filter_operator,
                    filter_value,
                    payload_template,
                    created_at,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    name,
                    target_url,
                    1 if enabled else 0,
                    interval_seconds,
                    filter_method,
                    1 if body_size_gt_zero else 0,
                    burst_packets,
                    burst_window_seconds,
                    filter_field,
                    filter_operator,
                    filter_value,
                    payload_template,
                    now,
                    now,
                ),
            )
            conn.commit()
            return int(cursor.lastrowid)

    def update_webhook(
        self,
        *,
        webhook_id: int,
        name: str,
        target_url: str,
        enabled: bool,
        interval_seconds: int,
        filter_method: str,
        body_size_gt_zero: bool,
        burst_packets: int,
        burst_window_seconds: int,
        filter_field: str,
        filter_operator: str,
        filter_value: str,
        payload_template: str,
    ) -> bool:
        now = _utc_now_iso()
        with self._lock, self._connect() as conn:
            updated = conn.execute(
                """
                UPDATE webhooks
                SET name = ?,
                    target_url = ?,
                    enabled = ?,
                    interval_seconds = ?,
                    filter_method = ?,
                    body_size_gt_zero = ?,
                    burst_packets = ?,
                    burst_window_seconds = ?,
                    filter_field = ?,
                    filter_operator = ?,
                    filter_value = ?,
                    payload_template = ?,
                    updated_at = ?
                WHERE id = ?
                """,
                (
                    name,
                    target_url,
                    1 if enabled else 0,
                    interval_seconds,
                    filter_method,
                    1 if body_size_gt_zero else 0,
                    burst_packets,
                    burst_window_seconds,
                    filter_field,
                    filter_operator,
                    filter_value,
                    payload_template,
                    now,
                    webhook_id,
                ),
            ).rowcount
            conn.commit()
            return bool(updated)

    def delete_webhook(self, webhook_id: int) -> bool:
        with self._lock, self._connect() as conn:
            deleted = conn.execute("DELETE FROM webhooks WHERE id = ?", (webhook_id,)).rowcount
            conn.commit()
            return bool(deleted)

    def mark_result(
        self,
        *,
        webhook_id: int,
        last_scan_id: int,
        response_status: int | None,
        error: str | None,
    ) -> None:
        now = _utc_now_iso()
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                UPDATE webhooks
                SET last_scan_id = ?,
                    last_response_status = ?,
                    last_error = ?,
                    last_run_at = ?,
                    updated_at = ?
                WHERE id = ?
                """,
                (
                    last_scan_id,
                    response_status,
                    error,
                    now,
                    now,
                    webhook_id,
                ),
            )
            conn.commit()


class WebhookDispatcher:
    def __init__(self, *, honeypot_db_path: str, store: WebhookStore) -> None:
        self._store = store
        self._honeypot_db_uri = f"file:{honeypot_db_path}?mode=ro"
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._jinja = SandboxedEnvironment(undefined=StrictUndefined, autoescape=False)
        self._jinja.filters["tojson"] = lambda value: json.dumps(value, ensure_ascii=True)

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run_loop, daemon=True, name="webhook-dispatcher")
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=3)

    def _run_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                self._tick()
            except Exception:
                # Keep the background worker alive even if one run fails unexpectedly.
                pass
            self._stop_event.wait(1.0)

    def _is_due(self, webhook: WebhookRow, now: datetime) -> bool:
        last_run = _parse_iso_or_none(webhook.last_run_at)
        if last_run is None:
            return True
        due_at = last_run + timedelta(seconds=webhook.interval_seconds)
        return now >= due_at

    def _tick(self) -> None:
        now = datetime.utcnow()
        for webhook in self._store.list_webhooks():
            if not webhook.enabled or not self._is_due(webhook, now):
                continue

            scan = self._select_latest_scan(
                after_scan_id=webhook.last_scan_id,
                filter_method=webhook.filter_method,
                body_size_gt_zero=webhook.body_size_gt_zero,
                burst_packets=webhook.burst_packets,
                burst_window_seconds=webhook.burst_window_seconds,
                filter_field=webhook.filter_field,
                filter_operator=webhook.filter_operator,
                filter_value=webhook.filter_value,
            )

            if scan is None:
                self._store.mark_result(
                    webhook_id=webhook.id,
                    last_scan_id=webhook.last_scan_id,
                    response_status=None,
                    error=None,
                )
                continue

            response_status: int | None = None
            error: str | None = None
            try:
                payload = self._render_payload(webhook=webhook, scan=scan)
                with httpx.Client(timeout=10.0) as client:
                    response = client.post(webhook.target_url, json=payload)
                    response_status = int(response.status_code)
                    response.raise_for_status()
            except Exception as exc:
                error = str(exc)[:500]

            self._store.mark_result(
                webhook_id=webhook.id,
                last_scan_id=int(scan["id"]),
                response_status=response_status,
                error=error,
            )

    def send_test_notification(
        self,
        *,
        name: str,
        target_url: str,
        payload_template: str,
        filter_method: str,
        body_size_gt_zero: bool,
        burst_packets: int,
        burst_window_seconds: int,
        filter_field: str,
        filter_operator: str,
        filter_value: str,
    ) -> dict[str, Any]:
        preview = self.preview_notification(
            name=name,
            payload_template=payload_template,
            filter_method=filter_method,
            body_size_gt_zero=body_size_gt_zero,
            burst_packets=burst_packets,
            burst_window_seconds=burst_window_seconds,
            filter_field=filter_field,
            filter_operator=filter_operator,
            filter_value=filter_value,
        )
        if not preview.get("ok"):
            return preview

        scan = preview.get("scan")
        payload = preview.get("payload")
        if not isinstance(scan, dict) or payload is None:
            return {
                "ok": False,
                "reason": "preview_failed",
                "message": "Could not build payload preview.",
            }

        response_status: int | None = None
        error: str | None = None
        try:
            with httpx.Client(timeout=10.0) as client:
                response = client.post(target_url, json=payload)
                response_status = int(response.status_code)
                response.raise_for_status()
        except Exception as exc:
            error = str(exc)[:500]

        if error:
            return {
                "ok": False,
                "reason": "delivery_failed",
                "message": error,
                "response_status": response_status,
                "scan": {
                    "id": int(scan["id"]),
                    "ts": str(scan["ts"]),
                    "method": str(scan["method"]),
                    "path": str(scan["path"]),
                },
                "payload": payload,
            }

        return {
            "ok": True,
            "message": "Test notification sent.",
            "response_status": response_status,
            "scan": {
                "id": int(scan["id"]),
                "ts": str(scan["ts"]),
                "method": str(scan["method"]),
                "path": str(scan["path"]),
            },
            "payload": payload,
        }

    def preview_notification(
        self,
        *,
        name: str,
        payload_template: str,
        filter_method: str,
        body_size_gt_zero: bool,
        burst_packets: int,
        burst_window_seconds: int,
        filter_field: str,
        filter_operator: str,
        filter_value: str,
    ) -> dict[str, Any]:
        scan = self._select_latest_scan(
            after_scan_id=0,
            filter_method=filter_method,
            body_size_gt_zero=body_size_gt_zero,
            burst_packets=burst_packets,
            burst_window_seconds=burst_window_seconds,
            filter_field=filter_field,
            filter_operator=filter_operator,
            filter_value=filter_value,
        )
        if scan is None:
            return {
                "ok": False,
                "reason": "no_matching_scan",
                "message": "No scan matches the configured filters.",
            }

        try:
            payload = self._render_payload_from_values(
                payload_template=payload_template,
                webhook_id=0,
                webhook_name=name,
                scan=scan,
            )
        except Exception as exc:
            return {
                "ok": False,
                "reason": "render_failed",
                "message": str(exc)[:500],
                "scan": {
                    "id": int(scan["id"]),
                    "ts": str(scan["ts"]),
                    "method": str(scan["method"]),
                    "path": str(scan["path"]),
                },
            }

        return {
            "ok": True,
            "message": "Preview generated.",
            "scan": {
                "id": int(scan["id"]),
                "ts": str(scan["ts"]),
                "method": str(scan["method"]),
                "path": str(scan["path"]),
            },
            "payload": payload,
        }

    def _connect_honeypot(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._honeypot_db_uri, uri=True)
        conn.row_factory = sqlite3.Row
        return conn

    def _select_latest_scan(
        self,
        *,
        after_scan_id: int,
        filter_method: str,
        body_size_gt_zero: bool,
        burst_packets: int,
        burst_window_seconds: int,
        filter_field: str,
        filter_operator: str,
        filter_value: str,
    ) -> dict[str, Any] | None:
        where_parts = ["id > ?"]
        params: list[Any] = [after_scan_id]

        method_value = filter_method.strip().upper()
        if method_value and method_value in ALLOWED_HTTP_METHODS:
            where_parts.append("method = ?")
            params.append(method_value)

        if body_size_gt_zero:
            where_parts.append("body_size > 0")

        db_field = ALLOWED_FILTER_FIELDS.get(filter_field, "")
        filter_value_clean = filter_value.strip()
        if db_field and filter_value_clean:
            operator = filter_operator if filter_operator in ALLOWED_FILTER_OPERATORS else "equals"
            if operator == "contains":
                where_parts.append(f"COALESCE({db_field}, '') LIKE ?")
                params.append(f"%{filter_value_clean}%")
            else:
                where_parts.append(f"COALESCE({db_field}, '') = ?")
                params.append(filter_value_clean)

        where_sql = " AND ".join(where_parts)

        normalized_burst_packets = max(0, int(burst_packets))
        normalized_burst_window = max(0, int(burst_window_seconds))
        burst_enabled = normalized_burst_packets > 0 and normalized_burst_window > 0

        with self._connect_honeypot() as conn:
            try:
                rows = conn.execute(
                    (
                        "SELECT id, ts, method, path, query_string, client_ip, user_agent, "
                        "body_size, body_text, headers_json "
                        f"FROM scans WHERE {where_sql} ORDER BY id DESC LIMIT 250"
                    ),
                    params,
                ).fetchall()
            except sqlite3.OperationalError:
                rows = conn.execute(
                    (
                        "SELECT id, ts, method, path, query_string, client_ip, user_agent, body_size "
                        f"FROM scans WHERE {where_sql} ORDER BY id DESC LIMIT 250"
                    ),
                    params,
                ).fetchall()

            row = None
            for candidate in rows:
                if burst_enabled and not self._matches_burst_condition(
                    conn,
                    row=candidate,
                    burst_packets=normalized_burst_packets,
                    burst_window_seconds=normalized_burst_window,
                ):
                    continue
                row = candidate
                break

        if row is None:
            return None

        headers: dict[str, str]
        if "headers_json" in row.keys() and row["headers_json"]:
            try:
                parsed = json.loads(str(row["headers_json"]))
                headers = parsed if isinstance(parsed, dict) else {}
            except Exception:
                headers = {}
        else:
            headers = {}

        return {
            "id": int(row["id"]),
            "ts": str(row["ts"]),
            "method": str(row["method"]),
            "path": str(row["path"]),
            "query_string": str(row["query_string"]),
            "client_ip": str(row["client_ip"]) if row["client_ip"] else "",
            "user_agent": str(row["user_agent"]) if row["user_agent"] else "",
            "body_size": int(row["body_size"]),
            "body_text": str(row["body_text"]) if "body_text" in row.keys() and row["body_text"] else "",
            "headers": headers,
            "url": (
                f"{str(row['path'])}?{str(row['query_string'])}"
                if row["query_string"]
                else str(row["path"])
            ),
        }

    def _matches_burst_condition(
        self,
        conn: sqlite3.Connection,
        *,
        row: sqlite3.Row,
        burst_packets: int,
        burst_window_seconds: int,
    ) -> bool:
        client_ip = str(row["client_ip"]) if row["client_ip"] else ""
        if not client_ip:
            return False

        ts_text = str(row["ts"])
        try:
            ts_dt = datetime.fromisoformat(ts_text)
        except ValueError:
            return False

        window_start = (ts_dt - timedelta(seconds=burst_window_seconds)).isoformat(timespec="seconds")
        count_row = conn.execute(
            """
            SELECT COUNT(*) AS cnt
            FROM scans
            WHERE client_ip = ?
              AND ts >= ?
              AND ts <= ?
            """,
            (client_ip, window_start, ts_text),
        ).fetchone()
        count = int(count_row["cnt"]) if count_row else 0
        return count >= burst_packets

    def _render_payload(self, *, webhook: WebhookRow, scan: dict[str, Any]) -> Any:
        return self._render_payload_from_values(
            payload_template=webhook.payload_template,
            webhook_id=webhook.id,
            webhook_name=webhook.name,
            scan=scan,
        )

    def _render_payload_from_values(
        self,
        *,
        payload_template: str,
        webhook_id: int,
        webhook_name: str,
        scan: dict[str, Any],
    ) -> Any:
        template = self._jinja.from_string(payload_template)
        rendered = template.render(
            scan=scan,
            now=_utc_now_iso(),
            webhook={"id": webhook_id, "name": webhook_name},
        )
        return json.loads(rendered)
