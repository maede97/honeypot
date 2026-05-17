import logging
import os
import json
from datetime import datetime

from apscheduler.schedulers.background import BackgroundScheduler
from fastapi import FastAPI, Header, HTTPException, Request

from .database import Database, db_from_env

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
LOGGER = logging.getLogger("honeypot")

MAX_BODY_LOG_BYTES = int(os.getenv("MAX_BODY_LOG_BYTES", "16384"))
RETENTION_DAYS = int(os.getenv("RETENTION_DAYS", "7"))
RETENTION_SCHEDULE_HOUR = int(os.getenv("RETENTION_SCHEDULE_HOUR", "0"))
RETENTION_SCHEDULE_MINUTE = int(os.getenv("RETENTION_SCHEDULE_MINUTE", "30"))

app = FastAPI(
    title="vps-control",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)
_db: Database | None = None
_scheduler: BackgroundScheduler | None = None

def _safe_body_size(body: bytes) -> int:
    if len(body) <= MAX_BODY_LOG_BYTES:
        return len(body)
    return MAX_BODY_LOG_BYTES


def _extract_body_text(body: bytes) -> str:
    if not body:
        return ""

    clipped = body[:MAX_BODY_LOG_BYTES]
    decoded = clipped.decode("utf-8", errors="replace")
    if len(body) > MAX_BODY_LOG_BYTES:
        return f"{decoded}\n...[truncated]"
    return decoded


def _extract_client_ip(request: Request) -> str | None:
    cf_connecting_ip = request.headers.get("cf-connecting-ip", "")
    if cf_connecting_ip:
        return cf_connecting_ip

    return request.client.host if request.client else None


def _run_retention_job() -> None:
    if _db is None:
        LOGGER.error("retention_job_skipped reason=no_db")
        return

    try:
        archived_groups, deleted_rows = _db.rollup_and_prune_old_scans(RETENTION_DAYS)
    except Exception as exc:
        LOGGER.exception("retention_job_failed error=%s", exc)
    else:
        LOGGER.info(
            "retention_job_done retention_days=%s archived_groups=%s deleted_rows=%s",
            RETENTION_DAYS,
            archived_groups,
            deleted_rows,
        )


@app.on_event("startup")
def startup_event() -> None:
    global _db
    global _scheduler

    _db = db_from_env()
    _db.initialize()
    _run_retention_job()

    _scheduler = BackgroundScheduler(timezone=None)
    _scheduler.add_job(
        _run_retention_job,
        trigger="cron",
        hour=RETENTION_SCHEDULE_HOUR,
        minute=RETENTION_SCHEDULE_MINUTE,
        id="daily-retention-prune",
        replace_existing=True,
    )
    _scheduler.start()

    LOGGER.info(
        "startup_retention retention_days=%s retention_schedule=%02d:%02d local",
        RETENTION_DAYS,
        RETENTION_SCHEDULE_HOUR,
        RETENTION_SCHEDULE_MINUTE,
    )


@app.on_event("shutdown")
def shutdown_event() -> None:
    if _scheduler is not None:
        _scheduler.shutdown(wait=False)


@app.middleware("http")
async def log_all_requests(request: Request, call_next):
    if _db is None:
        return await call_next(request)

    body = await request.body()
    body_size = _safe_body_size(body)
    body_text = _extract_body_text(body)

    client_ip = _extract_client_ip(request)
    user_agent = request.headers.get("user-agent")
    headers_json = json.dumps(dict(request.headers.items()), separators=(",", ":"))

    _db.log_scan(
        method=request.method,
        path=request.url.path,
        query_string=request.url.query,
        client_ip=client_ip,
        user_agent=user_agent,
        body_size=body_size,
        body_text=body_text,
        headers_json=headers_json,
    )

    LOGGER.info(
        "scan method=%s path=%s query=%s ip=%s ua=%s body_size=%s",
        request.method,
        request.url.path,
        request.url.query,
        client_ip,
        user_agent,
        body_size,
    )

    return await call_next(request)


@app.api_route("/{full_path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
async def catch_all(full_path: str, request: Request) -> dict[str, str]:
    # Return a plain response to look like an ordinary HTTP target.
    return {"status": "ok", "path": f"/{full_path}", "method": request.method}
