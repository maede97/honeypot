import os
from contextlib import asynccontextmanager
from functools import wraps

import bcrypt
from fastapi import FastAPI, Form, HTTPException, Query, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from .database import Database
from .webhooks import (
    ALLOWED_FILTER_FIELDS,
    ALLOWED_FILTER_OPERATORS,
    ALLOWED_HTTP_METHODS,
    WebhookDispatcher,
    WebhookStore,
)

HONEYPOT_DB_PATH = os.getenv("HONEYPOT_DB_PATH", "/data/honeypot.db")
GUI_DB_PATH = os.getenv("GUI_DB_PATH", "/gui-data/gui.db")
GUI_ADMIN_USERNAME = os.getenv("GUI_ADMIN_USERNAME", "admin")
GUI_ADMIN_PASSWORD_BCRYPT = os.getenv("GUI_ADMIN_PASSWORD_BCRYPT", "")
GUI_SESSION_SECRET = os.getenv("GUI_SESSION_SECRET", "")

WEBHOOK_FILTER_FIELDS = ["", *ALLOWED_FILTER_FIELDS.keys()]
WEBHOOK_METHODS = ["", "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]
WEBHOOK_OPERATORS = ["equals", "contains"]

_db = Database(HONEYPOT_DB_PATH)
_webhook_store = WebhookStore(GUI_DB_PATH)
_webhook_dispatcher = WebhookDispatcher(honeypot_db_path=HONEYPOT_DB_PATH, store=_webhook_store)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    _webhook_store.initialize()
    _webhook_dispatcher.start()
    try:
        yield
    finally:
        _webhook_dispatcher.stop()

app = FastAPI(
    title="honeypot-gui",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    lifespan=lifespan,
)
app.mount("/public", StaticFiles(directory="app/public"), name="public")
app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")

if not GUI_SESSION_SECRET:
    raise RuntimeError("GUI_SESSION_SECRET must be configured")

if not GUI_ADMIN_PASSWORD_BCRYPT:
    raise RuntimeError("GUI_ADMIN_PASSWORD_BCRYPT must be configured")

app.add_middleware(
    SessionMiddleware,
    secret_key=GUI_SESSION_SECRET,
    same_site="lax",
    https_only=True,
)


def _is_authenticated(request: Request) -> bool:
    return bool(request.session.get("authenticated"))


def login_required(handler):
    @wraps(handler)
    async def wrapped(*args, **kwargs):
        request = kwargs.get("request")
        if request is None:
            for arg in args:
                if isinstance(arg, Request):
                    request = arg
                    break

        if request is None or not _is_authenticated(request):
            return RedirectResponse(url="/login", status_code=303)
        return await handler(*args, **kwargs)

    return wrapped


def _verify_password(submitted_password: str) -> bool:
    try:
        return bcrypt.checkpw(
            submitted_password.encode("utf-8"),
            GUI_ADMIN_PASSWORD_BCRYPT.encode("utf-8"),
        )
    except ValueError:
        return False


def _normalize_webhook_filter(
    filter_method: str,
    body_size_gt_zero: str,
    filter_field: str,
    filter_operator: str,
    filter_value: str,
) -> tuple[str, bool, str, str, str]:
    normalized_method = filter_method.strip().upper()
    normalized_body_size = body_size_gt_zero.strip().lower() == "on"
    normalized_field = filter_field.strip()
    normalized_operator = filter_operator.strip().lower()
    normalized_value = filter_value.strip()

    if normalized_method and normalized_method not in ALLOWED_HTTP_METHODS:
        raise HTTPException(status_code=400, detail="Unsupported HTTP method filter")

    if normalized_field and normalized_field not in ALLOWED_FILTER_FIELDS:
        raise HTTPException(status_code=400, detail="Unsupported filter field")

    if normalized_operator not in ALLOWED_FILTER_OPERATORS:
        raise HTTPException(status_code=400, detail="Unsupported filter operator")

    if not normalized_field:
        return normalized_method, normalized_body_size, "", normalized_operator, ""

    return normalized_method, normalized_body_size, normalized_field, normalized_operator, normalized_value


def _validate_webhook_interval(interval_seconds: int) -> int:
    if interval_seconds < 1:
        raise HTTPException(status_code=400, detail="interval_seconds must be >= 1")
    return interval_seconds


def _validate_webhook_payload_template(payload_template: str) -> str:
    candidate = payload_template.strip()
    if not candidate:
        raise HTTPException(status_code=400, detail="payload_template is required")
    return candidate


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/login")
def login_page(request: Request):
    if _is_authenticated(request):
        return RedirectResponse(url="/", status_code=303)
    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={"error": None},
    )


@app.post("/login")
def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    if username != GUI_ADMIN_USERNAME or not _verify_password(password):
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={"error": "Invalid credentials"},
            status_code=401,
        )

    request.session["authenticated"] = True
    request.session["username"] = username
    return RedirectResponse(url="/", status_code=303)


@app.post("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login", status_code=303)


@app.get("/")
@login_required
async def dashboard(request: Request):
    return templates.TemplateResponse(request=request, name="dashboard.html", context={})


@app.get("/scans")
@login_required
async def scans(
    request: Request,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=10, le=200),
    path: str = Query(default=""),
    ip: str = Query(default=""),
    method: str = Query(default=""),
    from_ts: str = Query(default=""),
    to_ts: str = Query(default=""),
    sort_by: str = Query(default="ts"),
    sort_dir: str = Query(default="desc"),
):
    method = method.upper().strip()
    if method and method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
        raise HTTPException(status_code=400, detail="Unsupported HTTP method filter")

    sort_by = sort_by.strip().lower()
    allowed_sort_by = {"ts", "method", "path", "ip", "ua", "body"}
    if sort_by not in allowed_sort_by:
        sort_by = "ts"

    sort_dir = sort_dir.strip().lower()
    if sort_dir not in {"asc", "desc"}:
        sort_dir = "desc"

    rows, total = _db.list_scans(
        page=page,
        page_size=page_size,
        path_filter=path.strip(),
        ip_filter=ip.strip(),
        method_filter=method,
        from_ts=from_ts.strip(),
        to_ts=to_ts.strip(),
        sort_by=sort_by,
        sort_dir=sort_dir,
    )

    pages = max((total + page_size - 1) // page_size, 1)
    return templates.TemplateResponse(
        request=request,
        name="scans.html",
        context={
            "rows": rows,
            "total": total,
            "page": page,
            "page_size": page_size,
            "pages": pages,
            "filters": {
                "path": path,
                "ip": ip,
                "method": method,
                "from_ts": from_ts,
                "to_ts": to_ts,
            },
            "sort": {
                "by": sort_by,
                "dir": sort_dir,
            },
        },
    )


@app.get("/scans/{scan_id}")
@login_required
async def scan_detail(request: Request, scan_id: int):
    scan = _db.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    return templates.TemplateResponse(
        request=request,
        name="scan_detail.html",
        context={"scan": scan},
    )


@app.get("/api/stats")
@login_required
async def stats_api(request: Request):
    _ = request
    return JSONResponse(content=_db.dashboard_stats())


@app.get("/webhooks")
@login_required
async def webhooks_page(request: Request, msg: str = Query(default="")):
    webhooks = _webhook_store.list_webhooks()
    preview_by_webhook = {
        webhook.id: _db.list_matching_scans(
            method_filter=webhook.filter_method,
            body_size_gt_zero=webhook.body_size_gt_zero,
            field_filter=webhook.filter_field,
            operator_filter=webhook.filter_operator,
            value_filter=webhook.filter_value,
            limit=8,
        )
        for webhook in webhooks
    }

    return templates.TemplateResponse(
        request=request,
        name="webhooks.html",
        context={
            "webhooks": webhooks,
            "preview_by_webhook": preview_by_webhook,
            "message": msg,
            "filter_fields": WEBHOOK_FILTER_FIELDS,
            "filter_methods": WEBHOOK_METHODS,
            "filter_operators": WEBHOOK_OPERATORS,
        },
    )


@app.post("/webhooks")
@login_required
async def webhooks_create(
    request: Request,
    name: str = Form(...),
    target_url: str = Form(...),
    interval_seconds: int = Form(...),
    filter_method: str = Form(default=""),
    body_size_gt_zero: str = Form(default="off"),
    filter_field: str = Form(default=""),
    filter_operator: str = Form(default="equals"),
    filter_value: str = Form(default=""),
    payload_template: str = Form(...),
    enabled: str | None = Form(default=None),
):
    _ = request

    interval_clean = _validate_webhook_interval(interval_seconds)
    payload_clean = _validate_webhook_payload_template(payload_template)
    method_clean, body_size_clean, field_clean, operator_clean, value_clean = _normalize_webhook_filter(
        filter_method,
        body_size_gt_zero,
        filter_field,
        filter_operator,
        filter_value,
    )

    _webhook_store.create_webhook(
        name=name.strip() or "Webhook",
        target_url=target_url.strip(),
        enabled=enabled == "on",
        interval_seconds=interval_clean,
        filter_method=method_clean,
        body_size_gt_zero=body_size_clean,
        filter_field=field_clean,
        filter_operator=operator_clean,
        filter_value=value_clean,
        payload_template=payload_clean,
    )

    return RedirectResponse(url="/webhooks?msg=Webhook+created", status_code=303)


@app.post("/webhooks/test")
@login_required
async def webhooks_test(
    request: Request,
    name: str = Form(...),
    target_url: str = Form(...),
    filter_method: str = Form(default=""),
    body_size_gt_zero: str = Form(default="off"),
    filter_field: str = Form(default=""),
    filter_operator: str = Form(default="equals"),
    filter_value: str = Form(default=""),
    payload_template: str = Form(...),
):
    _ = request

    payload_clean = _validate_webhook_payload_template(payload_template)
    method_clean, body_size_clean, field_clean, operator_clean, value_clean = _normalize_webhook_filter(
        filter_method,
        body_size_gt_zero,
        filter_field,
        filter_operator,
        filter_value,
    )

    result = _webhook_dispatcher.send_test_notification(
        name=name.strip() or "Webhook",
        target_url=target_url.strip(),
        payload_template=payload_clean,
        filter_method=method_clean,
        body_size_gt_zero=body_size_clean,
        filter_field=field_clean,
        filter_operator=operator_clean,
        filter_value=value_clean,
    )
    status = 200 if result.get("ok") else 400
    return JSONResponse(content=result, status_code=status)


@app.post("/webhooks/preview")
@login_required
async def webhooks_preview(
    request: Request,
    name: str = Form(...),
    filter_method: str = Form(default=""),
    body_size_gt_zero: str = Form(default="off"),
    filter_field: str = Form(default=""),
    filter_operator: str = Form(default="equals"),
    filter_value: str = Form(default=""),
    payload_template: str = Form(...),
):
    _ = request

    payload_clean = _validate_webhook_payload_template(payload_template)
    method_clean, body_size_clean, field_clean, operator_clean, value_clean = _normalize_webhook_filter(
        filter_method,
        body_size_gt_zero,
        filter_field,
        filter_operator,
        filter_value,
    )

    result = _webhook_dispatcher.preview_notification(
        name=name.strip() or "Webhook",
        payload_template=payload_clean,
        filter_method=method_clean,
        body_size_gt_zero=body_size_clean,
        filter_field=field_clean,
        filter_operator=operator_clean,
        filter_value=value_clean,
    )
    status = 200 if result.get("ok") else 400
    return JSONResponse(content=result, status_code=status)


@app.get("/webhooks/{webhook_id}/edit")
@login_required
async def webhook_edit_page(request: Request, webhook_id: int):
    webhook = _webhook_store.get_webhook(webhook_id)
    if webhook is None:
        raise HTTPException(status_code=404, detail="Webhook not found")

    return templates.TemplateResponse(
        request=request,
        name="webhook_edit.html",
        context={
            "webhook": webhook,
            "filter_fields": WEBHOOK_FILTER_FIELDS,
            "filter_methods": WEBHOOK_METHODS,
            "filter_operators": WEBHOOK_OPERATORS,
            "preview_rows": _db.list_matching_scans(
                method_filter=webhook.filter_method,
                body_size_gt_zero=webhook.body_size_gt_zero,
                field_filter=webhook.filter_field,
                operator_filter=webhook.filter_operator,
                value_filter=webhook.filter_value,
                limit=12,
            ),
        },
    )


@app.post("/webhooks/{webhook_id}/edit")
@login_required
async def webhook_edit_submit(
    request: Request,
    webhook_id: int,
    name: str = Form(...),
    target_url: str = Form(...),
    interval_seconds: int = Form(...),
    filter_method: str = Form(default=""),
    body_size_gt_zero: str = Form(default="off"),
    filter_field: str = Form(default=""),
    filter_operator: str = Form(default="equals"),
    filter_value: str = Form(default=""),
    payload_template: str = Form(...),
    enabled: str | None = Form(default=None),
):
    _ = request

    interval_clean = _validate_webhook_interval(interval_seconds)
    payload_clean = _validate_webhook_payload_template(payload_template)
    method_clean, body_size_clean, field_clean, operator_clean, value_clean = _normalize_webhook_filter(
        filter_method,
        body_size_gt_zero,
        filter_field,
        filter_operator,
        filter_value,
    )

    updated = _webhook_store.update_webhook(
        webhook_id=webhook_id,
        name=name.strip() or "Webhook",
        target_url=target_url.strip(),
        enabled=enabled == "on",
        interval_seconds=interval_clean,
        filter_method=method_clean,
        body_size_gt_zero=body_size_clean,
        filter_field=field_clean,
        filter_operator=operator_clean,
        filter_value=value_clean,
        payload_template=payload_clean,
    )
    if not updated:
        raise HTTPException(status_code=404, detail="Webhook not found")

    return RedirectResponse(url="/webhooks?msg=Webhook+updated", status_code=303)


@app.post("/webhooks/{webhook_id}/delete")
@login_required
async def webhook_delete(request: Request, webhook_id: int):
    _ = request
    deleted = _webhook_store.delete_webhook(webhook_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Webhook not found")
    return RedirectResponse(url="/webhooks?msg=Webhook+deleted", status_code=303)
