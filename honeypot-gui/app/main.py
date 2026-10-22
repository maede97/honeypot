import asyncio
import secrets
import os
import re
import ipaddress
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from functools import wraps

import bcrypt
import httpx
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
METHOD_COLOR_SETTING_KEY = "dashboard_method_colors"
HEATMAP_COLOR_SETTING_KEY = "dashboard_heatmap_colors"
HEATMAP_THRESHOLD_SETTING_KEY = "dashboard_heatmap_thresholds"
DEFAULT_METHOD_COLORS = {
    "GET": "#2563eb",
    "POST": "#059669",
    "PUT": "#0ea5e9",
    "PATCH": "#14b8a6",
    "DELETE": "#b23a48",
    "HEAD": "#7c3aed",
    "OPTIONS": "#ea580c",
}
DEFAULT_HEATMAP_COLORS = {
    "ZERO": "#1e334c",
    "LOW": "#3394ff",
    "MEDIUM": "#2fcf88",
    "HIGH": "#14b86b",
    "VERY_HIGH": "#f59f0b",
}
DEFAULT_HEATMAP_THRESHOLDS = {
    "LOW_MAX": 10,
    "MEDIUM_MAX": 50,
    "HIGH_MAX": 200,
}
GEOLOOKUP_CACHE_LIMIT = 5000

_db = Database(HONEYPOT_DB_PATH)
_webhook_store = WebhookStore(GUI_DB_PATH)
_webhook_dispatcher = WebhookDispatcher(honeypot_db_path=HONEYPOT_DB_PATH, store=_webhook_store)
_geo_cache: dict[str, dict] = {}


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


def _ensure_csrf_token(request: Request) -> str:
    token = request.session.get("csrf_token")
    if isinstance(token, str) and token:
        return token
    token = secrets.token_urlsafe(32)
    request.session["csrf_token"] = token
    return token


def _require_csrf(request: Request, submitted_token: str) -> None:
    expected = request.session.get("csrf_token")
    if not isinstance(expected, str) or not expected:
        raise HTTPException(status_code=403, detail="Missing CSRF session token")
    if not submitted_token or not secrets.compare_digest(expected, submitted_token):
        raise HTTPException(status_code=403, detail="Invalid CSRF token")


def _template_response(request: Request, name: str, context: dict, status_code: int = 200):
    merged = {"csrf_token": _ensure_csrf_token(request), **context}
    return templates.TemplateResponse(
        request=request,
        name=name,
        context=merged,
        status_code=status_code,
    )


def _normalize_scan_timestamp(raw_value: str) -> tuple[str, str]:
    text = raw_value.strip()
    if not text:
        return "", ""

    parsed: datetime | None = None
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        parsed = None

    if parsed is None and len(text) == 16:
        try:
            parsed = datetime.strptime(text, "%Y-%m-%dT%H:%M")
        except ValueError:
            parsed = None

    if parsed is None:
        return text, ""

    normalized = parsed.replace(microsecond=0).isoformat(timespec="seconds")
    local_input = parsed.strftime("%Y-%m-%dT%H:%M")
    return normalized, local_input


def _preset_from_hours(hours_back: int) -> tuple[str, str]:
    now = datetime.utcnow().replace(microsecond=0)
    start = now - timedelta(hours=hours_back)
    return start.isoformat(timespec="seconds"), now.isoformat(timespec="seconds")


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
    burst_packets: str,
    burst_window_seconds: str,
    filter_field: str,
    filter_operator: str,
    filter_value: str,
) -> tuple[str, bool, int, int, str, str, str]:
    normalized_method = filter_method.strip().upper()
    normalized_body_size = body_size_gt_zero.strip().lower() == "on"

    burst_packets_text = burst_packets.strip()
    burst_window_text = burst_window_seconds.strip()
    try:
        normalized_burst_packets = int(burst_packets_text) if burst_packets_text else 0
        normalized_burst_window = int(burst_window_text) if burst_window_text else 0
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Burst filters must be integer values") from exc

    if normalized_burst_packets < 0 or normalized_burst_window < 0:
        raise HTTPException(status_code=400, detail="Burst filters must be non-negative")

    burst_enabled = normalized_burst_packets > 0 or normalized_burst_window > 0
    if burst_enabled and (normalized_burst_packets < 1 or normalized_burst_window < 1):
        raise HTTPException(status_code=400, detail="Burst filter requires packets >= 1 and window >= 1")

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
        return (
            normalized_method,
            normalized_body_size,
            normalized_burst_packets,
            normalized_burst_window,
            "",
            normalized_operator,
            "",
        )

    return (
        normalized_method,
        normalized_body_size,
        normalized_burst_packets,
        normalized_burst_window,
        normalized_field,
        normalized_operator,
        normalized_value,
    )


def _validate_webhook_interval(interval_seconds: int) -> int:
    if interval_seconds < 1:
        raise HTTPException(status_code=400, detail="interval_seconds must be >= 1")
    return interval_seconds


def _validate_webhook_payload_template(payload_template: str) -> str:
    candidate = payload_template.strip()
    if not candidate:
        raise HTTPException(status_code=400, detail="payload_template is required")
    return candidate


def _normalize_hex_color(candidate: str, default: str) -> str:
    normalized = candidate.strip()
    if re.fullmatch(r"#[0-9a-fA-F]{6}", normalized):
        return normalized.lower()
    return default


def _load_method_colors() -> dict[str, str]:
    saved_colors = _webhook_store.get_json_setting(METHOD_COLOR_SETTING_KEY)
    return {
        method: _normalize_hex_color(saved_colors.get(method, ""), default)
        for method, default in DEFAULT_METHOD_COLORS.items()
    }


def _load_heatmap_colors() -> dict[str, str]:
    saved_colors = _webhook_store.get_json_setting(HEATMAP_COLOR_SETTING_KEY)
    return {
        bucket: _normalize_hex_color(saved_colors.get(bucket, ""), default)
        for bucket, default in DEFAULT_HEATMAP_COLORS.items()
    }


def _normalize_heatmap_thresholds(
    submitted: dict[str, str],
    *,
    defaults: dict[str, int],
) -> dict[str, int]:
    def _parse_int(name: str, minimum: int) -> int:
        candidate = submitted.get(name, "").strip()
        if not candidate:
            return defaults[name]
        try:
            parsed = int(candidate)
        except ValueError:
            return defaults[name]
        if parsed < minimum:
            return defaults[name]
        return parsed

    low_max = _parse_int("LOW_MAX", 1)
    medium_max = _parse_int("MEDIUM_MAX", low_max + 1)
    high_max = _parse_int("HIGH_MAX", medium_max + 1)

    if medium_max <= low_max:
        medium_max = max(defaults["MEDIUM_MAX"], low_max + 1)
    if high_max <= medium_max:
        high_max = max(defaults["HIGH_MAX"], medium_max + 1)

    return {
        "LOW_MAX": low_max,
        "MEDIUM_MAX": medium_max,
        "HIGH_MAX": high_max,
    }


def _load_heatmap_thresholds() -> dict[str, int]:
    saved_thresholds = _webhook_store.get_json_setting(HEATMAP_THRESHOLD_SETTING_KEY)
    return _normalize_heatmap_thresholds(saved_thresholds, defaults=DEFAULT_HEATMAP_THRESHOLDS)


def _is_public_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def _unknown_geo() -> dict:
    return {
        "country": "",
        "region": "",
        "city": "",
        "continent": "",
        "latitude": None,
        "longitude": None,
    }


async def _fetch_geo_info(client: httpx.AsyncClient, ip: str) -> dict:
    if ip in _geo_cache:
        return _geo_cache[ip]

    if not _is_public_ip(ip):
        geo = _unknown_geo()
        _geo_cache[ip] = geo
        return geo

    geo = _unknown_geo()
    try:
        response = await client.get(f"https://ipwho.is/{ip}")
        response.raise_for_status()
        payload = response.json()
        if payload.get("success", True):
            geo = {
                "country": str(payload.get("country", "") or ""),
                "region": str(payload.get("region", "") or ""),
                "city": str(payload.get("city", "") or ""),
                "continent": str(payload.get("continent", "") or ""),
                "latitude": payload.get("latitude"),
                "longitude": payload.get("longitude"),
            }
    except Exception:
        pass

    if len(_geo_cache) >= GEOLOOKUP_CACHE_LIMIT:
        _geo_cache.pop(next(iter(_geo_cache)))
    _geo_cache[ip] = geo
    return geo


async def _enrich_ips(ips: list[str]) -> dict[str, dict]:
    unique_ips = sorted({ip for ip in ips if ip})
    if not unique_ips:
        return {}

    async with httpx.AsyncClient(timeout=4.0) as client:
        geos = await asyncio.gather(*[_fetch_geo_info(client, ip) for ip in unique_ips])
    return {ip: geo for ip, geo in zip(unique_ips, geos, strict=False)}


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/login")
def login_page(request: Request):
    if _is_authenticated(request):
        return RedirectResponse(url="/", status_code=303)
    return _template_response(request, "login.html", {"error": None})


@app.post("/login")
def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    csrf_token: str = Form(...),
):
    _require_csrf(request, csrf_token)
    if username != GUI_ADMIN_USERNAME or not _verify_password(password):
        return _template_response(request, "login.html", {"error": "Invalid credentials"}, status_code=401)

    request.session["authenticated"] = True
    request.session["username"] = username
    return RedirectResponse(url="/", status_code=303)


@app.post("/logout")
def logout(request: Request, csrf_token: str = Form(...)):
    _require_csrf(request, csrf_token)
    request.session.clear()
    return RedirectResponse(url="/login", status_code=303)


@app.get("/")
@login_required
async def dashboard(request: Request):
    return _template_response(
        request,
        "dashboard.html",
        {
            "method_colors": _load_method_colors(),
            "heatmap_colors": _load_heatmap_colors(),
            "heatmap_thresholds": _load_heatmap_thresholds(),
        },
    )


@app.get("/settings")
@login_required
async def settings_page(request: Request, msg: str = Query(default="")):
    webhooks = _webhook_store.list_webhooks()
    return _template_response(
        request,
        "webhooks.html",
        {
            "webhooks": webhooks,
            "message": msg,
            "method_colors": _load_method_colors(),
            "heatmap_colors": _load_heatmap_colors(),
            "heatmap_thresholds": _load_heatmap_thresholds(),
            "filter_fields": WEBHOOK_FILTER_FIELDS,
            "filter_methods": WEBHOOK_METHODS,
            "filter_operators": WEBHOOK_OPERATORS,
        },
    )


@app.get("/scans")
@login_required
async def scans(
    request: Request,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=10, le=200),
    path: str = Query(default=""),
    ip: str = Query(default=""),
    method: str = Query(default=""),
    header_text: str = Query(default=""),
    body_text: str = Query(default=""),
    from_ts: str = Query(default=""),
    to_ts: str = Query(default=""),
    sort_by: str = Query(default="ts"),
    sort_dir: str = Query(default="desc"),
    range_filter: str = Query(default="", alias="range"),
):
    method = method.upper().strip()
    if method and method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "PROPFIND", "CONNECT"}:
        raise HTTPException(status_code=400, detail="Unsupported HTTP method filter")

    sort_by = sort_by.strip().lower()
    allowed_sort_by = {"ts", "method", "path", "ip", "ua", "body"}
    if sort_by not in allowed_sort_by:
        sort_by = "ts"

    sort_dir = sort_dir.strip().lower()
    if sort_dir not in {"asc", "desc"}:
        sort_dir = "desc"

    from_ts_value, from_ts_local = _normalize_scan_timestamp(from_ts)
    to_ts_value, to_ts_local = _normalize_scan_timestamp(to_ts)
    quick_range = range_filter.strip().lower()
    if quick_range in {"1h", "24h", "7d"}:
        hours = {"1h": 1, "24h": 24, "7d": 168}[quick_range]
        from_ts_value, to_ts_value = _preset_from_hours(hours)
        from_ts_local = datetime.fromisoformat(from_ts_value).strftime("%Y-%m-%dT%H:%M")
        to_ts_local = datetime.fromisoformat(to_ts_value).strftime("%Y-%m-%dT%H:%M")
    else:
        quick_range = ""

    rows, total = _db.list_scans(
        page=page,
        page_size=page_size,
        path_filter=path.strip(),
        ip_filter=ip.strip(),
        method_filter=method,
        header_filter=header_text.strip(),
        body_filter=body_text.strip(),
        from_ts=from_ts_value,
        to_ts=to_ts_value,
        sort_by=sort_by,
        sort_dir=sort_dir,
    )

    pages = max((total + page_size - 1) // page_size, 1)
    return _template_response(
        request,
        "scans.html",
        {
            "rows": rows,
            "total": total,
            "page": page,
            "page_size": page_size,
            "pages": pages,
            "filters": {
                "path": path,
                "ip": ip,
                "method": method,
                "header_text": header_text,
                "body_text": body_text,
                "from_ts": from_ts_value,
                "to_ts": to_ts_value,
                "from_ts_local": from_ts_local,
                "to_ts_local": to_ts_local,
            },
            "active_range": quick_range,
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

    return _template_response(request, "scan_detail.html", {"scan": scan})


@app.get("/ips")
@login_required
async def ips_page(
    request: Request,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=10, le=200),
    ip: str = Query(default=""),
):
    rows, total = _db.list_ip_overview(
        page=page,
        page_size=page_size,
        ip_filter=ip.strip(),
    )
    pages = max((total + page_size - 1) // page_size, 1)

    table_ips = [row.client_ip for row in rows]
    map_source = _db.top_ip_hitters(limit=200)
    map_ips = [row["client_ip"] for row in map_source]
    geo_by_ip = await _enrich_ips([*table_ips, *map_ips])

    enriched_rows = [
        {
            "client_ip": row.client_ip,
            "hits": row.hits,
            "first_seen": row.first_seen,
            "last_seen": row.last_seen,
            "geo": geo_by_ip.get(row.client_ip, _unknown_geo()),
        }
        for row in rows
    ]

    map_points = []
    for row in map_source:
        geo = geo_by_ip.get(row["client_ip"], _unknown_geo())
        lat = geo.get("latitude")
        lon = geo.get("longitude")
        if isinstance(lat, (int, float)) and isinstance(lon, (int, float)):
            map_points.append(
                {
                    "client_ip": row["client_ip"],
                    "hits": row["hits"],
                    "country": geo.get("country", ""),
                    "city": geo.get("city", ""),
                    "lat": lat,
                    "lon": lon,
                }
            )

    return _template_response(
        request,
        "ips.html",
        {
            "rows": enriched_rows,
            "total": total,
            "page": page,
            "page_size": page_size,
            "pages": pages,
            "ip_filter": ip,
            "top_hitters": map_source[:10],
            "map_points": map_points,
            "map_source_count": len(map_source),
        },
    )


@app.get("/api/stats")
@login_required
async def stats_api(request: Request):
    _ = request
    return JSONResponse(content=_db.dashboard_stats())


@app.get("/api/webhooks/{webhook_id}/matches")
@login_required
async def webhook_matches_api(request: Request, webhook_id: int):
    _ = request
    webhook = _webhook_store.get_webhook(webhook_id)
    if webhook is None:
        raise HTTPException(status_code=404, detail="Webhook not found")

    rows = _db.list_matching_scans(
        method_filter=webhook.filter_method,
        body_size_gt_zero=webhook.body_size_gt_zero,
        burst_packets=webhook.burst_packets,
        burst_window_seconds=webhook.burst_window_seconds,
        field_filter=webhook.filter_field,
        operator_filter=webhook.filter_operator,
        value_filter=webhook.filter_value,
        limit=12,
    )
    return JSONResponse(content={"ok": True, "rows": rows})


@app.get("/webhooks")
@login_required
async def webhooks_page(request: Request):
    _ = request
    return RedirectResponse(url="/settings", status_code=303)


@app.post("/settings/method-colors")
@login_required
async def settings_method_colors(
    request: Request,
    csrf_token: str = Form(...),
    get_color: str = Form(default=""),
    post_color: str = Form(default=""),
    put_color: str = Form(default=""),
    patch_color: str = Form(default=""),
    delete_color: str = Form(default=""),
    head_color: str = Form(default=""),
    options_color: str = Form(default=""),
):
    _require_csrf(request, csrf_token)
    submitted = {
        "GET": get_color,
        "POST": post_color,
        "PUT": put_color,
        "PATCH": patch_color,
        "DELETE": delete_color,
        "HEAD": head_color,
        "OPTIONS": options_color,
    }
    colors = {
        method: _normalize_hex_color(submitted.get(method, ""), default)
        for method, default in DEFAULT_METHOD_COLORS.items()
    }
    _webhook_store.set_json_setting(METHOD_COLOR_SETTING_KEY, colors)
    return RedirectResponse(url="/settings?msg=Settings+updated", status_code=303)


@app.post("/settings/heatmap-colors")
@login_required
async def settings_heatmap_colors(
    request: Request,
    csrf_token: str = Form(...),
    zero_color: str = Form(default=""),
    low_color: str = Form(default=""),
    medium_color: str = Form(default=""),
    high_color: str = Form(default=""),
    very_high_color: str = Form(default=""),
    low_max: str = Form(default=""),
    medium_max: str = Form(default=""),
    high_max: str = Form(default=""),
):
    _require_csrf(request, csrf_token)
    submitted = {
        "ZERO": zero_color,
        "LOW": low_color,
        "MEDIUM": medium_color,
        "HIGH": high_color,
        "VERY_HIGH": very_high_color,
    }
    colors = {
        bucket: _normalize_hex_color(submitted.get(bucket, ""), default)
        for bucket, default in DEFAULT_HEATMAP_COLORS.items()
    }
    thresholds = _normalize_heatmap_thresholds(
        {
            "LOW_MAX": low_max,
            "MEDIUM_MAX": medium_max,
            "HIGH_MAX": high_max,
        },
        defaults=_load_heatmap_thresholds(),
    )
    _webhook_store.set_json_setting(HEATMAP_COLOR_SETTING_KEY, colors)
    _webhook_store.set_json_setting(
        HEATMAP_THRESHOLD_SETTING_KEY,
        {name: str(value) for name, value in thresholds.items()},
    )
    return RedirectResponse(url="/settings?msg=Settings+updated", status_code=303)


@app.post("/webhooks")
@login_required
async def webhooks_create(
    request: Request,
    csrf_token: str = Form(...),
    name: str = Form(...),
    target_url: str = Form(...),
    interval_seconds: int = Form(...),
    filter_method: str = Form(default=""),
    body_size_gt_zero: str = Form(default="off"),
    burst_packets: str = Form(default="0"),
    burst_window_seconds: str = Form(default="0"),
    filter_field: str = Form(default=""),
    filter_operator: str = Form(default="equals"),
    filter_value: str = Form(default=""),
    payload_template: str = Form(...),
    enabled: str | None = Form(default=None),
):
    _require_csrf(request, csrf_token)

    interval_clean = _validate_webhook_interval(interval_seconds)
    payload_clean = _validate_webhook_payload_template(payload_template)
    method_clean, body_size_clean, burst_packets_clean, burst_window_clean, field_clean, operator_clean, value_clean = _normalize_webhook_filter(
        filter_method,
        body_size_gt_zero,
        burst_packets,
        burst_window_seconds,
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
        burst_packets=burst_packets_clean,
        burst_window_seconds=burst_window_clean,
        filter_field=field_clean,
        filter_operator=operator_clean,
        filter_value=value_clean,
        payload_template=payload_clean,
    )

    return RedirectResponse(url="/settings?msg=Webhook+created", status_code=303)


@app.post("/webhooks/test")
@login_required
async def webhooks_test(
    request: Request,
    csrf_token: str = Form(...),
    name: str = Form(...),
    target_url: str = Form(...),
    filter_method: str = Form(default=""),
    body_size_gt_zero: str = Form(default="off"),
    burst_packets: str = Form(default="0"),
    burst_window_seconds: str = Form(default="0"),
    filter_field: str = Form(default=""),
    filter_operator: str = Form(default="equals"),
    filter_value: str = Form(default=""),
    payload_template: str = Form(...),
):
    _require_csrf(request, csrf_token)

    payload_clean = _validate_webhook_payload_template(payload_template)
    method_clean, body_size_clean, burst_packets_clean, burst_window_clean, field_clean, operator_clean, value_clean = _normalize_webhook_filter(
        filter_method,
        body_size_gt_zero,
        burst_packets,
        burst_window_seconds,
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
        burst_packets=burst_packets_clean,
        burst_window_seconds=burst_window_clean,
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
    csrf_token: str = Form(...),
    name: str = Form(...),
    filter_method: str = Form(default=""),
    body_size_gt_zero: str = Form(default="off"),
    burst_packets: str = Form(default="0"),
    burst_window_seconds: str = Form(default="0"),
    filter_field: str = Form(default=""),
    filter_operator: str = Form(default="equals"),
    filter_value: str = Form(default=""),
    payload_template: str = Form(...),
):
    _require_csrf(request, csrf_token)

    payload_clean = _validate_webhook_payload_template(payload_template)
    method_clean, body_size_clean, burst_packets_clean, burst_window_clean, field_clean, operator_clean, value_clean = _normalize_webhook_filter(
        filter_method,
        body_size_gt_zero,
        burst_packets,
        burst_window_seconds,
        filter_field,
        filter_operator,
        filter_value,
    )

    result = _webhook_dispatcher.preview_notification(
        name=name.strip() or "Webhook",
        payload_template=payload_clean,
        filter_method=method_clean,
        body_size_gt_zero=body_size_clean,
        burst_packets=burst_packets_clean,
        burst_window_seconds=burst_window_clean,
        filter_field=field_clean,
        filter_operator=operator_clean,
        filter_value=value_clean,
    )
    status = 200 if result.get("ok") else 400
    return JSONResponse(content=result, status_code=status)


@app.post("/webhooks/validate-template")
@login_required
async def webhooks_validate_template(
    request: Request,
    csrf_token: str = Form(...),
    name: str = Form(...),
    payload_template: str = Form(...),
):
    _require_csrf(request, csrf_token)
    payload_clean = _validate_webhook_payload_template(payload_template)
    result = _webhook_dispatcher.validate_payload_template(
        name=name.strip() or "Webhook",
        payload_template=payload_clean,
    )
    status = 200 if result.get("ok") else 400
    return JSONResponse(content=result, status_code=status)


@app.get("/webhooks/{webhook_id}/edit")
@login_required
async def webhook_edit_page(request: Request, webhook_id: int):
    webhook = _webhook_store.get_webhook(webhook_id)
    if webhook is None:
        raise HTTPException(status_code=404, detail="Webhook not found")

    return _template_response(
        request,
        "webhook_edit.html",
        {
            "webhook": webhook,
            "filter_fields": WEBHOOK_FILTER_FIELDS,
            "filter_methods": WEBHOOK_METHODS,
            "filter_operators": WEBHOOK_OPERATORS,
            "preview_rows": _db.list_matching_scans(
                method_filter=webhook.filter_method,
                body_size_gt_zero=webhook.body_size_gt_zero,
                burst_packets=webhook.burst_packets,
                burst_window_seconds=webhook.burst_window_seconds,
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
    csrf_token: str = Form(...),
    name: str = Form(...),
    target_url: str = Form(...),
    interval_seconds: int = Form(...),
    filter_method: str = Form(default=""),
    body_size_gt_zero: str = Form(default="off"),
    burst_packets: str = Form(default="0"),
    burst_window_seconds: str = Form(default="0"),
    filter_field: str = Form(default=""),
    filter_operator: str = Form(default="equals"),
    filter_value: str = Form(default=""),
    payload_template: str = Form(...),
    enabled: str | None = Form(default=None),
):
    _require_csrf(request, csrf_token)

    interval_clean = _validate_webhook_interval(interval_seconds)
    payload_clean = _validate_webhook_payload_template(payload_template)
    method_clean, body_size_clean, burst_packets_clean, burst_window_clean, field_clean, operator_clean, value_clean = _normalize_webhook_filter(
        filter_method,
        body_size_gt_zero,
        burst_packets,
        burst_window_seconds,
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
        burst_packets=burst_packets_clean,
        burst_window_seconds=burst_window_clean,
        filter_field=field_clean,
        filter_operator=operator_clean,
        filter_value=value_clean,
        payload_template=payload_clean,
    )
    if not updated:
        raise HTTPException(status_code=404, detail="Webhook not found")

    return RedirectResponse(url="/settings?msg=Webhook+updated", status_code=303)


@app.post("/webhooks/{webhook_id}/delete")
@login_required
async def webhook_delete(request: Request, webhook_id: int, csrf_token: str = Form(...)):
    _require_csrf(request, csrf_token)
    deleted = _webhook_store.delete_webhook(webhook_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Webhook not found")
    return RedirectResponse(url="/settings?msg=Webhook+deleted", status_code=303)
