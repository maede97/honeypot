import os
from functools import wraps

import bcrypt
from fastapi import FastAPI, Form, HTTPException, Query, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from .database import Database

HONEYPOT_DB_PATH = os.getenv("HONEYPOT_DB_PATH", "/data/honeypot.db")
GUI_ADMIN_USERNAME = os.getenv("GUI_ADMIN_USERNAME", "admin")
GUI_ADMIN_PASSWORD_BCRYPT = os.getenv("GUI_ADMIN_PASSWORD_BCRYPT", "")
GUI_SESSION_SECRET = os.getenv("GUI_SESSION_SECRET", "")

app = FastAPI(
    title="honeypot-gui",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)
app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")
_db = Database(HONEYPOT_DB_PATH)

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
