"""Server-rendered pages.  All data loading happens through the JSON API."""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from .config import BASE_DIR
from .deps import optional_session

router = APIRouter(tags=["pages"])
templates = Jinja2Templates(directory=str(BASE_DIR / "frontend" / "templates"))
APP_VERSION = "1.0.0"


def _page(request: Request, name: str, active: str, user) -> HTMLResponse:
    return templates.TemplateResponse(
        request,
        name,
        {"active": active, "user": user, "version": APP_VERSION},
    )


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request, notice: str = ""):
    if optional_session(request) is not None:
        return RedirectResponse("/", status_code=302)
    notices = {
        "expired": ("登录状态已过期，请重新登录。", "warn"),
        "logout": ("已退出登录。", "ok"),
        "required": ("请先登录后再访问该功能。", "warn"),
    }
    text, kind = notices.get(notice, ("", "error"))
    return templates.TemplateResponse(
        request, "login.html", {"notice": text, "notice_kind": kind}
    )


@router.get("/", response_class=HTMLResponse)
def console_page(request: Request):
    ctx = optional_session(request)
    if ctx is None:
        return RedirectResponse("/login?notice=required", status_code=302)
    return _page(request, "console.html", "console", ctx)


@router.get("/shell", response_class=HTMLResponse)
def shell_page(request: Request):
    ctx = optional_session(request)
    if ctx is None:
        return RedirectResponse("/login?notice=required", status_code=302)
    return _page(request, "shell.html", "shell", ctx)


@router.get("/records", response_class=HTMLResponse)
def records_page(request: Request):
    ctx = optional_session(request)
    if ctx is None:
        return RedirectResponse("/login?notice=required", status_code=302)
    return _page(request, "records.html", "records", ctx)


@router.get("/tasks", response_class=HTMLResponse)
def tasks_page(request: Request):
    ctx = optional_session(request)
    if ctx is None:
        return RedirectResponse("/login?notice=required", status_code=302)
    return _page(request, "tasks.html", "tasks", ctx)


@router.get("/standards", response_class=HTMLResponse)
def standards_page(request: Request):
    ctx = optional_session(request)
    if ctx is None:
        return RedirectResponse("/login?notice=required", status_code=302)
    return _page(request, "standards.html", "standards", ctx)


@router.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request):
    ctx = optional_session(request)
    if ctx is None:
        return RedirectResponse("/login?notice=required", status_code=302)
    if ctx.role != "admin":
        return templates.TemplateResponse(
            request, "error.html", {"code": 403, "message": "该页面仅管理员可访问", "version": APP_VERSION}
        )
    return _page(request, "settings.html", "settings", ctx)


@router.get("/manual", response_class=HTMLResponse)
def manual_page(request: Request):
    ctx = optional_session(request)
    if ctx is None:
        return RedirectResponse("/login?notice=required", status_code=302)
    return _page(request, "manual.html", "manual", ctx)
