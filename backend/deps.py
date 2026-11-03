"""FastAPI dependencies for authentication, CSRF and roles."""

from __future__ import annotations

import hmac

from fastapi import HTTPException, Request, status

from .security import SessionContext, client_ip, load_session


def _unauthorised(code: str, message: str) -> HTTPException:
    return HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail={"code": code, "message": message})


def current_session(request: Request) -> SessionContext:
    sid = request.cookies.get(request.app.state.settings.cookie_name, "")
    ctx = load_session(sid)
    if ctx is None:
        # Distinguish "never logged in" from "expired" only for UX wording; both 401.
        raise _unauthorised("unauthenticated", "请先登录后再访问该功能")
    request.state.session = ctx
    return ctx


def optional_session(request: Request) -> SessionContext | None:
    sid = request.cookies.get(request.app.state.settings.cookie_name, "")
    ctx = load_session(sid)
    if ctx is not None:
        request.state.session = ctx
    return ctx


def require_operator(request: Request) -> SessionContext:
    ctx = current_session(request)
    if ctx.role not in {"admin", "operator"}:
        raise HTTPException(status_code=403, detail={"code": "forbidden", "message": "当前账号无此操作权限"})
    return ctx


def require_admin(request: Request) -> SessionContext:
    ctx = current_session(request)
    if ctx.role != "admin":
        raise HTTPException(status_code=403, detail={"code": "forbidden", "message": "仅管理员可执行该操作"})
    return ctx


def require_csrf(request: Request, session: SessionContext) -> None:
    """Verify the per-session CSRF token sent in the X-CSRF-Token header.

    Same-origin is also asserted when the browser sends Origin, which blocks
    cross-site form posts even if a token were somehow reused.
    """
    token = request.headers.get("x-csrf-token", "")
    if not token or not hmac.compare_digest(token, session.csrf_token):
        raise HTTPException(status_code=403, detail={"code": "csrf_failed", "message": "CSRF 校验失败，请刷新页面后重试"})
    origin = request.headers.get("origin")
    if origin and request.app.state.settings.public_origin:
        if origin.rstrip("/") != request.app.state.settings.public_origin.rstrip("/"):
            raise HTTPException(status_code=403, detail={"code": "origin_mismatch", "message": "请求来源不受信任"})


def client_ip_of(request: Request) -> str:
    return client_ip(request)
