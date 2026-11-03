"""Login / logout / session endpoints."""

from __future__ import annotations

import time

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field

from .config import settings
from .db import audit, connect, now_iso
from .deps import current_session, optional_session, require_csrf
from .security import (
    RateLimiter,
    clear_login_failures,
    client_ip,
    create_session,
    destroy_session,
    destroy_user_sessions,
    hash_password,
    login_blocked,
    record_login,
    verify_password,
)

router = APIRouter(prefix="/api/auth", tags=["auth"])

# burst protection on top of the persistent failure counters
_login_burst = RateLimiter(limit=settings.login_rate_per_minute, window_seconds=60)
_DUMMY_HASH = hash_password("bedrock-dummy-password-for-timing")


class LoginPayload(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class PasswordPayload(BaseModel):
    # Length policy lives in the handler so that the response carries a
    # human-readable Chinese message instead of a bare validation error.
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=1, max_length=256)


def _set_cookie(response: Response, sid: str) -> None:
    response.set_cookie(
        key=settings.cookie_name,
        value=sid,
        max_age=settings.session_absolute_seconds,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="lax",
        path=settings.cookie_path,
        domain=settings.cookie_domain or None,
    )


@router.post("/login")
def login(payload: LoginPayload, request: Request, response: Response) -> dict:
    ip = client_ip(request)
    username = payload.username.strip().lower()

    allowed, retry_after = _login_burst.allow(f"login:{ip}")
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail={"code": "too_many_requests", "message": f"登录请求过于频繁，请 {retry_after} 秒后重试"},
            headers={"Retry-After": str(retry_after)},
        )

    blocked, retry = login_blocked(ip, username)
    if blocked:
        audit(None, username, "login_blocked", ip, "账户或来源被临时锁定")
        raise HTTPException(
            status_code=429,
            detail={
                "code": "login_locked",
                "message": f"失败次数过多，登录已临时锁定，请 {max(retry // 60, 1)} 分钟后再试",
            },
            headers={"Retry-After": str(retry)},
        )

    with connect() as conn:
        row = conn.execute(
            "SELECT id, username, password_hash, role, is_active FROM users WHERE username=?", (username,)
        ).fetchone()

    stored = row["password_hash"] if row else _DUMMY_HASH
    password_ok = verify_password(payload.password, stored)
    if not row or not row["is_active"] or not password_ok:
        record_login(ip, username, False)
        audit(row["id"] if row else None, username, "login_failed", ip, "凭据无效")
        raise HTTPException(status_code=401, detail={"code": "invalid_credentials", "message": "用户名或密码错误"})

    clear_login_failures(ip, username)
    record_login(ip, username, True)
    sid, ctx = create_session(row["id"], ip, request.headers.get("user-agent", ""))
    _set_cookie(response, sid)
    audit(row["id"], username, "login_success", ip, "")
    return {
        "ok": True,
        "user": {"username": ctx.username, "role": ctx.role},
        "csrf_token": ctx.csrf_token,
        "expires_in": settings.session_idle_seconds,
    }


@router.post("/logout")
def logout(request: Request, response: Response) -> dict:
    ctx = optional_session(request)
    if ctx is not None:
        require_csrf(request, ctx)
        destroy_session(ctx.id_hash)
        audit(ctx.user_id, ctx.username, "logout", client_ip(request), "")
    response.delete_cookie(
        settings.cookie_name, path=settings.cookie_path, domain=settings.cookie_domain or None
    )
    return {"ok": True}


@router.get("/session")
def session_info(request: Request) -> dict:
    ctx = current_session(request)
    return {
        "username": ctx.username,
        "role": ctx.role,
        "csrf_token": ctx.csrf_token,
        "expires_at": int(ctx.expires_at),
        "server_time": int(time.time()),
    }


@router.post("/password")
def change_password(payload: PasswordPayload, request: Request) -> dict:
    ctx = current_session(request)
    require_csrf(request, ctx)

    if len(payload.new_password) < settings.password_min_length:
        raise HTTPException(
            status_code=400,
            detail={
                "code": "weak_password",
                "message": f"新密码长度至少 {settings.password_min_length} 位",
            },
        )
    if payload.new_password == payload.current_password:
        raise HTTPException(status_code=400, detail={"code": "same_password", "message": "新密码不能与当前密码相同"})
    if payload.new_password.lower() in {"password", "12345678", "admin123456"}:
        raise HTTPException(status_code=400, detail={"code": "weak_password", "message": "该密码过于常见，请更换"})

    with connect() as conn:
        row = conn.execute("SELECT password_hash FROM users WHERE id=?", (ctx.user_id,)).fetchone()
    if row is None or not verify_password(payload.current_password, row["password_hash"]):
        audit(ctx.user_id, ctx.username, "password_change_failed", client_ip(request), "")
        raise HTTPException(status_code=401, detail={"code": "invalid_credentials", "message": "当前密码不正确"})

    with connect() as conn:
        conn.execute(
            "UPDATE users SET password_hash=?, password_changed_at=? WHERE id=?",
            (hash_password(payload.new_password), now_iso(), ctx.user_id),
        )
    destroy_user_sessions(ctx.user_id, keep=ctx.id_hash)
    audit(ctx.user_id, ctx.username, "password_changed", client_ip(request), "其他会话已失效")
    return {"ok": True}


@router.get("/sessions")
def my_sessions(request: Request) -> dict:
    ctx = current_session(request)
    with connect() as conn:
        rows = conn.execute(
            "SELECT id_hash, created_at, last_seen, expires_at, ip, user_agent FROM sessions "
            "WHERE user_id=? AND revoked=0 ORDER BY last_seen DESC",
            (ctx.user_id,),
        ).fetchall()
    return {
        "current": ctx.id_hash,
        "items": [
            {
                "id": row["id_hash"][:12],
                "current": row["id_hash"] == ctx.id_hash,
                "created_at": int(row["created_at"]),
                "last_seen": int(row["last_seen"]),
                "expires_at": int(row["expires_at"]),
                "ip": row["ip"],
                "user_agent": row["user_agent"][:120],
            }
            for row in rows
        ],
    }


@router.post("/sessions/revoke-others")
def revoke_other_sessions(request: Request) -> dict:
    ctx = current_session(request)
    require_csrf(request, ctx)
    removed = destroy_user_sessions(ctx.user_id, keep=ctx.id_hash)
    audit(ctx.user_id, ctx.username, "sessions_revoked", client_ip(request), f"撤销 {removed} 个会话")
    return {"ok": True, "revoked": removed}
