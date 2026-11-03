"""System configuration endpoints (admin only, non-sensitive settings)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from .config import settings
from .db import all_runtime_settings, audit, connect, now_iso, set_runtime_setting
from .deps import client_ip_of, require_admin, require_csrf
from .security import SessionContext
from .shell_client import describe_transport, health

router = APIRouter(prefix="/api/settings", tags=["settings"])

APP_VERSION = "1.0.0"


class RuntimeSettingsPayload(BaseModel):
    test_repeat: int = Field(ge=1, le=5)
    default_prompt: str = Field(min_length=1, max_length=500)


@router.get("")
async def get_settings(request: Request, session: SessionContext = Depends(require_admin)) -> dict:
    shell = await health(force=True)
    # 以前这里在 socket 缺失时显示 shell_host:shell_port，暗示"走了 TCP"；
    # 但 Linux 上客户端已经禁止回退 TCP，那样显示等于撒谎（见 shell_client._connect）。
    effective_transport = describe_transport()
    with connect() as conn:
        users = conn.execute("SELECT COUNT(*) c FROM users").fetchone()["c"]
        providers = conn.execute("SELECT COUNT(*) c FROM providers").fetchone()["c"]
        runs = conn.execute("SELECT COUNT(*) c FROM suite_runs").fetchone()["c"]
        sessions = conn.execute("SELECT COUNT(*) c FROM sessions WHERE expires_at > strftime('%s','now')").fetchone()["c"]
        last_audit = conn.execute("SELECT ts, username, action, ip FROM audit_log ORDER BY id DESC LIMIT 10").fetchall()

    return {
        "version": APP_VERSION,
        "runtime": all_runtime_settings(),
        "environment": {
            "env": settings.env,
            "bind": f"{settings.bind_host}:{settings.bind_port}",
            "db_path": str(settings.db_path),
            "cookie_secure": settings.cookie_secure,
            "session_idle_seconds": settings.session_idle_seconds,
            "session_absolute_seconds": settings.session_absolute_seconds,
            "login_max_failures": settings.login_max_failures,
            "login_lock_seconds": settings.login_lock_seconds,
            "model_connect_timeout": settings.model_connect_timeout,
            "model_first_token_timeout": settings.model_first_token_timeout,
            "model_total_timeout": settings.model_total_timeout,
            "model_max_concurrency": settings.model_max_concurrency,
            "model_max_body_bytes": settings.model_max_body_bytes,
            "allow_private_upstream": settings.allow_private_upstream,
            "upstream_extra_hosts": list(settings.upstream_extra_hosts),
            "shell_enabled": settings.shell_enabled,
            "shell_socket": effective_transport,
            "shell_rate_per_minute": settings.shell_rate_per_minute,
        },
        "shell": {"available": bool(shell.get("available")), "detail": shell},
        "counts": {"users": users, "providers": providers, "suite_runs": runs, "active_sessions": sessions},
        "recent_audit": [dict(row) for row in last_audit],
        "server_time": now_iso(),
    }


@router.post("")
def update_settings(
    payload: RuntimeSettingsPayload, request: Request, session: SessionContext = Depends(require_admin)
) -> dict:
    require_csrf(request, session)
    if payload.default_prompt.strip() == "":
        raise HTTPException(status_code=400, detail={"code": "invalid_prompt", "message": "默认提示词不能为空"})
    set_runtime_setting("test_repeat", str(payload.test_repeat))
    set_runtime_setting("default_prompt", payload.default_prompt.strip())
    audit(session.user_id, session.username, "settings_updated", client_ip_of(request), "runtime settings")
    return {"ok": True, "runtime": all_runtime_settings()}
