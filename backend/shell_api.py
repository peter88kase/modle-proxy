"""Web shell endpoints.

The browser never talks to the worker directly: this router authenticates the
session, enforces per-user rate limits, normalises the parameter whitelist and
then forwards a structured request over the socket.  The worker re-validates
everything and is the only process that spawns child processes.
"""

from __future__ import annotations

import asyncio
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from .config import settings
from .db import audit
from .deps import client_ip_of, require_csrf, require_operator
from .security import RateLimiter, SessionContext, redact_text
from .shell_client import ShellUnavailable, call_worker, health

router = APIRouter(prefix="/api/shell", tags=["shell"])

_exec_limiter = RateLimiter(limit=30, window_seconds=60)
_semaphore = asyncio.Semaphore(3)

PARAM_WHITELIST: dict[str, dict[str, type]] = {
    "curl": {"url": str, "timeout": int, "connect_timeout": int, "head_only": bool},
    # 自由命令模式：整段 curl 命令由工作进程用 shlex 解析，参数仍走白名单
    "curl_raw": {"command_line": str, "timeout": int},
    "ping": {"host": str, "count": int, "timeout": int},
    "dig": {"host": str, "rtype": str},
}

# 单字段长度上限：命令文本要能容纳多行 JSON
FIELD_LIMITS = {"command_line": 8192}


class ExecPayload(BaseModel):
    command: Literal["curl", "curl_raw", "ping", "dig"]
    params: dict[str, Any] = Field(default_factory=dict)
    timeout: int | None = Field(default=None, ge=1, le=60)


def _sanitise(command: str, params: dict[str, Any]) -> dict[str, Any]:
    allowed = PARAM_WHITELIST[command]
    clean: dict[str, Any] = {}
    for key, value in params.items():
        expected = allowed.get(key)
        if expected is None:
            raise HTTPException(status_code=400, detail={"code": "invalid_param", "message": f"不支持的参数: {key}"})
        if expected is int:
            try:
                number = int(value)
            except (TypeError, ValueError):
                raise HTTPException(status_code=400, detail={"code": "invalid_param", "message": f"参数 {key} 必须是整数"})
            if not 1 <= number <= 60:
                raise HTTPException(status_code=400, detail={"code": "invalid_param", "message": f"参数 {key} 超出允许范围"})
            clean[key] = number
        elif expected is bool:
            clean[key] = bool(value)
        else:
            if not isinstance(value, str):
                raise HTTPException(status_code=400, detail={"code": "invalid_param", "message": f"参数 {key} 必须是字符串"})
            limit = FIELD_LIMITS.get(key, 2048)
            if len(value) > limit:
                raise HTTPException(
                    status_code=400, detail={"code": "invalid_param", "message": f"参数 {key} 过长（上限 {limit} 字符）"}
                )
            clean[key] = value.strip()

    if command == "curl" and not clean.get("url"):
        raise HTTPException(status_code=400, detail={"code": "invalid_param", "message": "请填写要测试的 URL"})
    if command == "curl_raw" and not clean.get("command_line"):
        raise HTTPException(status_code=400, detail={"code": "invalid_param", "message": "请粘贴 curl 命令"})
    if command in {"ping", "dig"} and not clean.get("host"):
        raise HTTPException(status_code=400, detail={"code": "invalid_param", "message": "请填写目标主机"})
    if command == "dig":
        clean["rtype"] = (clean.get("rtype") or "A").upper()
    return clean


@router.get("/health")
async def shell_health(request: Request, session: SessionContext = Depends(require_operator)) -> dict:
    data = await health(force=True)
    return {
        "available": bool(data.get("available")),
        "detail": data,
        "limits": {
            "request_timeout": settings.shell_request_timeout,
            "rate_per_minute": settings.shell_rate_per_minute,
            "app_concurrency": 3,
        },
    }


@router.post("/exec")
async def shell_exec(
    payload: ExecPayload, request: Request, session: SessionContext = Depends(require_operator)
) -> dict:
    require_csrf(request, session)

    allowed, retry = _exec_limiter.allow(f"shell:{session.user_id}")
    if not allowed:
        raise HTTPException(
            status_code=429,
            detail={"code": "rate_limited", "message": f"命令执行过于频繁，请 {retry} 秒后再试"},
            headers={"Retry-After": str(retry)},
        )

    clean = _sanitise(payload.command, payload.params)
    ip = client_ip_of(request)

    try:
        await asyncio.wait_for(_semaphore.acquire(), timeout=5)
    except asyncio.TimeoutError:
        raise HTTPException(status_code=429, detail={"code": "busy", "message": "并发诊断任务已满，请稍后重试"})

    try:
        response = await call_worker(
            {
                "action": "exec",
                "command": payload.command,
                "params": clean,
                "timeout": payload.timeout or settings.shell_request_timeout,
            },
            timeout=(payload.timeout or 30) + 10,
        )
    except ShellUnavailable as exc:
        raise HTTPException(status_code=503, detail={"code": "shell_unavailable", "message": str(exc)})
    finally:
        _semaphore.release()

    if not response.get("ok"):
        error = response.get("error") or {}
        detail = {"code": error.get("code", "command_failed"), "message": error.get("message", "命令执行失败")}
        audit(session.user_id, session.username, "shell_exec_denied", ip, f"{payload.command}:{detail['code']}")
        status = 403 if detail["code"] in {"command_not_allowed", "blocked_target", "port_not_allowed"} else 400
        raise HTTPException(status_code=status, detail=detail)

    data = response.get("data") or {}
    detail = f"{payload.command} host={data.get('target_host', '')} exit={data.get('exit_code')} {data.get('duration_ms')}ms"
    if payload.command == "curl_raw":
        # 审计里保留可追溯的命令摘要，但 header 中的 key 必须脱敏
        detail += " cmd=" + redact_text(str(clean.get("command_line", "")), 200)
    audit(session.user_id, session.username, "shell_exec", ip, detail)
    return {
        "command": payload.command,
        "status": data.get("status"),
        "exit_code": data.get("exit_code"),
        "duration_ms": data.get("duration_ms"),
        "stdout": data.get("stdout", ""),
        "stderr": data.get("stderr", ""),
        "truncated": data.get("truncated", False),
        "timed_out": data.get("timed_out", False),
        "timeout_seconds": data.get("timeout_seconds"),
        "target_host": data.get("target_host", ""),
        # -L 跟随重定向的落点：0/空表示没有跳转（不是"没查"）
        "redirect_count": data.get("redirect_count", 0),
        "redirect_final_url": data.get("redirect_final_url", ""),
        "redirect_left_host": data.get("redirect_left_host", False),
        "error_message": redact_text(data.get("stderr", ""), 200) if data.get("status") == "error" else "",
    }
