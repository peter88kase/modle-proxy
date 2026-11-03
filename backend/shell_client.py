"""Client for the isolated shell worker process."""

from __future__ import annotations

import asyncio
import json
import os
import sys
import time
from typing import Any

from .config import settings


class ShellUnavailable(RuntimeError):
    pass


_health_cache: dict[str, Any] = {"ts": 0.0, "data": None}

#: 成功结果缓存 10 秒，避免每次页面刷新都打一次 RPC。
HEALTH_OK_TTL = 10.0
#: 失败结果不缓存：worker 起来之后，下一次刷新就应该显示"在线"，
#: 而不是继续显示最多 10 秒的陈旧"离线"（那会让人以为它"自己好了"）。
HEALTH_FAIL_TTL = 0.0


def _unix_socket_configured() -> bool:
    """是否应该走 unix socket 传输。

    Windows 开发机没有 unix socket，只能用 TCP 回环；Linux 上一旦配置了
    ``SHELL_SOCKET`` 就必须走 socket，不允许回退。
    """
    return sys.platform != "win32" and bool(settings.shell_socket)


def describe_transport() -> str:
    """给设置页用的传输方式描述（不撒谎：socket 缺失时直接说出来）。"""
    if _unix_socket_configured():
        path = settings.shell_socket
        state = "socket 就绪" if os.path.exists(path) else "socket 不存在，工作进程可能未启动"
        return f"unix:{path}（{state}）"
    return f"tcp:{settings.shell_host}:{settings.shell_port}"


async def _connect() -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    if _unix_socket_configured():
        path = settings.shell_socket
        if not os.path.exists(path):
            # 关键：不再回退 TCP。生产环境的 worker 根本不监听 TCP，回退只会把
            # "worker 没起来"伪装成"连接被拒绝"，把排查引向错误方向。
            raise ShellUnavailable(
                f"Shell 工作进程可能未启动：unix socket {path} 不存在"
                f"（已禁用 TCP 回退 {settings.shell_host}:{settings.shell_port}）。"
                "请检查 bedrock-shell.service 是否处于 failed。"
            )
        return await asyncio.open_unix_connection(path)
    return await asyncio.open_connection(settings.shell_host, settings.shell_port)


async def call_worker(payload: dict[str, Any], timeout: float | None = None) -> dict[str, Any]:
    if not settings.shell_enabled:
        raise ShellUnavailable("Shell 功能已在服务端配置中关闭")
    if not settings.shell_token:
        raise ShellUnavailable("Shell 工作进程令牌未配置")
    timeout = timeout or settings.shell_request_timeout
    envelope = dict(payload)
    envelope["token"] = settings.shell_token

    try:
        reader, writer = await asyncio.wait_for(_connect(), timeout=5)
    except (ConnectionRefusedError, FileNotFoundError, asyncio.TimeoutError, OSError) as exc:
        raise ShellUnavailable(f"无法连接 Shell 工作进程：{exc}") from exc

    try:
        writer.write(json.dumps(envelope, ensure_ascii=False).encode("utf-8") + b"\n")
        await writer.drain()
        line = await asyncio.wait_for(reader.readline(), timeout=timeout)
    except asyncio.TimeoutError as exc:
        raise ShellUnavailable("Shell 工作进程响应超时") from exc
    except (ConnectionResetError, BrokenPipeError) as exc:
        raise ShellUnavailable("Shell 工作进程连接中断") from exc
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

    if not line:
        raise ShellUnavailable("Shell 工作进程未返回数据")
    try:
        response = json.loads(line.decode("utf-8"))
    except ValueError as exc:
        raise ShellUnavailable("Shell 工作进程返回了无法解析的响应") from exc
    if not isinstance(response, dict):
        raise ShellUnavailable("Shell 工作进程返回格式错误")
    return response


async def health(force: bool = False) -> dict[str, Any]:
    now = time.time()
    cached = _health_cache["data"]
    if not force and isinstance(cached, dict):
        ttl = HEALTH_OK_TTL if cached.get("available") else HEALTH_FAIL_TTL
        if ttl > 0 and now - _health_cache["ts"] < ttl:
            return cached
    try:
        response = await call_worker({"action": "health"}, timeout=5)
    except ShellUnavailable as exc:
        # 失败不入缓存：见 HEALTH_FAIL_TTL 的说明。
        return {"available": False, "error": str(exc)}
    data = response.get("data") if response.get("ok") else None
    if not isinstance(data, dict):
        return {
            "available": False,
            "error": (response.get("error") or {}).get("message", "健康检查失败"),
        }
    data["available"] = True
    _health_cache.update(ts=now, data=data)
    return data
