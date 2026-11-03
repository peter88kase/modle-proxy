"""Server-side proxy that executes model test calls.

Design notes
------------
* Credentials live only inside the ``CallSpec`` of the current request.  They
  are never written to a log, the database or a browser cookie, and the spec is
  wiped in ``finally`` once the call finishes (streaming included).
* Timeouts are measured the way chapter 1 of the acceptance standard requires:
  connection timeout, time-to-first-valid-content (TTFT, ignoring SSE
  comments/heartbeats and empty deltas) and total request timeout.  Waiting for
  the response headers is part of the TTFT budget, otherwise an upstream that
  accepts the connection and never answers would hang forever.
* Response bodies are capped, redirects are refused and every hop is checked by
  the SSRF guard before the socket is opened.
"""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable

import httpx

from .adapters.base import (
    BaseAdapter,
    CallSpec,
    ParsedResponse,
    UpstreamProtocolError,
)
from .config import settings
from .netguard import TargetError, validate_url
from .budget import take_request
from .security import redact_text, redact_url

StreamCallback = Callable[[str, dict[str, Any]], Awaitable[None]]


@dataclass
class CallOutcome:
    ok: bool = False
    http_status: int | None = None
    latency_ms: int = 0
    ttft_ms: int | None = None
    text: str = ""
    reported_model: str = ""
    finish_reason: str = ""
    usage: dict[str, Any] = field(default_factory=dict)
    error_code: str = ""
    error_message: str = ""
    request_id: str = ""
    content_type: str = ""
    bytes_read: int = 0
    chunk_count: int = 0
    #: 是否收到协议层的正常结束信号（[DONE]/message_stop 或显式 finish_reason）。
    #: 与 ``finish_reason`` 分开：截断的流两者都为空，STREAM-04/05 才能判红。
    stream_terminated: bool = False
    #: 结束信号来源：upstream_field / upstream_event / synthesized（见 BaseStreamParser）。
    finish_source: str = ""
    #: 非 2xx 响应的正文预览（脱敏 + 截断）。
    #: 为什么要单独一个字段：`text` 在非 2xx 上恒为空（只有 2xx 才走解析），
    #: 而"鉴权拒绝时有没有夹带模型输出"必须看错误体才判得出来。
    error_body_preview: str = ""
    #: 2xx 响应的**原始** body 前 2KB（脱敏 + 截断）。
    #:
    #: 与 `text` 的区别很关键：`text` 是适配器**提取后的回答正文**（例如 `CONNECT_OK`），
    #: 而 REQ-04 要判的是"这个响应整体是不是 API 数据"。用 `text` 去判会得出
    #: "看起来像纯文本"的错误结论——那正是它曾经误判的原因。
    raw_body_preview: str = ""
    #: 响应正文能否解析为 JSON 文档（对象/数组）。
    #:
    #: 三态：``True``/``False`` = 真的把响应体读回来判过；``None`` = 没读到正文
    #: （超时、被拦的重定向、连接失败），此时任何结论都不该由本字段给出。
    #:
    #: 为什么必须单独存一个布尔值：``raw_body_preview`` 是给**人看**的脱敏预览，
    #: 默认截断到 400 字符（曾把 758 字符的正常 JSON 截成半句），拿它去 ``json.loads``
    #: 判定，等于用"显示用的副本"代替"真身"——真实响应一超过 400 字符就必然判失败。
    body_is_json: bool | None = None
    #: 无法解析的 SSE 事件数（畸形事件过去被静默丢弃，见 F5）。
    malformed_events: int = 0
    cancelled: bool = False
    timed_out: bool = False
    truncated: bool = False
    endpoint_host: str = ""
    request_method: str = ""
    request_url: str = ""
    request_body: dict[str, Any] = field(default_factory=dict)
    request_headers: dict[str, str] = field(default_factory=dict)
    auth_headers: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def summary(self) -> dict[str, Any]:
        """Non-sensitive metadata that is safe to return to the browser or store."""
        return {
            "ok": self.ok,
            "http_status": self.http_status,
            "latency_ms": self.latency_ms,
            "ttft_ms": self.ttft_ms,
            "reported_model": self.reported_model,
            "finish_reason": self.finish_reason,
            "usage": self.usage,
            "error_code": self.error_code,
            "error_message": redact_text(self.error_message),
            "request_id": self.request_id,
            "content_type": self.content_type,
            "bytes_read": self.bytes_read,
            "chunk_count": self.chunk_count,
            "stream_terminated": self.stream_terminated,
            "finish_source": self.finish_source,
            "error_body_preview": self.error_body_preview,
            "body_is_json": self.body_is_json,
            "malformed_events": self.malformed_events,
            "cancelled": self.cancelled,
            "timed_out": self.timed_out,
            "truncated": self.truncated,
            "endpoint_host": self.endpoint_host,
            "answer_chars": len(self.text),
            "notes": self.notes,
            "request": {
                "method": self.request_method,
                "url": self.request_url,
                "headers": self.request_headers,
                "auth_headers": self.auth_headers,
                "body": self.request_body,
            },
        }


def _is_json_document(raw: bytes) -> bool:
    """整段响应体能否解析成 JSON 对象/数组。

    用**完整原始字节**判，不用任何截断/脱敏后的预览：
    预览是有损的展示副本，它的截断点会落在字符串中间，让合法 JSON 变成非法。
    ``utf-8-sig`` 兼容带 BOM 的上游；解析失败一律 False（HTML / SSE / 纯文本）。
    """
    if not raw:
        return False
    try:
        value = json.loads(raw.decode("utf-8-sig", "replace"))
    except (ValueError, UnicodeDecodeError):
        return False
    return isinstance(value, (dict, list))


def _timeout_error(exc: BaseException) -> tuple[str, str]:
    if isinstance(exc, httpx.ConnectTimeout):
        return "connect_timeout", "连接超时：在规定时间内未能与上游建立连接"
    if isinstance(exc, httpx.ReadTimeout):
        return "read_timeout", "读取超时：上游在预算内未返回数据"
    if isinstance(exc, httpx.WriteTimeout):
        return "write_timeout", "发送超时"
    if isinstance(exc, httpx.PoolTimeout):
        return "pool_timeout", "连接池等待超时"
    if isinstance(exc, httpx.ConnectError):
        return "connect_error", f"连接失败：{exc}"
    if isinstance(exc, httpx.RemoteProtocolError):
        return "protocol_error", f"上游协议异常：{exc}"
    if isinstance(exc, httpx.DecodingError):
        return "decode_error", f"响应解码失败：{exc}"
    if isinstance(exc, httpx.HTTPError):
        return "http_error", f"请求异常：{exc}"
    if isinstance(exc, asyncio.TimeoutError):
        return "total_timeout", "请求总超时：上游未在预算内完成响应"
    return "unknown_error", redact_text(str(exc))


def _headers_dict(response: httpx.Response) -> dict[str, str]:
    return {k.lower(): v for k, v in response.headers.items()}


def _parse_error_body(adapter: BaseAdapter, body: bytes, headers: dict[str, str]) -> ParsedResponse | None:
    if not body:
        return None
    try:
        return adapter.parse(body, headers)
    except (UpstreamProtocolError, ValueError):
        return None


async def _read_limited(response: httpx.Response, max_bytes: int, timeout: float) -> tuple[bytes, bool]:
    """Read a body with a hard deadline and a byte cap."""

    async def _collect() -> tuple[bytearray, bool]:
        buffer = bytearray()
        async for chunk in response.aiter_bytes():
            buffer.extend(chunk)
            if len(buffer) > max_bytes:
                return buffer, True
        return buffer, False

    buffer, truncated = await asyncio.wait_for(_collect(), timeout=max(0.1, timeout))
    return bytes(buffer), truncated


async def execute(
    adapter: BaseAdapter,
    spec: CallSpec,
    *,
    total_timeout: float | None = None,
    connect_timeout: float | None = None,
    first_token_timeout: float | None = None,
    stream_idle_timeout: float | None = None,
    max_bytes: int | None = None,
    on_event: StreamCallback | None = None,
) -> CallOutcome:
    total_timeout = total_timeout or settings.model_total_timeout
    connect_timeout = connect_timeout or settings.model_connect_timeout
    first_token_timeout = first_token_timeout or settings.model_first_token_timeout
    stream_idle_timeout = stream_idle_timeout or first_token_timeout
    max_bytes = max_bytes or settings.model_max_body_bytes

    outcome = CallOutcome()
    allowed, reason = take_request()
    if not allowed:
        # 预算或时长用尽：不发出请求，也不伪造任何响应
        outcome.error_code = "budget_exhausted"
        outcome.error_message = reason
        outcome.notes.append(reason)
        return outcome
    prepared = adapter.build(spec)
    # Non-sensitive request metadata for the "request detail" panel.  Header
    # values for auth are replaced by a marker, never echoed.
    outcome.request_method = prepared.method
    outcome.request_url = redact_url(prepared.url)
    outcome.request_body = prepared.json_body or {}
    for name, value in prepared.headers.items():
        lower = name.lower()
        if lower in {"authorization", "x-api-key", "x-goog-api-key", "api-key", "x-token"}:
            outcome.auth_headers.append(name)
        elif lower in {"content-type", "accept", "anthropic-version"}:
            outcome.request_headers[name] = value
    try:
        # DNS resolution is blocking; keep it off the event loop.
        target = await asyncio.to_thread(validate_url, prepared.url, resolve=True)
        outcome.endpoint_host = target.host
    except TargetError as exc:
        outcome.error_code = f"target_blocked:{exc.code}"
        outcome.error_message = exc.message
        return outcome

    headers = dict(prepared.headers)
    headers.setdefault("User-Agent", settings.user_agent)
    headers["Accept-Encoding"] = "identity"

    timeout = httpx.Timeout(connect=connect_timeout, read=None, write=connect_timeout, pool=connect_timeout)
    started = time.perf_counter()
    deadline = started + total_timeout

    client = httpx.AsyncClient(
        follow_redirects=False,
        timeout=timeout,
        trust_env=False,
        limits=httpx.Limits(max_connections=8, max_keepalive_connections=0),
    )
    response: httpx.Response | None = None
    try:
        async with client:
            request = client.build_request(prepared.method, prepared.url, headers=headers, json=prepared.json_body)
            header_budget = min(first_token_timeout, max(0.1, deadline - time.perf_counter()))
            try:
                response = await asyncio.wait_for(client.send(request, stream=True), timeout=header_budget)
            except asyncio.TimeoutError:
                outcome.latency_ms = int((time.perf_counter() - started) * 1000)
                outcome.timed_out = True
                outcome.error_code = "first_content_timeout"
                outcome.error_message = "首个有效内容超时：上游未在预算内返回响应头"
                return outcome
            except (httpx.HTTPError, OSError) as exc:
                outcome.latency_ms = int((time.perf_counter() - started) * 1000)
                outcome.error_code, outcome.error_message = _timeout_error(exc)
                outcome.timed_out = outcome.error_code in {"total_timeout", "read_timeout", "connect_timeout"}
                return outcome

            hdrs = _headers_dict(response)
            outcome.http_status = response.status_code

            if 300 <= response.status_code < 400:
                location = response.headers.get("location", "")
                outcome.error_code = "redirect_blocked"
                outcome.error_message = "上游返回重定向，已阻止自动跟随" + (
                    f"，目标：{redact_url(location)}" if location else ""
                )
                outcome.latency_ms = int((time.perf_counter() - started) * 1000)
                return outcome

            if response.status_code >= 400:
                try:
                    raw, _ = await _read_limited(
                        response, min(max_bytes, 64 * 1024), deadline - time.perf_counter()
                    )
                except (asyncio.TimeoutError, httpx.HTTPError):
                    outcome.latency_ms = int((time.perf_counter() - started) * 1000)
                    outcome.timed_out = True
                    outcome.error_code = "total_timeout"
                    outcome.error_message = "请求总超时：上游返回错误状态后未结束响应体"
                    return outcome
                outcome.bytes_read = len(raw)
                outcome.latency_ms = int((time.perf_counter() - started) * 1000)
                parsed = _parse_error_body(adapter, raw, hdrs)
                if parsed and (parsed.error_message or parsed.error_code):
                    code = f"http_{response.status_code}"
                    if parsed.error_code:
                        code += f":{parsed.error_code}"
                    outcome.error_code = code
                    outcome.error_message = parsed.error_message or f"HTTP {response.status_code}"
                else:
                    preview = raw.decode("utf-8", "replace")[:400]
                    if "text/html" in hdrs.get("content-type", ""):
                        outcome.error_code = "http_error_html"
                        outcome.error_message = f"HTTP {response.status_code}，返回内容为 HTML 页面（可能是网关错误页）"
                    else:
                        outcome.error_code = f"http_{response.status_code}"
                        outcome.error_message = redact_text(preview) or f"HTTP {response.status_code}"
                # 注意：**不要把错误体写进 outcome.text**。
                # rejection_ok()（AUTH-02/03/04、MODEL-02/03）依赖 `text` 在非 2xx 上
                # 恒为空来表达"没有模型输出"；谁把 body 填进 text，这四项会突然把
                # 合法的 401+JSON 错误体判成 FAIL，而改动者不会想到这层耦合。
                # 要看错误体请用 error_body_preview。
                # 错误体预览保持短（400）：`looks_like_model_output()` 里有一条
                # "超过 200 字符且不像 JSON → 当模型输出"的兜底，把预览放大到 2000
                # 会让一篇 HTML 错误页也被判成"夹带模型输出"，那是无谓的误判。
                # 是否 JSON 由下面的 body_is_json 基于**完整字节**判，与预览无关。
                outcome.error_body_preview = redact_text(raw.decode("utf-8", "replace"), limit=400)
                outcome.body_is_json = _is_json_document(raw)
                outcome.request_id = hdrs.get("x-request-id", "") or hdrs.get("request-id", "")
                outcome.content_type = hdrs.get("content-type", "")
                return outcome

            if spec.stream:
                await _consume_stream(
                    adapter,
                    response,
                    hdrs,
                    outcome,
                    started,
                    deadline,
                    first_token_timeout,
                    stream_idle_timeout,
                    max_bytes,
                    on_event,
                )
            else:
                try:
                    raw, truncated = await _read_limited(response, max_bytes, deadline - time.perf_counter())
                except (asyncio.TimeoutError, httpx.HTTPError):
                    outcome.latency_ms = int((time.perf_counter() - started) * 1000)
                    outcome.timed_out = True
                    outcome.error_code = "total_timeout"
                    outcome.error_message = "请求总超时：上游未在预算内返回完整响应体"
                    return outcome
                outcome.truncated = truncated
                outcome.bytes_read = len(raw)
                outcome.latency_ms = int((time.perf_counter() - started) * 1000)
                outcome.content_type = hdrs.get("content-type", "")
                try:
                    parsed = adapter.parse(raw, hdrs)
                except UpstreamProtocolError as exc:
                    outcome.error_code = "invalid_response"
                    outcome.error_message = str(exc)
                    return outcome
                _apply_parsed(outcome, parsed)
                # 保留原始 2xx body（脱敏 + 截断），供 REQ-04 判断"整体是不是 API 数据"。
                # 必须用 raw 而不是 parsed.text：后者是提取后的回答正文。
                outcome.raw_body_preview = redact_text(raw.decode("utf-8", "replace"), limit=2000)
                outcome.body_is_json = _is_json_document(raw)
                if not outcome.text and not outcome.error_code:
                    outcome.error_code = "empty_response"
                    outcome.error_message = "上游返回成功状态但没有可识别的正文内容"
                outcome.ok = bool(outcome.text) and not outcome.error_code and not outcome.truncated
            outcome.request_id = outcome.request_id or hdrs.get("x-request-id", "")
            return outcome
    finally:
        if response is not None:
            try:
                await response.aclose()
            except Exception:  # noqa: BLE001 - closing a broken stream must not mask the result
                pass
        # Drop credential references held by this frame as early as possible.
        spec.api_key = ""
        spec.api_secret = ""
        headers.clear()


def _apply_parsed(outcome: CallOutcome, parsed: ParsedResponse) -> None:
    outcome.text = parsed.text
    outcome.reported_model = parsed.reported_model
    outcome.finish_reason = parsed.finish_reason
    outcome.usage = parsed.usage or {}
    outcome.request_id = parsed.request_id or outcome.request_id
    outcome.content_type = parsed.content_type or outcome.content_type
    if parsed.error_code or parsed.error_message:
        outcome.error_code = parsed.error_code or "upstream_error"
        outcome.error_message = parsed.error_message
    outcome.ok = bool(parsed.text) and not parsed.error_message


async def _consume_stream(
    adapter: BaseAdapter,
    response: httpx.Response,
    headers: dict[str, str],
    outcome: CallOutcome,
    started: float,
    deadline: float,
    first_token_timeout: float,
    idle_timeout: float,
    max_bytes: int,
    on_event: StreamCallback | None,
) -> None:
    parser = adapter.stream_parser()
    iterator = response.aiter_bytes().__aiter__()
    first_content_seen = False
    bytes_total = 0

    while True:
        remaining = deadline - time.perf_counter()
        if remaining <= 0:
            outcome.timed_out = True
            outcome.error_code = "total_timeout"
            outcome.error_message = "请求总超时：上游未在预算内结束流式响应"
            break
        budget = min(remaining, first_token_timeout if not first_content_seen else idle_timeout)
        try:
            chunk = await asyncio.wait_for(iterator.__anext__(), timeout=budget)
        except StopAsyncIteration:
            break
        except asyncio.TimeoutError:
            outcome.timed_out = True
            outcome.error_code = "first_content_timeout" if not first_content_seen else "stream_idle_timeout"
            outcome.error_message = (
                "首个有效内容超时：上游仅返回响应头/心跳，未在预算内返回正文"
                if not first_content_seen
                else "流中空闲超时：上游在预算内未继续返回数据"
            )
            break
        except httpx.HTTPError as exc:
            outcome.error_code, outcome.error_message = _timeout_error(exc)
            break

        bytes_total += len(chunk)
        outcome.bytes_read = bytes_total
        if bytes_total > max_bytes:
            outcome.truncated = True
            outcome.error_code = "response_too_large"
            outcome.error_message = "响应体超过上限，已截断并终止读取"
            break

        for event in parser.feed(chunk):
            if event.kind == "text" and event.text:
                outcome.chunk_count += 1
                if not first_content_seen:
                    first_content_seen = True
                    outcome.ttft_ms = int((time.perf_counter() - started) * 1000)
                if on_event:
                    await on_event("delta", {"text": event.text})
            elif event.kind == "usage":
                outcome.usage.update(event.usage or {})
                if on_event:
                    await on_event("usage", {"usage": event.usage or {}})
            elif event.kind == "error":
                outcome.error_code = "stream_error"
                outcome.error_message = event.error
                if on_event:
                    await on_event("error", {"message": redact_text(event.error)})

    for event in parser.finish():
        if event.kind == "error":
            outcome.error_code = "stream_error"
            outcome.error_message = event.error

    outcome.latency_ms = int((time.perf_counter() - started) * 1000)
    outcome.text = parser.full_text
    outcome.reported_model = parser.reported_model
    # 只记录上游真的报了的结束原因；不再有 "eof" 兜底。
    outcome.finish_reason = parser.finish_reason
    outcome.stream_terminated = parser.terminated
    outcome.finish_source = parser.finish_source
    outcome.malformed_events = parser.malformed_events
    outcome.content_type = headers.get("content-type", "") or outcome.content_type

    if not outcome.error_code:
        if not outcome.text:
            outcome.error_code = "empty_stream"
            outcome.error_message = "流式响应结束但未收到任何正文内容（可能只收到心跳或空事件）"
        elif not outcome.stream_terminated:
            outcome.error_code = "stream_incomplete"
            outcome.error_message = "流式响应未收到正常结束标记（无 [DONE]/结束原因），疑似被中途截断"
    outcome.ok = bool(outcome.text) and not outcome.error_code and not outcome.timed_out and not outcome.truncated


async def list_models(adapter: BaseAdapter, base_url: str, api_key: str, auth_style: str) -> list[str]:
    request = adapter.models_request(base_url, api_key, auth_style)
    if request is None:
        raise TargetError("unsupported", "该适配器不支持在线获取模型列表")
    await asyncio.to_thread(validate_url, request.url, resolve=True)
    headers = dict(request.headers)
    headers.setdefault("User-Agent", settings.user_agent)

    # 不同网关的列模型路径不一致（/models、/v1/models，base 里也可能已经带了 /v1）。
    # 首个路径 404 时把常见写法都试一遍，避免“填了 /v1”被判成上游不支持。
    base = base_url.rstrip("/")
    candidates = [request.url]
    for path in ("models", "v1/models"):
        url = f"{base}/{path}"
        if url not in candidates:
            candidates.append(url)

    async with httpx.AsyncClient(
        follow_redirects=False,
        timeout=httpx.Timeout(connect=settings.model_connect_timeout, read=15, write=10, pool=5),
        trust_env=False,
    ) as client:
        last_status = 0
        for url in candidates:
            if url != request.url:
                await asyncio.to_thread(validate_url, url, resolve=True)
            try:
                response = await client.request(request.method, url, headers=headers)
            except Exception as exc:  # noqa: BLE001 - 网络异常要把尝试过的路径一起报出来
                raise TargetError(
                    "upstream_error",
                    f"获取模型列表失败：{type(exc).__name__}（已尝试 {'、'.join(candidates)}）",
                ) from exc
            last_status = response.status_code
            if response.status_code < 400:
                return adapter.parse_models(response.content)
        raise TargetError(
            "upstream_error",
            f"获取模型列表失败：HTTP {last_status}（已尝试 {'、'.join(candidates)}）",
        )
