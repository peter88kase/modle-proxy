"""Anthropic Messages API adapter (including Claude-compatible gateways)."""

from __future__ import annotations

import json
from typing import Any

from .base import (
    BaseAdapter,
    BaseStreamParser,
    CallSpec,
    ParsedResponse,
    PreparedRequest,
    StreamEvent,
    UpstreamProtocolError,
    extract_error,
    model_path,
    join_url,
)


class AnthropicAdapter(BaseAdapter):
    id = "anthropic"
    label = "Anthropic Messages"
    protocols = ("anthropic-messages",)
    auth_styles = ("x-api-key", "bearer")
    supports_stream = True
    supports_models_list = True
    parameter_notes = "max_tokens 必填；system 为顶层字符串字段，不属于 messages"

    def build(self, spec: CallSpec) -> PreparedRequest:
        headers = {
            "Content-Type": "application/json",
            "Accept": "text/event-stream" if spec.stream else "application/json",
        }
        # 版本号位置取决于端点类型（见 CallSpec.version_in_body）：
        # 直连 Anthropic / bedrock-mantle 用 header；bedrock-runtime 的 InvokeModel
        # 用 body。**只发一种**——同时发会被直连端点当成冲突字段。
        if not spec.version_in_body:
            headers["anthropic-version"] = spec.api_version or "2023-06-01"
        if spec.api_key or spec.send_empty_auth:
            if (spec.auth_style or "x-api-key").lower() == "bearer":
                headers["Authorization"] = f"Bearer {spec.api_key}".strip()
            else:
                headers["x-api-key"] = spec.api_key

        body: dict[str, Any] = {
            "model": spec.model,
            "max_tokens": max(spec.max_tokens, 1),
            "messages": [{"role": "user", "content": spec.prompt}],
            "stream": spec.stream,
        }
        # Bedrock invoke_model 风格：版本号是 body 的必填字段（不是 header）。
        # 默认值取 AWS 文档里那个唯一合法值 `bedrock-2023-05-31`。
        if spec.version_in_body:
            body["anthropic_version"] = spec.api_version or "bedrock-2023-05-31"
        if spec.system:
            body["system"] = spec.system
        if spec.temperature is not None:
            body["temperature"] = spec.temperature
        if spec.top_p is not None:
            body["top_p"] = spec.top_p
        body.update(spec.extra_body.get("body") or {})

        path = spec.extra_body["path"] if "path" in spec.extra_body else "v1/messages"
        base = spec.base_url.rstrip("/")
        if base.endswith("/v1") and path.startswith("v1/"):
            path = path[3:]
        return PreparedRequest("POST", join_url(base, path), headers, body)

    def parse(self, body: bytes, headers: dict[str, str]) -> ParsedResponse:
        try:
            payload = json.loads(body.decode("utf-8", "replace") or "{}")
        except ValueError as exc:
            raise UpstreamProtocolError(f"响应不是合法 JSON: {exc}") from exc
        if not isinstance(payload, dict):
            raise UpstreamProtocolError("响应 JSON 顶层不是对象")

        if payload.get("type") == "error" or payload.get("error"):
            code, message = extract_error(payload)
            return ParsedResponse(
                error_code=code or "upstream_error",
                error_message=message or "上游返回错误",
                reported_model=str((payload.get("error") or {}).get("type", "")) if isinstance(payload.get("error"), dict) else "",
            )

        if payload.get("content") is None:
            # 401/403 这类错误体常常没有 content（如 {"id":"Unauthorized","message":"..."}）。
            # 直接报“缺少 content 字段”会把鉴权拒绝说成解析失败，评审方看不出真实原因。
            code, message = extract_error(payload)
            return ParsedResponse(
                error_code=code or "no_content",
                error_message=message or str(payload.get("id") or "上游返回了无法识别的响应体"),
                reported_model=str(payload.get("model") or ""),
                request_id=headers.get("request-id", "") or headers.get("x-request-id", ""),
                content_type=headers.get("content-type", ""),
            )

        text_parts: list[str] = []
        for block in payload.get("content") or []:
            if isinstance(block, dict) and block.get("type") == "text":
                text_parts.append(str(block.get("text") or ""))
        usage = payload.get("usage") if isinstance(payload.get("usage"), dict) else {}
        return ParsedResponse(
            text="".join(text_parts),
            reported_model=str(payload.get("model") or ""),
            finish_reason=str(payload.get("stop_reason") or ""),
            usage=usage,
            error_code="" if payload.get("content") is not None else "no_content",
            error_message="" if payload.get("content") is not None else "响应中缺少 content 字段",
            request_id=headers.get("request-id", "") or headers.get("x-request-id", ""),
            content_type=headers.get("content-type", ""),
        )

    def stream_parser(self) -> "AnthropicStreamParser":
        return AnthropicStreamParser(self)

    def models_request(self, base_url: str, api_key: str, auth_style: str) -> PreparedRequest | None:
        headers = {"Accept": "application/json", "anthropic-version": "2023-06-01"}
        if (auth_style or "x-api-key").lower() == "bearer":
            headers["Authorization"] = f"Bearer {api_key}"
        else:
            headers["x-api-key"] = api_key
        # base 里已经写了 /v1 时不要拼成 /v1/v1/models（页面提示就让人填 /v1）
        return PreparedRequest("GET", model_path(base_url, "v1/models"), headers, None)

    def parse_models(self, body: bytes) -> list[str]:
        try:
            payload = json.loads(body.decode("utf-8", "replace"))
        except ValueError:
            return []
        data = payload.get("data") if isinstance(payload, dict) else None
        if not isinstance(data, list):
            return []
        return sorted({item.get("id") for item in data if isinstance(item, dict) and item.get("id")})


class AnthropicStreamParser(BaseStreamParser):
    def _handle(self, event_name: str, payload: dict[str, Any]) -> list[StreamEvent]:
        kind = payload.get("type") or event_name
        events: list[StreamEvent] = []

        if kind == "message_start":
            message = payload.get("message") or {}
            if isinstance(message, dict):
                self.reported_model = str(message.get("model") or "")
                usage = message.get("usage")
                if isinstance(usage, dict) and usage:
                    self.usage.update(usage)
                    events.append(StreamEvent(kind="usage", usage=dict(usage)))
            return events

        if kind == "content_block_delta":
            delta = payload.get("delta") or {}
            if isinstance(delta, dict) and delta.get("type") in ("text_delta", "text"):
                event = self._text(str(delta.get("text") or ""))
                if event:
                    events.append(event)
            return events

        if kind == "message_delta":
            delta = payload.get("delta") or {}
            if isinstance(delta, dict) and delta.get("stop_reason"):
                self.finish_reason = str(delta["stop_reason"])
            usage = payload.get("usage")
            if isinstance(usage, dict) and usage:
                # message_delta usage carries output_tokens; merge instead of adding.
                for key, value in usage.items():
                    if isinstance(value, (int, float)):
                        self.usage[key] = value
                events.append(StreamEvent(kind="usage", usage=dict(usage)))
            return events

        if kind == "message_stop":
            self.done = True
            # 不合成 "stop"：结束原因只能是上游报的 stop_reason。
            events.append(StreamEvent(kind="done"))
            return events

        if kind == "error":
            error = payload.get("error") or {}
            message = error.get("message") if isinstance(error, dict) else str(error)
            events.append(StreamEvent(kind="error", error=str(message or "上游流式错误")))
            self.done = True
            return events

        return events
