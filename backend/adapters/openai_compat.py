"""OpenAI-compatible Chat Completions adapter.

Covers OpenAI itself plus every gateway that speaks the same protocol
(DeepSeek, Moonshot, DashScope compatible mode, vLLM, Ollama, one-api/new-api,
self-hosted proxies, ...).  Auth style is configurable because gateways often
expect a custom header.
"""

from __future__ import annotations

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
    join_url,
    _content_to_text,
)


class OpenAIAdapter(BaseAdapter):
    id = "openai"
    label = "OpenAI Chat Completions 兼容"
    protocols = ("openai-chat",)
    auth_styles = ("bearer", "api-key", "custom-header", "none")
    supports_stream = True
    supports_models_list = True
    parameter_notes = "max_tokens / temperature / top_p 由上游决定；部分推理模型会拒绝 temperature"

    def _auth_headers(self, spec: CallSpec) -> dict[str, str]:
        style = (spec.auth_style or "bearer").lower()
        send = bool(spec.api_key) or spec.send_empty_auth
        if style == "bearer":
            return {"Authorization": f"Bearer {spec.api_key}".strip()} if send else {}
        if style == "api-key":
            return {"api-key": spec.api_key} if send else {}
        if style == "custom-header":
            name = (spec.extra_body.get("auth_header_name") or "X-Api-Key").strip()
            return {name: spec.api_key} if send else {}
        return {}

    def build(self, spec: CallSpec) -> PreparedRequest:
        headers = {
            "Content-Type": "application/json",
            "Accept": "text/event-stream" if spec.stream else "application/json",
        }
        headers.update(self._auth_headers(spec))

        messages: list[dict[str, str]] = []
        if spec.system:
            messages.append({"role": "system", "content": spec.system})
        messages.append({"role": "user", "content": spec.prompt})

        body: dict[str, Any] = {
            "model": spec.model,
            "messages": messages,
            "stream": spec.stream,
            "max_tokens": spec.max_tokens,
        }
        if spec.temperature is not None:
            body["temperature"] = spec.temperature
        if spec.top_p is not None:
            body["top_p"] = spec.top_p
        if spec.stream and spec.stream_usage:
            body["stream_options"] = {"include_usage": True}
        body.update(spec.extra_body.get("body") or {})

        # 默认路径**带 `v1/`**：运营商填的 base 常常是 `https://host`（不带 /v1），
        # 而 OpenAI 兼容端点的真实路径是 `/v1/chat/completions`。少了这一层会 404，
        # 而 404 会被 NET-03 / REQ-01 判成"未到达正确 API"——结论看起来像供应商的
        # 问题，实际是平台把 URL 拼错了（判错归因，比判错结论更难发现）。
        #
        # 去重与 `anthropic.py` 一致：base 已含 `/v1` 时不要再叠一层，
        # 否则 `https://host/v1` + `v1/chat/completions` 会变成 `/v1/v1/...`。
        path = spec.extra_body["path"] if "path" in spec.extra_body else "v1/chat/completions"
        base = spec.base_url.rstrip("/")
        if base.endswith("/v1") and path.startswith("v1/"):
            path = path[3:]
        return PreparedRequest("POST", join_url(base, path), headers, body)

    def parse(self, body: bytes, headers: dict[str, str]) -> ParsedResponse:
        try:
            payload = __import__("json").loads(body.decode("utf-8", "replace") or "{}")
        except ValueError as exc:
            raise UpstreamProtocolError(f"响应不是合法 JSON: {exc}") from exc
        if not isinstance(payload, dict):
            raise UpstreamProtocolError("响应 JSON 顶层不是对象")

        code, message = extract_error(payload)
        if "choices" not in payload:
            return ParsedResponse(
                error_code=code or "no_choices",
                error_message=message or "响应中缺少 choices 字段",
                reported_model=str(payload.get("model") or ""),
                usage=payload.get("usage") if isinstance(payload.get("usage"), dict) else {},
            )

        text = ""
        finish = ""
        choices = payload.get("choices") or []
        if choices and isinstance(choices[0], dict):
            message_obj = choices[0].get("message") or {}
            text = _content_to_text(message_obj.get("content")) if isinstance(message_obj, dict) else ""
            finish = str(choices[0].get("finish_reason") or "")
            if not text and isinstance(message_obj, dict) and message_obj.get("refusal"):
                text = ""

        return ParsedResponse(
            text=text,
            reported_model=str(payload.get("model") or ""),
            finish_reason=finish,
            usage=payload.get("usage") if isinstance(payload.get("usage"), dict) else {},
            request_id=headers.get("x-request-id", "") or headers.get("request-id", ""),
            content_type=headers.get("content-type", ""),
        )

    def stream_parser(self) -> "OpenAIStreamParser":
        return OpenAIStreamParser(self)

    def models_request(self, base_url: str, api_key: str, auth_style: str) -> PreparedRequest | None:
        headers = {"Accept": "application/json"}
        style = (auth_style or "bearer").lower()
        if style == "api-key":
            headers["api-key"] = api_key
        elif style == "none":
            pass
        else:
            headers["Authorization"] = f"Bearer {api_key}"
        return PreparedRequest("GET", join_url(base_url, "models"), headers, None)

    def parse_models(self, body: bytes) -> list[str]:
        try:
            payload = __import__("json").loads(body.decode("utf-8", "replace"))
        except ValueError:
            return []
        data = payload.get("data") if isinstance(payload, dict) else None
        if not isinstance(data, list):
            return []
        return sorted({item.get("id") for item in data if isinstance(item, dict) and item.get("id")})


class OpenAIStreamParser(BaseStreamParser):
    def _handle(self, event_name: str, payload: dict[str, Any]) -> list[StreamEvent]:
        events: list[StreamEvent] = []
        if payload.get("error"):
            code, message = extract_error(payload)
            return [StreamEvent(kind="error", error=message or code or "上游返回错误事件")]
        if payload.get("model") and not self.reported_model:
            self.reported_model = str(payload["model"])
        usage = payload.get("usage")
        if isinstance(usage, dict) and usage:
            self.usage.update(usage)
            events.append(StreamEvent(kind="usage", usage=dict(usage)))
        for choice in payload.get("choices") or []:
            if not isinstance(choice, dict):
                continue
            delta = choice.get("delta") or {}
            if isinstance(delta, dict):
                piece = _content_to_text(delta.get("content"))
                event = self._text(piece)
                if event:
                    events.append(event)
            if choice.get("finish_reason"):
                self.finish_reason = str(choice["finish_reason"])
        return events
