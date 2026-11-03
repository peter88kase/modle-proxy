"""Google Gemini generateContent / streamGenerateContent adapter.

The API key is sent through the ``x-goog-api-key`` header on purpose: the query
string form (?key=...) would put a credential into URLs, proxies and logs.
"""

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
    join_url,
)


class GeminiAdapter(BaseAdapter):
    id = "gemini"
    label = "Google Gemini generateContent"
    protocols = ("gemini-generate-content",)
    auth_styles = ("goog-api-key",)
    supports_stream = True
    supports_models_list = False
    parameter_notes = "generationConfig: temperature / topP / maxOutputTokens；流式使用 ?alt=sse"

    def build(self, spec: CallSpec) -> PreparedRequest:
        action = "streamGenerateContent?alt=sse" if spec.stream else "generateContent"
        model = spec.model.strip()
        if model.startswith("models/"):
            model = model[len("models/"):]
        base = spec.base_url.rstrip("/")
        if base.endswith("/v1beta") or base.endswith("/v1"):
            url = f"{base}/models/{model}:{action}"
        else:
            url = f"{base}/v1beta/models/{model}:{action}"

        headers = {"Content-Type": "application/json", "Accept": "text/event-stream" if spec.stream else "application/json"}
        if spec.api_key or spec.send_empty_auth:
            headers["x-goog-api-key"] = spec.api_key

        payload: dict[str, Any] = {
            "contents": [{"role": "user", "parts": [{"text": spec.prompt}]}],
            "generationConfig": {"maxOutputTokens": max(spec.max_tokens, 1)},
        }
        if spec.system:
            payload["systemInstruction"] = {"parts": [{"text": spec.system}]}
        if spec.temperature is not None:
            payload["generationConfig"]["temperature"] = spec.temperature
        if spec.top_p is not None:
            payload["generationConfig"]["topP"] = spec.top_p
        payload.update(spec.extra_body.get("body") or {})

        return PreparedRequest("POST", url, headers, payload)

    def parse(self, body: bytes, headers: dict[str, str]) -> ParsedResponse:
        try:
            payload = json.loads(body.decode("utf-8", "replace") or "{}")
        except ValueError as exc:
            raise UpstreamProtocolError(f"响应不是合法 JSON: {exc}") from exc
        if not isinstance(payload, dict):
            raise UpstreamProtocolError("响应 JSON 顶层不是对象")

        if payload.get("error"):
            code, message = extract_error(payload)
            return ParsedResponse(error_code=code or "upstream_error", error_message=message or "上游返回错误")

        candidates = payload.get("candidates") or []
        text_parts: list[str] = []
        finish = ""
        if candidates and isinstance(candidates[0], dict):
            finish = str(candidates[0].get("finishReason") or "")
            content = candidates[0].get("content") or {}
            for part in content.get("parts") or []:
                if isinstance(part, dict) and isinstance(part.get("text"), str):
                    text_parts.append(part["text"])

        usage_raw = payload.get("usageMetadata") or {}
        usage = {
            "prompt_tokens": usage_raw.get("promptTokenCount"),
            "completion_tokens": usage_raw.get("candidatesTokenCount"),
            "total_tokens": usage_raw.get("totalTokenCount"),
            "cached_tokens": usage_raw.get("cachedContentTokenCount"),
        }
        usage = {k: v for k, v in usage.items() if v is not None}

        blocked = payload.get("promptFeedback", {}).get("blockReason") if isinstance(payload.get("promptFeedback"), dict) else None
        return ParsedResponse(
            text="".join(text_parts),
            reported_model=str(payload.get("modelVersion") or ""),
            finish_reason=finish,
            usage=usage,
            error_code="blocked" if blocked else "",
            error_message=f"请求被安全策略拦截: {blocked}" if blocked else "",
            request_id=headers.get("x-request-id", ""),
            content_type=headers.get("content-type", ""),
        )

    def stream_parser(self) -> "GeminiStreamParser":
        return GeminiStreamParser(self)

    def models_request(self, base_url: str, api_key: str, auth_style: str) -> PreparedRequest | None:
        base = base_url.rstrip("/")
        url = f"{base}/models" if base.endswith("/v1beta") else f"{base}/v1beta/models"
        return PreparedRequest("GET", url, {"x-goog-api-key": api_key, "Accept": "application/json"}, None)

    def parse_models(self, body: bytes) -> list[str]:
        try:
            payload = json.loads(body.decode("utf-8", "replace"))
        except ValueError:
            return []
        models = payload.get("models") if isinstance(payload, dict) else None
        if not isinstance(models, list):
            return []
        out = []
        for item in models:
            name = item.get("name") if isinstance(item, dict) else None
            if name:
                out.append(str(name).replace("models/", ""))
        return sorted(set(out))


class GeminiStreamParser(BaseStreamParser):
    def _handle(self, event_name: str, payload: dict[str, Any]) -> list[StreamEvent]:
        events: list[StreamEvent] = []
        if payload.get("error"):
            code, message = extract_error(payload)
            self.done = True
            return [StreamEvent(kind="error", error=message or code or "上游流式错误")]

        if payload.get("modelVersion") and not self.reported_model:
            self.reported_model = str(payload["modelVersion"])

        for candidate in payload.get("candidates") or []:
            if not isinstance(candidate, dict):
                continue
            content = candidate.get("content") or {}
            for part in content.get("parts") or []:
                if isinstance(part, dict) and isinstance(part.get("text"), str):
                    event = self._text(part["text"])
                    if event:
                        events.append(event)
            if candidate.get("finishReason"):
                self.finish_reason = str(candidate["finishReason"]).lower()

        usage_raw = payload.get("usageMetadata")
        if isinstance(usage_raw, dict) and usage_raw:
            usage = {
                "prompt_tokens": usage_raw.get("promptTokenCount"),
                "completion_tokens": usage_raw.get("candidatesTokenCount"),
                "total_tokens": usage_raw.get("totalTokenCount"),
            }
            usage = {k: v for k, v in usage.items() if v is not None}
            self.usage.update(usage)
            events.append(StreamEvent(kind="usage", usage=usage))
        return events
