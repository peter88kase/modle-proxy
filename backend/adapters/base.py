"""Adapter layer: isolate every vendor-specific detail behind one interface.

Adding a provider means adding a module in this package, registering it in
``ADAPTERS`` and adding a seed entry in ``config/providers.json``.  Nothing in
the API layer knows about request bodies, auth headers or SSE dialects.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any


class UpstreamProtocolError(ValueError):
    """Raised when the upstream body cannot be parsed by the adapter."""


@dataclass
class CallSpec:
    """One concrete test call.  Credentials are ``repr=False`` so that an
    accidental traceback or debug print cannot leak them."""

    base_url: str
    model: str
    api_key: str = field(default="", repr=False)
    api_secret: str = field(default="", repr=False)
    auth_style: str = ""
    system: str = ""
    prompt: str = ""
    max_tokens: int = 64
    temperature: float | None = 0.2
    top_p: float | None = None
    stream: bool = False
    stream_usage: bool = False
    extra_body: dict[str, Any] = field(default_factory=dict)
    #: 版本号的值。**留空 = 按 `version_in_body` 取该模式的默认值**：
    #: header 模式 `2023-06-01`，body 模式 `bedrock-2023-05-31`。
    #: 两个默认值不同，所以不能在这里写死一个——否则 body 模式会误用 header 的值。
    api_version: str = ""
    #: 版本号放在**请求体**而不是 header。
    #:
    #: AWS 官方文档（Bedrock inference-messages-api）明确两种端点是两套写法：
    #: * `bedrock-runtime` 的 `InvokeModel`：body 里 `"anthropic_version": "bedrock-2023-05-31"`
    #: * `bedrock-mantle` / Anthropic 直连：header `anthropic-version: 2023-06-01`
    #:
    #: **两者二选一，不能同时发**：直连 Anthropic 收到 body 里的 `anthropic_version`
    #: 会当成意外字段报 400；而 Bedrock 网关只认 body 那一份。
    #: 第三方网关（转 Bedrock 的）通常走 body 这一套，需要显式打开。
    version_in_body: bool = False
    send_empty_auth: bool = False


@dataclass
class PreparedRequest:
    method: str
    url: str
    headers: dict[str, str]
    json_body: dict[str, Any] | None


@dataclass
class ParsedResponse:
    text: str = ""
    reported_model: str = ""
    finish_reason: str = ""
    usage: dict[str, Any] = field(default_factory=dict)
    error_code: str = ""
    error_message: str = ""
    request_id: str = ""
    content_type: str = ""


@dataclass
class StreamEvent:
    kind: str  # text | usage | meta | done | error | ping
    text: str = ""
    usage: dict[str, Any] | None = None
    model: str = ""
    error: str = ""
    finish_reason: str = ""


class SSEDecoder:
    """Incremental text/event-stream decoder (handles CRLF, comments, multi-line data)."""

    def __init__(self) -> None:
        self._buffer = ""
        self._event = ""
        self._data: list[str] = []

    def feed(self, chunk: bytes) -> list[tuple[str, str]]:
        self._buffer += chunk.decode("utf-8", "replace")
        events: list[tuple[str, str]] = []
        while "\n" in self._buffer:
            line, self._buffer = self._buffer.split("\n", 1)
            line = line.rstrip("\r")
            if line == "":
                if self._data:
                    events.append((self._event or "message", "\n".join(self._data)))
                self._event, self._data = "", []
            elif line.startswith(":"):
                continue
            elif line.startswith("event:"):
                self._event = line[6:].strip()
            elif line.startswith("data:"):
                self._data.append(line[5:].lstrip())
        return events

    def flush(self) -> list[tuple[str, str]]:
        events: list[tuple[str, str]] = []
        if self._buffer:
            tail, self._buffer = self._buffer, ""
            if tail.startswith("data:"):
                self._data.append(tail[5:].lstrip())
        if self._data:
            events.append((self._event or "message", "\n".join(self._data)))
            self._event, self._data = "", []
        return events


def join_url(base: str, path: str) -> str:
    base = base.rstrip("/")
    if not path:
        return base
    return base + "/" + path.lstrip("/")


def model_path(base: str, model: str) -> str:
    """Avoid duplicating /v1 when the operator already typed it into the base."""
    base = base.rstrip("/")
    if base.endswith("/v1") and model.startswith("/v1/"):
        model = model[3:]
    return join_url(base, model)


class BaseAdapter:
    id: str = "base"
    label: str = "基础适配器"
    protocols: tuple[str, ...] = ()
    auth_styles: tuple[str, ...] = ("bearer",)
    supports_stream: bool = True
    supports_models_list: bool = False
    parameter_notes: str = ""

    def build(self, spec: CallSpec) -> PreparedRequest:  # pragma: no cover - interface
        raise NotImplementedError

    def parse(self, body: bytes, headers: dict[str, str]) -> ParsedResponse:
        raise NotImplementedError

    def stream_parser(self) -> "BaseStreamParser":
        raise NotImplementedError

    def models_request(self, base_url: str, api_key: str, auth_style: str) -> PreparedRequest | None:
        return None

    def parse_models(self, body: bytes) -> list[str]:
        return []


class BaseStreamParser:
    adapter: BaseAdapter

    def __init__(self, adapter: BaseAdapter) -> None:
        self.adapter = adapter
        self.sse = SSEDecoder()
        self.done = False
        self.text_parts: list[str] = []
        self.usage: dict[str, Any] = {}
        self.reported_model = ""
        self.finish_reason = ""
        # F5：畸形事件过去被 `except ValueError: continue` 静默丢弃，
        # 于是"全程可解析"这半句根本无从判定。这里计数并向上暴露。
        self.malformed_events = 0
        self.parsed_events = 0

    def feed(self, chunk: bytes) -> list[StreamEvent]:
        events: list[StreamEvent] = []
        for event_name, data in self.sse.feed(chunk):
            events.extend(self._consume(event_name, data))
        return events

    def _consume(self, event_name: str, data: str) -> list[StreamEvent]:
        raw = data.strip()
        if raw == "[DONE]":
            self.done = True
            # 不合成 finish_reason：要判"结束原因"就得拿到上游真的报了什么。
            return [StreamEvent(kind="done")]
        if not raw:
            return []
        try:
            payload = json.loads(raw)
        except ValueError:
            self.malformed_events += 1
            return []
        if not isinstance(payload, dict):
            self.malformed_events += 1
            return []
        self.parsed_events += 1
        return self._handle(event_name, payload)

    def finish(self) -> list[StreamEvent]:
        """流结束时的收尾。

        这里**不再合成** ``finish_reason``。过去是
        ``finish_reason=self.finish_reason or "eof"``，被 ``upstream.py`` 写回
        outcome 之后，第一章 STREAM-04 的 ``bool(o.finish_reason)`` 恒为真、
        STREAM-05 的 ``stream_incomplete`` 成了死分支——截断流一律判 PASS。
        现在只把缓冲区里残留的半个事件交出去（解析失败会进 malformed_events）。
        """
        events: list[StreamEvent] = []
        for event_name, data in self.sse.flush():
            events.extend(self._consume(event_name, data))
        return events

    @property
    def terminated(self) -> bool:
        """是否收到协议层的正常结束信号（``[DONE]``/``message_stop`` 或显式结束原因）。"""
        return self.done or bool(self.finish_reason)

    @property
    def finish_source(self) -> str:
        """结束信号的来源，报告与断言都要看它，而不是只看"有没有值"。

        * ``upstream_field``：上游在响应字段里报了 finish_reason/stop_reason；
        * ``upstream_event``：上游发了显式终止事件（``[DONE]``/``message_stop``）；
        * ``synthesized``：流结束了但**没有任何结束信号**（被截断）。
          这一类过去被伪装成 ``finish_reason="eof"``，正是 STREAM-04 恒真的根源。
        """
        if self.finish_reason:
            return "upstream_field"
        if self.done:
            return "upstream_event"
        return "synthesized"

    def _text(self, text: str) -> StreamEvent | None:
        if not text:
            return None
        self.text_parts.append(text)
        return StreamEvent(kind="text", text=text)

    def _handle(self, event_name: str, payload: dict[str, Any]) -> list[StreamEvent]:
        raise NotImplementedError

    @property
    def full_text(self) -> str:
        return "".join(self.text_parts)


def _content_to_text(content: Any) -> str:
    """OpenAI-compatible content may be a string or a list of parts."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        chunks: list[str] = []
        for part in content:
            if isinstance(part, str):
                chunks.append(part)
            elif isinstance(part, dict):
                if isinstance(part.get("text"), str):
                    chunks.append(part["text"])
                elif part.get("type") == "text" and isinstance(part.get("content"), str):
                    chunks.append(part["content"])
        return "".join(chunks)
    return ""


def extract_error(payload: Any) -> tuple[str, str]:
    """Normalise the many error shapes vendors use."""
    if not isinstance(payload, dict):
        return "", ""
    error = payload.get("error")
    if isinstance(error, dict):
        code = str(error.get("code") or error.get("type") or error.get("status") or "")
        message = str(error.get("message") or error.get("msg") or "")
        return code, message
    if isinstance(error, str):
        return "", error
    for key in ("message", "msg", "error_msg", "detail"):
        if isinstance(payload.get(key), str):
            return str(payload.get("code") or payload.get("type") or ""), payload[key]
    return "", ""


# imported at the bottom to avoid circular imports
from . import anthropic, gemini, openai_compat  # noqa: E402

ADAPTERS: dict[str, BaseAdapter] = {
    openai_compat.OpenAIAdapter.id: openai_compat.OpenAIAdapter(),
    anthropic.AnthropicAdapter.id: anthropic.AnthropicAdapter(),
    gemini.GeminiAdapter.id: gemini.GeminiAdapter(),
}


def get_adapter(adapter_id: str) -> BaseAdapter:
    adapter = ADAPTERS.get(adapter_id)
    if adapter is None:
        raise KeyError(f"未知的适配器: {adapter_id}")
    return adapter
